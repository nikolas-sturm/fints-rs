//! Bank workflow trait and DKB implementation.
//!
//! Each bank defines its own complete workflow via the `BankOps` trait.
//! The workflows compose typed Dialog transitions from `protocol.rs`.
//!
//! Compile-time safety: workflow methods take typed dialog states.
//! `fetch()` takes `Dialog<Open>` — you can't call it without authentication.

use tracing::{info, warn};

use crate::banks::BankConfig;
use crate::error::{FinTSError, Result};
use crate::protocol::*;
use crate::session::SessionState;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Workflow result types
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of initiating a connection.
pub struct InitiateResult {
    pub dialog: Dialog<TanPending>,
    pub challenge: TanChallenge,
    pub tan_methods: Vec<TanMethod>,
    pub allowed_security_functions: Vec<SecurityFunction>,
    pub no_tan_required: bool,
    pub params: BankParams,
    pub system_id: SystemId,
}

/// Result when no TAN is required (SCA exemption).
pub struct InitiateNoTanResult {
    pub dialog: Dialog<Open>,
    pub params: BankParams,
    pub system_id: SystemId,
    pub tan_methods: Vec<TanMethod>,
    pub allowed_security_functions: Vec<SecurityFunction>,
}

/// Either we need TAN or we're already authenticated.
pub enum InitiateOutcome {
    NeedTan(InitiateResult),
    Authenticated(InitiateNoTanResult),
}

/// Result of fetching data from an open dialog.
pub struct FetchResult {
    pub balance: Option<AccountBalance>,
    pub transactions: Vec<Transaction>,
    pub holdings: Vec<SecurityHolding>,
}

/// Options controlling what data to fetch in a single authenticated dialog.
#[derive(Debug, Clone, Default)]
pub struct FetchOpts {
    /// Fetch balance (HKSAL). Default: true.
    pub balance: bool,
    /// Fetch transactions (HKKAZ). Default: true.
    pub transactions: bool,
    /// Fetch securities holdings (HKWPD). Default: true.
    pub holdings: bool,
    /// Days of transaction history to fetch. Default: 90.
    pub days: u32,
}

impl FetchOpts {
    /// Fetch everything: balance, transactions, and holdings.
    pub fn all(days: u32) -> Self {
        Self { balance: true, transactions: true, holdings: true, days }
    }
    /// Fetch only balance (single request, fast).
    pub fn balance_only() -> Self {
        Self { balance: true, transactions: false, holdings: false, days: 0 }
    }
    /// Skip holdings (for accounts without a depot).
    pub fn no_holdings(days: u32) -> Self {
        Self { balance: true, transactions: true, holdings: false, days }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BankOps trait
// ═══════════════════════════════════════════════════════════════════════════════

/// Each bank implements its own workflow as typed Dialog transitions.
///
/// `fetch()` takes `&mut Dialog<Open>` and `&Account` — compile-time proof that:
/// 1. Authentication has been completed (Dialog<Open>)
/// 2. Account has valid IBAN + BIC (Account)
pub trait BankOps: Send + Sync {
    fn config(&self) -> &BankConfig;

    /// Create a fresh dialog for this bank's endpoint.
    /// Banks that need non-default dialog setup (e.g. ING's security
    /// function 900) override this or chain builder calls at the call site.
    fn new_dialog(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
    ) -> Result<Dialog<New>> {
        let c = self.config();
        Dialog::new(c.url.as_str(), &c.blz, username, pin, product_id)
    }

    /// Phase 1: [sync +] init, return TAN challenge or authenticated dialog.
    ///
    /// With a `session` that holds a system ID and BPD, the synchronization
    /// dialog is skipped and HKVVB announces the cached BPD/UPD versions.
    fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> impl std::future::Future<Output = Result<InitiateOutcome>> + Send;

    /// Phase 2: fetch balance + transactions from an open dialog.
    /// Takes `&Account` — IBAN and BIC are guaranteed present.
    fn fetch(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        days: u32,
    ) -> impl std::future::Future<Output = Result<FetchResult>> + Send;

    /// Fetch securities holdings from an open dialog.
    /// Takes `&Account` — IBAN and BIC are guaranteed present.
    /// Returns an empty Vec if the bank does not support depot queries.
    fn fetch_holdings(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
    ) -> impl std::future::Future<Output = Result<Vec<SecurityHolding>>> + Send;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared dialog setup
// ═══════════════════════════════════════════════════════════════════════════════

/// The standard PIN/TAN dialog setup every bank uses unless it needs
/// something special:
///
/// ```text
///   [Sync dialog — skipped when the session has a system ID and BPD]
///     HKIDN + HKVVB + HKSYN  → BPD, UPD, system ID;  HKEND
///   Business dialog
///     HKIDN + HKVVB(cached BPD/UPD versions) + HKTAN:4(ref=HKIDN)
///       → 0030/3955: TAN required (decoupled: confirm in app)
///       → 3076:      SCA exemption, dialog open
/// ```
///
/// If the bank rejects a cached system ID (9391), the session is discarded
/// and the setup runs once more with a full synchronization.
pub async fn initiate_default<B: BankOps + ?Sized>(
    bank: &B,
    username: &UserId,
    pin: &Pin,
    product_id: &ProductId,
    session: Option<&SessionState>,
) -> Result<InitiateOutcome> {
    let config = bank.config();
    let session = session.filter(|s| {
        let matches = s.blz == config.blz && &s.user_id == username;
        if !matches {
            warn!("[FinTS] Ignoring session state for {}/{} (dialog is {}/{})", s.blz, s.user_id, config.blz, username);
        }
        matches
    });

    match initiate_once(bank, username, pin, product_id, session).await {
        Err(FinTSError::SystemIdInvalid(msg)) if session.is_some_and(|s| s.system_id.is_assigned()) => {
            warn!("[FinTS] Bank rejected cached system ID ({}); re-synchronizing", msg);
            initiate_once(bank, username, pin, product_id, None).await
        }
        other => other,
    }
}

async fn initiate_once<B: BankOps + ?Sized>(
    bank: &B,
    username: &UserId,
    pin: &Pin,
    product_id: &ProductId,
    session: Option<&SessionState>,
) -> Result<InitiateOutcome> {
    let (mut params, sys_id) = match session {
        Some(s) if s.can_skip_sync() => {
            info!("[FinTS] Using cached BPD v{} / UPD v{} and system ID — skipping sync dialog",
                s.bpd_version, s.upd_version);
            (s.to_params(), s.system_id.clone())
        }
        _ => {
            let mut sync_dialog = bank.new_dialog(username, pin, product_id)?;
            if let Some(sid) = session.map(|s| &s.system_id).filter(|s| s.is_assigned()) {
                sync_dialog = sync_dialog.with_system_id(sid);
            }
            let (synced, _) = sync_dialog.sync().await?;
            let (params, sys_id) = synced.end().await?;
            let sys_id = if sys_id.is_assigned() {
                sys_id
            } else {
                session.map(|s| s.system_id.clone()).unwrap_or_else(SystemId::unassigned)
            };
            (params, sys_id)
        }
    };
    // TAN preferences from the session apply whether or not we synced.
    if let Some(s) = session {
        if s.tan_method.is_some() {
            params.preferred_security_function = s.tan_method.clone();
        }
        if s.tan_medium.is_some() {
            params.selected_tan_medium = s.tan_medium.clone();
        }
        params.select_security_function();
    }
    let tan_methods = params.tan_methods.clone();
    let allowed = params.allowed_security_functions.clone();

    let dialog = bank.new_dialog(username, pin, product_id)?
        .with_system_id(&sys_id)
        .with_params(&params);

    match dialog.init().await? {
        InitResult::TanRequired(tan_pending, challenge, _resp) => {
            let challenge = TanChallenge {
                decoupled: challenge.decoupled || tan_pending.bank_params().is_decoupled(),
                ..challenge
            };
            info!("[{}] TAN required: decoupled={}, task_ref='{}'",
                bank.config().name, challenge.decoupled, challenge.task_reference);
            Ok(InitiateOutcome::NeedTan(InitiateResult {
                params: tan_pending.bank_params().clone(),
                system_id: tan_pending.system_id().clone(),
                dialog: tan_pending,
                challenge,
                tan_methods,
                allowed_security_functions: allowed,
                no_tan_required: false,
            }))
        }
        InitResult::Opened(open, _resp) => {
            info!("[{}] Dialog opened without TAN (SCA exemption)", bank.config().name);
            Ok(InitiateOutcome::Authenticated(InitiateNoTanResult {
                params: open.bank_params().clone(),
                system_id: open.system_id().clone(),
                dialog: open,
                tan_methods,
                allowed_security_functions: allowed,
            }))
        }
    }
}

/// Fetch balance, transactions (all touchdown pages) and holdings from an
/// open dialog. Balance and holdings are best-effort; transaction errors fail.
pub async fn fetch_default(
    tag: &str,
    dialog: &mut Dialog<Open>,
    account: &Account,
    days: u32,
) -> Result<FetchResult> {
    info!("[{}] Fetching IBAN={}, BIC={}", tag, account.iban(), account.bic());

    // ── Balance (HKSAL) ──
    let balance = match dialog.balance(account).await {
        Ok(BalanceResult::Success(b)) => {
            info!("[{}] Balance: {}", tag, b.amount);
            Some(b)
        }
        Ok(BalanceResult::NeedTan(_)) => {
            warn!("[{}] Balance requires additional TAN — skipping", tag);
            None
        }
        Ok(BalanceResult::Empty) => {
            warn!("[{}] No balance data in response", tag);
            None
        }
        Err(e) => {
            warn!("[{}] Balance failed: {}", tag, e);
            None
        }
    };

    let transactions = fetch_transactions(tag, dialog, account, days).await?;

    // ── Holdings (HKWPD) — best-effort, non-fatal ──
    let holdings = match fetch_holdings_default(tag, dialog, account).await {
        Ok(h) => h,
        Err(e) => {
            warn!("[{}] Holdings fetch failed (non-fatal): {}", tag, e);
            Vec::new()
        }
    };

    Ok(FetchResult { balance, transactions, holdings })
}

/// Fetch and parse all transaction pages (HKKAZ with touchdown pagination).
pub async fn fetch_transactions(
    tag: &str,
    dialog: &mut Dialog<Open>,
    account: &Account,
    days: u32,
) -> Result<Vec<Transaction>> {
    let end_date = chrono::Local::now().date_naive();
    let start_date = end_date - chrono::Duration::days(days.max(1) as i64);
    info!("[{}] Transactions {} to {}", tag, start_date, end_date);

    let mut all_booked = Mt940Data::new();
    let mut all_pending = Mt940Data::new();
    let mut touchdown: Option<TouchdownPoint> = None;
    let mut pages = 0u32;

    loop {
        match dialog.transactions(account, start_date, end_date, touchdown.as_ref()).await? {
            TransactionResult::NeedTan(_) => {
                return Err(FinTSError::Dialog(format!(
                    "{tag}: the bank requires an additional TAN for transactions"
                )));
            }
            TransactionResult::Success(page) => {
                pages += 1;
                if !page.booked.is_empty() { all_booked.extend(page.booked.0); }
                if !page.pending.is_empty() { all_pending.extend(page.pending.0); }
                match page.touchdown {
                    // A bank repeating the same touchdown point would loop forever.
                    Some(td) if Some(&td) == touchdown.as_ref() => {
                        warn!("[{}] Bank repeated touchdown point {} — stopping", tag, td);
                        break;
                    }
                    Some(td) => {
                        info!("[{}] Touchdown {} (page {}): more data...", tag, td, pages);
                        touchdown = Some(td);
                    }
                    None => break,
                }
            }
        }
    }

    let mut transactions = parse_mt940(all_booked.as_bytes(), TransactionStatus::Booked)?;
    if !all_pending.is_empty() {
        transactions.extend(parse_mt940(all_pending.as_bytes(), TransactionStatus::Pending)?);
    }
    info!("[{}] {} transactions in {} page(s)", tag, transactions.len(), pages);
    Ok(transactions)
}

/// Fetch all holdings pages (HKWPD). A depot the bank doesn't offer, or an
/// account that can't be addressed as a depot, yields an empty list.
pub async fn fetch_holdings_default(
    tag: &str,
    dialog: &mut Dialog<Open>,
    account: &Account,
) -> Result<Vec<SecurityHolding>> {
    info!("[{}] Fetching holdings for {}", tag, account.account_number().unwrap_or(account.iban()));

    let mut all_holdings = Vec::new();
    let mut touchdown: Option<TouchdownPoint> = None;

    loop {
        let result = match dialog.holdings(account, None, touchdown.as_ref()).await {
            Ok(r) => r,
            Err(FinTSError::SegmentNotSupported(why)) if all_holdings.is_empty() => {
                info!("[{}] Holdings not available: {}", tag, why);
                return Ok(all_holdings);
            }
            Err(e) => return Err(e),
        };

        match result {
            HoldingsResult::NeedTan(_) => {
                warn!("[{}] Holdings requires additional TAN — skipping", tag);
                return Ok(all_holdings);
            }
            HoldingsResult::Empty => break,
            HoldingsResult::Success(page) => {
                all_holdings.extend(page.holdings);
                match page.touchdown {
                    Some(td) if Some(&td) == touchdown.as_ref() => break,
                    Some(td) => touchdown = Some(td),
                    None => break,
                }
            }
        }
    }

    info!("[{}] {} holdings", tag, all_holdings.len());
    Ok(all_holdings)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DKB implementation
// ═══════════════════════════════════════════════════════════════════════════════

/// DKB (Deutsche Kreditbank) FinTS workflow.
///
/// DKB message flow per spec + empirical discovery:
/// ```text
///   Sync dialog (skipped with a cached SessionState):
///     Msg 1: HKIDN + HKVVB + HKSYN   → BPD, system_id
///     Msg 2: HKEND
///
///   Business dialog:
///     Msg 1: HKIDN + HKVVB + HKTAN:4(ref=HKIDN)  → InitResult
///       → TanRequired: push sent (3955)
///       → Opened: SCA exemption (3076)
///     Msg 2: HKTAN:S(task_ref)                     → PollResult
///       → Confirmed: 0020
///       → Pending: 3955/3956
///     Msg 3: HKSAL [+ HKTAN:4(ref=HKSAL)]         → SendResult
///       → Success: balance data (HISAL)
///       → NeedTan: additional TAN for balance
///     Msg 4: HKKAZ [+ HKTAN:4(ref=HKKAZ)]         → SendResult
///       → Success: transaction data (HIKAZ)
///       → Touchdown: more data, fetch again
///     Msg 5: HKEND
/// ```
pub struct Dkb {
    bank: BankConfig,
}

impl Dkb {
    pub fn new() -> Self {
        Self {
            bank: crate::banks::bank_by_blz("12030000").unwrap_or_else(|| {
                BankConfig::new(
                    "Deutsche Kreditbank Berlin (DKB) AG",
                    "12030000",
                    "BYLADEM1001",
                    "https://fints.dkb.de/fints",
                )
            }),
        }
    }
}

impl BankOps for Dkb {
    fn config(&self) -> &BankConfig { &self.bank }

    async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        _target_iban: Option<&Iban>,
        _target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        initiate_default(self, username, pin, product_id, session).await
    }

    async fn fetch(&self, dialog: &mut Dialog<Open>, account: &Account, days: u32) -> Result<FetchResult> {
        fetch_default("DKB", dialog, account, days).await
    }

    async fn fetch_holdings(&self, dialog: &mut Dialog<Open>, account: &Account) -> Result<Vec<SecurityHolding>> {
        fetch_holdings_default("DKB", dialog, account).await
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ING implementation
// ═══════════════════════════════════════════════════════════════════════════════

/// ING-DiBa (BLZ 50010517) FinTS workflow.
///
/// Starts identical to the generic path: overrides get added only once a
/// captured exchange with the real bank proves the generic flow wrong (see
/// the fork guide, "Testing against real banks"). Candidates to confirm with
/// real traffic: the security function used for dialog init (999 vs 900),
/// whether HKTAN:4 must accompany HKSAL/HKKAZ, and the TAN medium name.
///
/// Expected message flow (to be confirmed and updated from real traffic):
/// ```text
///   Sync dialog (first run only; cached in SessionState afterwards):
///     Msg 1: HKIDN + HKVVB + HKSYN            → BPD, UPD, system ID
///     Msg 2: HKEND
///
///   Business dialog:
///     Msg 1: HKIDN + HKVVB + HKTAN:4(ref=HKIDN)
///       → 3955 + HITAN: decoupled pushTAN sent to the ING app
///       → 3076: SCA exemption (90-day window), dialog open
///     Msg 2..n: HKTAN:S(task_ref)             → 3956 pending … 0020 confirmed
///     Then per account: HKSAL, HKKAZ (3040 touchdown pages), HKWPD for the depot
///     Last: HKEND
/// ```
pub struct Ing {
    bank: BankConfig,
}

impl Ing {
    /// ING-DiBa's BLZ.
    pub const BLZ: &'static str = "50010517";

    pub fn new() -> Self {
        Self {
            bank: crate::banks::bank_by_blz(Self::BLZ).unwrap_or_else(|| {
                // Same values as hbci4java's blz.properties.
                BankConfig::new("ING-DiBa", Self::BLZ, "INGDDEFFXXX", "https://fints.ing.de/fints/")
            }),
        }
    }
}

impl BankOps for Ing {
    fn config(&self) -> &BankConfig { &self.bank }

    async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        _target_iban: Option<&Iban>,
        _target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        initiate_default(self, username, pin, product_id, session).await
    }

    async fn fetch(&self, dialog: &mut Dialog<Open>, account: &Account, days: u32) -> Result<FetchResult> {
        fetch_default("ING", dialog, account, days).await
    }

    async fn fetch_holdings(&self, dialog: &mut Dialog<Open>, account: &Account) -> Result<Vec<SecurityHolding>> {
        fetch_holdings_default("ING", dialog, account).await
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Generic bank — any FinTS endpoint (used for custom/unknown banks)
// ═══════════════════════════════════════════════════════════════════════════════

/// A generic FinTS bank implementation that works with any BankConfig.
/// Used when the bank ID is not in the registry (e.g. custom URL + BLZ).
pub struct GenericBank {
    bank: BankConfig,
}

impl GenericBank {
    pub fn new(config: BankConfig) -> Self {
        Self { bank: config }
    }
}

impl BankOps for GenericBank {
    fn config(&self) -> &BankConfig { &self.bank }

    async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        _target_iban: Option<&Iban>,
        _target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        initiate_default(self, username, pin, product_id, session).await
    }

    async fn fetch(&self, dialog: &mut Dialog<Open>, account: &Account, days: u32) -> Result<FetchResult> {
        fetch_default(self.bank.name.as_str(), dialog, account, days).await
    }

    async fn fetch_holdings(&self, dialog: &mut Dialog<Open>, account: &Account) -> Result<Vec<SecurityHolding>> {
        fetch_holdings_default(self.bank.name.as_str(), dialog, account).await
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bank registry
// ═══════════════════════════════════════════════════════════════════════════════

/// Enum dispatch for bank implementations — zero-cost, no dynamic dispatch.
///
/// New banks are added here as enum variants. This avoids `Box<dyn BankOps>`
/// which is incompatible with native async fn in traits.
pub enum AnyBank {
    Dkb(Dkb),
    Ing(Ing),
    Generic(GenericBank),
}

macro_rules! dispatch {
    ($self:ident, $b:ident => $e:expr) => {
        match $self {
            AnyBank::Dkb($b) => $e,
            AnyBank::Ing($b) => $e,
            AnyBank::Generic($b) => $e,
        }
    };
}

impl AnyBank {
    pub fn config(&self) -> &BankConfig {
        dispatch!(self, b => b.config())
    }

    pub async fn initiate(
        &self,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<InitiateOutcome> {
        dispatch!(self, b => b.initiate(username, pin, product_id, session, target_iban, target_bic).await)
    }

    pub async fn fetch(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        days: u32,
    ) -> Result<FetchResult> {
        dispatch!(self, b => b.fetch(dialog, account, days).await)
    }

    pub async fn fetch_holdings(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
    ) -> Result<Vec<SecurityHolding>> {
        dispatch!(self, b => b.fetch_holdings(dialog, account).await)
    }

    /// Fetch data with fine-grained control via `FetchOpts`.
    /// This gives callers a single authenticated dialog for all operations.
    pub async fn fetch_with_opts(
        &self,
        dialog: &mut Dialog<Open>,
        account: &Account,
        opts: &FetchOpts,
    ) -> Result<FetchResult> {
        let tag = self.config().name.as_str().to_string();

        let balance = if opts.balance {
            match dialog.balance(account).await {
                Ok(BalanceResult::Success(b)) => Some(b),
                Ok(BalanceResult::NeedTan(_)) => { warn!("[{}] Balance requires TAN — skipping", tag); None }
                Ok(BalanceResult::Empty) => None,
                Err(e) => { warn!("[{}] Balance failed: {}", tag, e); None }
            }
        } else {
            None
        };

        let transactions = if opts.transactions {
            fetch_transactions(&tag, dialog, account, opts.days).await?
        } else {
            Vec::new()
        };

        let holdings = if opts.holdings {
            match self.fetch_holdings(dialog, account).await {
                Ok(h) => h,
                Err(e) => { warn!("[{}] Holdings fetch failed: {}", tag, e); Vec::new() }
            }
        } else {
            Vec::new()
        };

        Ok(FetchResult { balance, transactions, holdings })
    }
}

/// Look up a bank implementation by its BLZ (Bankleitzahl).
///
/// The BLZ is the canonical bank identifier — banks are dispatched based on it.
/// `12030000` → DKB, `50010517` → ING; all others → GenericBank.
pub fn bank_ops(blz: &str) -> Result<AnyBank> {
    let config = crate::banks::bank_by_blz(blz)
        .ok_or_else(|| FinTSError::Dialog(format!("Unknown BLZ: {}", blz)))?;
    match blz {
        "12030000" => Ok(AnyBank::Dkb(Dkb::new())),
        Ing::BLZ => Ok(AnyBank::Ing(Ing::new())),
        _ => Ok(AnyBank::Generic(GenericBank::new(config))),
    }
}

/// Create a bank implementation from a custom BankConfig (for non-registry banks).
pub fn bank_ops_with_config(config: BankConfig) -> AnyBank {
    AnyBank::Generic(GenericBank::new(config))
}

// ═══════════════════════════════════════════════════════════════════════════════
// MT940 parsing
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_mt940(data: &[u8], status: TransactionStatus) -> Result<Vec<Transaction>> {
    if data.is_empty() { return Ok(Vec::new()); }

    let (cow, _, had_errors) = encoding_rs::WINDOWS_1252.decode(data);
    if had_errors { warn!("MT940 encoding errors"); }
    let mt940_text = cow.into_owned();

    let cleaned: String = mt940_text.lines()
        .filter(|l| { let t = l.trim(); !t.is_empty() && t != "-" && t != "--" })
        .collect::<Vec<_>>().join("\r\n") + "\r\n";

    let sanitized = mt940::sanitizers::to_swift_charset(&cleaned);
    let messages = mt940::parse_mt940(&sanitized)
        .map_err(|e| FinTSError::Mt940(format!("MT940 parse error: {}", e)))?;

    let mut transactions = Vec::new();
    for msg in messages {
        for line in msg.statement_lines {
            let is_debit = matches!(line.ext_debit_credit_indicator, mt940::ExtDebitOrCredit::Debit);
            let amount = if is_debit { -line.amount } else { line.amount };

            let (applicant_name, applicant_iban, applicant_bic, purpose, posting_text) =
                match &line.information_to_account_owner {
                    Some(mt940::InformationToAccountOwner::Structured {
                        applicant_name, applicant_iban, applicant_bin, purpose, posting_text, ..
                    }) => (applicant_name.clone(), applicant_iban.clone(), applicant_bin.clone(), purpose.clone(), posting_text.clone()),
                    Some(mt940::InformationToAccountOwner::Plain(text)) => (None, None, None, Some(text.clone()), None),
                    None => (None, None, None, None, None),
                };

            let raw = serde_json::json!({
                "date": line.value_date.to_string(),
                "entry_date": line.entry_date.map(|d| d.to_string()),
                "amount": amount.to_string(),
                "currency": msg.opening_balance.iso_currency_code,
                "customer_ref": line.customer_ref,
                "bank_ref": line.bank_ref,
                "applicant_name": applicant_name,
                "applicant_iban": applicant_iban,
                "applicant_bic": applicant_bic,
                "purpose": purpose,
                "posting_text": posting_text,
            });

            transactions.push(Transaction {
                date: line.value_date, valuta_date: line.entry_date,
                amount,
                currency: Currency::new(&msg.opening_balance.iso_currency_code),
                applicant_name,
                applicant_iban: applicant_iban.map(|s| Iban::new(s)),
                applicant_bic: applicant_bic.map(|s| Bic::new(s)),
                purpose, posting_text,
                reference: Some(line.customer_ref.clone()),
                raw, status: status.clone(),
            });
        }
    }
    Ok(transactions)
}
