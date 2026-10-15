//! High-level Flow API.
//!
//! Orchestrates the interactive TAN flow for one user at one bank:
//!
//! 1. [`Flow::initiate`] — [sync +] dialog init. Pass the [`SessionState`]
//!    from the previous run so the sync dialog is skipped and the bank keeps
//!    seeing the same system ID.
//! 2. If [`Flow::needs_tan`]: [`Flow::await_decoupled`] waits for the app
//!    confirmation (pushTAN), reporting progress through a callback.
//! 3. [`Flow::fetch`] any number of accounts in the same dialog.
//! 4. [`Flow::finish`] ends the dialog and returns the updated
//!    [`SessionState`] to persist (encrypted) for the next run.
//!
//! The older one-shot helpers (`confirm_and_fetch*`) still work: they poll
//! the TAN status once, fetch one account and end the dialog.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{FinTSError, Result};
use crate::protocol::*;
use crate::session::SessionState;
use crate::types::*;
use crate::workflow::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Public result types
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub challenge: ChallengeText,
    pub challenge_hhduc: Option<HhdUcData>,
    pub decoupled: bool,
    pub tan_methods: Vec<TanMethod>,
    pub allowed_security_functions: Vec<SecurityFunction>,
    /// If true, skip TAN step — SCA exemption.
    pub no_tan_required: bool,
}

impl ChallengeInfo {
    /// The challenge's flicker code or photoTAN/QR image, if it has one.
    pub fn media(&self) -> Option<TanMedia> {
        self.challenge_hhduc.as_ref().and_then(HhdUcData::decode)
    }
}

/// Type alias for `FetchOpts` — preferred name in the flow/public API.
/// Both names refer to the same type from the workflow module.
pub use crate::workflow::FetchOpts as FetchOptions;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub iban: Iban,
    pub bic: Bic,
    pub balance: Option<AccountBalance>,
    pub transactions: Vec<Transaction>,
    pub holdings: Vec<SecurityHolding>,
    pub system_id: Option<SystemId>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Flow
// ═══════════════════════════════════════════════════════════════════════════════

enum FlowState {
    WaitingForTan {
        dialog: Dialog<TanPending>,
        challenge: TanChallenge,
    },
    Authenticated {
        dialog: Dialog<Open>,
    },
    Done,
}

pub struct Flow {
    bank: AnyBank,
    state: FlowState,
    blz: Blz,
    user_id: UserId,
    system_id: SystemId,
    /// Latest bank parameters, kept after the dialog ends for `session_state()`.
    params: BankParams,
}

const STILL_PENDING: &str = "TAN still pending: user has not yet confirmed in banking app";

impl Flow {
    /// Step 1: initiate connection using an already-resolved AnyBank.
    /// Use this when you have a custom BankConfig (e.g. non-registry banks).
    pub async fn initiate_with_bank(
        bank: AnyBank,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<(Self, ChallengeInfo)> {
        Self::initiate_inner(bank, username, pin, product_id, session, target_iban, target_bic).await
    }

    /// Step 1: initiate connection by BLZ, get TAN challenge.
    ///
    /// `session`: state from the previous run (see [`Flow::finish`]), or `None`
    /// on the very first run.
    pub async fn initiate(
        bank_id: &str,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<(Self, ChallengeInfo)> {
        let bank = bank_ops(bank_id)?;
        Self::initiate_inner(bank, username, pin, product_id, session, target_iban, target_bic).await
    }

    async fn initiate_inner(
        bank: AnyBank,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        session: Option<&SessionState>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<(Self, ChallengeInfo)> {
        let outcome = bank.initiate(
            username, pin, product_id, session, target_iban, target_bic,
        ).await?;
        let blz = bank.config().blz.clone();

        match outcome {
            InitiateOutcome::NeedTan(result) => {
                let info = ChallengeInfo {
                    challenge: result.challenge.challenge.clone(),
                    challenge_hhduc: result.challenge.challenge_hhduc.clone(),
                    decoupled: result.challenge.decoupled,
                    tan_methods: result.tan_methods,
                    allowed_security_functions: result.allowed_security_functions,
                    no_tan_required: false,
                };
                let flow = Flow {
                    bank,
                    state: FlowState::WaitingForTan {
                        dialog: result.dialog,
                        challenge: result.challenge,
                    },
                    blz,
                    user_id: username.clone(),
                    system_id: result.system_id,
                    params: result.params,
                };
                Ok((flow, info))
            }
            InitiateOutcome::Authenticated(result) => {
                let info = ChallengeInfo {
                    challenge: ChallengeText::new(""),
                    challenge_hhduc: None,
                    decoupled: false,
                    tan_methods: result.tan_methods,
                    allowed_security_functions: result.allowed_security_functions,
                    no_tan_required: true,
                };
                let flow = Flow {
                    bank,
                    state: FlowState::Authenticated { dialog: result.dialog },
                    blz,
                    user_id: username.clone(),
                    system_id: result.system_id,
                    params: result.params,
                };
                Ok((flow, info))
            }
        }
    }

    /// True while a TAN confirmation is pending.
    pub fn needs_tan(&self) -> bool {
        matches!(self.state, FlowState::WaitingForTan { .. })
    }

    /// The pending TAN challenge, if any.
    pub fn challenge(&self) -> Option<&TanChallenge> {
        match &self.state {
            FlowState::WaitingForTan { challenge, .. } => Some(challenge),
            _ => None,
        }
    }

    /// Step 2 (decoupled TAN, e.g. pushTAN): wait until the user confirms in
    /// the banking app, polling at the bank's announced intervals.
    ///
    /// Returns immediately if no TAN is pending. On timeout, cancellation or a
    /// bank error the dialog is gone and the flow is finished; start over with
    /// [`Flow::initiate`].
    pub async fn await_decoupled(
        &mut self,
        cancel: tokio_util::sync::CancellationToken,
        opts: &DecoupledOptions,
        on_event: impl FnMut(DecoupledEvent) + Send,
    ) -> Result<()> {
        match std::mem::replace(&mut self.state, FlowState::Done) {
            FlowState::WaitingForTan { dialog, challenge } => {
                let (open, _response) = dialog.await_decoupled(&challenge, cancel, opts, on_event).await?;
                info!("[Flow] Decoupled TAN confirmed");
                self.params = open.bank_params().clone();
                self.state = FlowState::Authenticated { dialog: open };
                Ok(())
            }
            other => {
                let done = matches!(other, FlowState::Done);
                self.state = other;
                if done { Err(FinTSError::Dialog("Flow already completed".into())) } else { Ok(()) }
            }
        }
    }

    /// Step 2 (TAN entry: chipTAN, photoTAN, smsTAN): send the TAN the user
    /// entered for [`Flow::challenge`]; [`ChallengeInfo::media`] has the
    /// flicker code or image to show first.
    ///
    /// On success the dialog is authenticated. If the bank rejects the TAN
    /// the dialog is gone and the flow is finished; start over with
    /// [`Flow::initiate`]. Decoupled challenges are confirmed in the app
    /// instead: use [`Flow::await_decoupled`].
    pub async fn submit_tan(&mut self, tan: &str) -> Result<()> {
        match std::mem::replace(&mut self.state, FlowState::Done) {
            FlowState::WaitingForTan { dialog, challenge } if !challenge.decoupled => {
                let (open, _response) = dialog.submit_tan(&challenge.task_reference, tan).await?;
                info!("[Flow] TAN accepted");
                self.params = open.bank_params().clone();
                self.state = FlowState::Authenticated { dialog: open };
                Ok(())
            }
            FlowState::Done => Err(FinTSError::Dialog("Flow already completed".into())),
            other => {
                let decoupled = matches!(other, FlowState::WaitingForTan { .. });
                self.state = other;
                Err(FinTSError::Dialog(if decoupled {
                    "decoupled TAN: confirm in the app and call await_decoupled()".into()
                } else {
                    "no TAN pending".into()
                }))
            }
        }
    }

    /// Poll the decoupled TAN status once. `Ok(true)` = confirmed (or no TAN
    /// was pending), `Ok(false)` = still pending. Prefer [`Flow::await_decoupled`],
    /// which respects the bank's polling rules.
    pub async fn poll_once(&mut self) -> Result<bool> {
        match std::mem::replace(&mut self.state, FlowState::Done) {
            FlowState::WaitingForTan { dialog, challenge } => {
                match dialog.poll(&challenge.task_reference).await? {
                    PollResult::Confirmed(open, _response) => {
                        info!("[Flow] TAN confirmed");
                        self.params = open.bank_params().clone();
                        self.state = FlowState::Authenticated { dialog: open };
                        Ok(true)
                    }
                    PollResult::Pending(dialog) => {
                        self.state = FlowState::WaitingForTan { dialog, challenge };
                        Ok(false)
                    }
                }
            }
            FlowState::Done => Err(FinTSError::Dialog("Flow already completed".into())),
            other => {
                self.state = other;
                Ok(true)
            }
        }
    }

    /// Accounts the bank listed in the UPD (giro, savings, depot, …).
    pub fn accounts(&self) -> &[SepaAccount] {
        match &self.state {
            FlowState::Authenticated { dialog } => &dialog.bank_params().accounts_from_upd,
            FlowState::WaitingForTan { dialog, .. } => &dialog.bank_params().accounts_from_upd,
            FlowState::Done => &self.params.accounts_from_upd,
        }
    }

    /// Step 3: fetch data for one account. The dialog stays open, so call this
    /// for every account, then [`Flow::finish`].
    pub async fn fetch(&mut self, account: &Account, opts: &FetchOpts) -> Result<FetchResult> {
        match &mut self.state {
            FlowState::Authenticated { dialog } => {
                let result = self.bank.fetch_with_opts(dialog, account, opts).await;
                self.params = dialog.bank_params().clone();
                result
            }
            FlowState::WaitingForTan { .. } => Err(FinTSError::Dialog(
                "TAN confirmation pending: call await_decoupled() first".into(),
            )),
            FlowState::Done => Err(FinTSError::Dialog("Flow already completed".into())),
        }
    }

    /// Step 4: end the dialog and return the session state to persist.
    pub async fn finish(mut self) -> Result<SessionState> {
        self.end_dialog().await;
        Ok(self.session_state())
    }

    /// Current session state (system ID, BPD/UPD, TAN method) to persist.
    pub fn session_state(&self) -> SessionState {
        let (params, system_id) = match &self.state {
            FlowState::Authenticated { dialog } => (dialog.bank_params(), dialog.system_id()),
            FlowState::WaitingForTan { dialog, .. } => (dialog.bank_params(), dialog.system_id()),
            FlowState::Done => (&self.params, &self.system_id),
        };
        SessionState::capture(&self.blz, &self.user_id, system_id, params)
    }

    async fn end_dialog(&mut self) {
        match std::mem::replace(&mut self.state, FlowState::Done) {
            FlowState::Authenticated { dialog } => {
                self.params = dialog.bank_params().clone();
                self.system_id = dialog.system_id().clone();
                dialog.end().await.ok();
            }
            FlowState::WaitingForTan { dialog, .. } => {
                self.params = dialog.bank_params().clone();
                dialog.cancel().await.ok();
            }
            FlowState::Done => {}
        }
    }

    /// Ensure the dialog is authenticated, polling the TAN status once.
    async fn ensure_authenticated(&mut self) -> Result<()> {
        if self.poll_once().await? {
            Ok(())
        } else {
            Err(FinTSError::Dialog(STILL_PENDING.into()))
        }
    }

    /// Step 2+3 in one go: poll TAN once and fetch everything
    /// (balance + transactions + holdings), then end the dialog.
    /// Equivalent to `confirm_and_fetch_opts(iban, bic, FetchOpts::all(days))`.
    pub async fn confirm_and_fetch(
        &mut self,
        iban: &str,
        bic: &str,
        days: u32,
    ) -> Result<SyncResult> {
        self.confirm_and_fetch_opts(iban, bic, &FetchOpts::all(days)).await
    }

    /// Like [`Flow::confirm_and_fetch`] with fine-grained fetch control.
    /// If the TAN is still pending, returns an error and the flow stays usable.
    pub async fn confirm_and_fetch_opts(
        &mut self,
        iban: &str,
        bic: &str,
        opts: &FetchOpts,
    ) -> Result<SyncResult> {
        self.ensure_authenticated().await?;
        let account = self.resolve_account(iban, bic)?;
        let fetch = self.fetch(&account, opts).await;
        self.end_dialog().await;
        let fetch = fetch?;
        Ok(SyncResult {
            iban: Iban::new(iban), bic: Bic::new(bic),
            balance: fetch.balance, transactions: fetch.transactions,
            holdings: fetch.holdings,
            system_id: Some(self.system_id.clone()),
        })
    }

    /// Poll TAN once and fetch only securities holdings, then end the dialog.
    pub async fn confirm_and_fetch_holdings(
        &mut self,
        iban: &str,
        bic: &str,
    ) -> Result<Vec<SecurityHolding>> {
        self.ensure_authenticated().await?;
        let account = self.resolve_account(iban, bic)?;
        let result = match &mut self.state {
            FlowState::Authenticated { dialog } => self.bank.fetch_holdings(dialog, &account).await,
            _ => Err(FinTSError::Dialog("Flow already completed".into())),
        };
        self.end_dialog().await;
        result
    }

    pub fn system_id(&self) -> &SystemId { &self.system_id }

    /// Resolve account with bank's BIC as fallback; prefer the UPD entry for
    /// this IBAN so the bank's own account number is used for national formats.
    fn resolve_account(&self, iban: &str, bic: &str) -> Result<Account> {
        let bank_bic = self.bank.config().bic.as_str();
        if let Some(acc) = self.accounts().iter().find(|a| a.iban.as_str() == iban) {
            let acc = SepaAccount {
                bic: Bic::new(if bic.is_empty() { acc.bic.as_str() } else { bic }),
                ..acc.clone()
            };
            return Account::from_sepa(&acc, bank_bic);
        }
        Account::new(iban, if bic.is_empty() { bank_bic } else { bic })
    }
}
