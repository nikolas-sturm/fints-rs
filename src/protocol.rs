//! FinTS 3.0 Protocol State Machine (spec-aligned).
//!
//! Implements the dialog lifecycle as defined in FinTS 3.0 Formals (2017-10-06)
//! and PIN/TAN Security (2020-07-10).
//!
//! ## Dialog types (spec Chapter C)
//!
//! - **Synchronization dialog**: HKIDN + HKVVB + HKSYN → get system_id → HKEND.
//!   Marked by presence of HKSYN. Business segments are forbidden (banks return 9110).
//! - **Normal dialog**: HKIDN + HKVVB [+ HKTAN:4] → [TAN confirmation] → business ops → HKEND.
//!
//! ## State machine (spec Chapter C, Section 6)
//!
//! ```text
//!   Dialog<New>
//!       │
//!       ├── sync()           → (Dialog<Synced>, Response)      [sync dialog]
//!       │
//!       └── init()           → InitResult                      [normal dialog]
//!             ├── Opened(Dialog<Open>)                            response 0010/0020
//!             └── TanRequired(Dialog<TanPending>, TanChallenge)   response 0030/3955
//!
//!   Dialog<Synced>
//!       └── end()            → (BankParams, String)             [get params + system_id]
//!
//!   Dialog<Open>
//!       ├── send()           → SendResult                       [business segment]
//!       │     ├── Success(Response)                               response 0020
//!       │     ├── NeedTan(Dialog<TanPending>, TanChallenge)       response 0030/3955
//!       │     └── Touchdown(Response, String)                     response 3040
//!       └── end()            → ()                               [HKEND]
//!
//!   Dialog<TanPending>
//!       ├── poll()           → PollResult                       [HKTAN process S]
//!       │     ├── Confirmed(Dialog<Open>, Response)               response 0020
//!       │     └── Pending(Dialog<TanPending>)                     response 3955/3956
//!       ├── submit_tan()     → (Dialog<Open>, Response)         [HKTAN process 2]
//!       └── cancel()         → ()                               [HKEND]
//! ```

use std::collections::HashMap;
use std::marker::PhantomData;
use tracing::{debug, info, warn};

use chrono::NaiveDate;

use crate::error::{FinTSError, Result};
use crate::message;
use crate::parser::{self, RawSegment, DEG};
use crate::segments::response::*;
use crate::transport::FinTSConnection;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Typestate markers (per spec dialog states)
// ═══════════════════════════════════════════════════════════════════════════════

/// Dialog not yet started. Can transition to `Synced` or `Open`/`TanPending`.
#[derive(Debug)]
pub struct New;
/// Synchronization dialog: system_id obtained, BPD/UPD cached. No business ops allowed.
#[derive(Debug)]
pub struct Synced;
/// Dialog is open and authenticated. Business segments can be sent.
#[derive(Debug)]
pub struct Open;
/// A TAN challenge is pending (either from init or from a business segment).
#[derive(Debug)]
pub struct TanPending;

// ═══════════════════════════════════════════════════════════════════════════════
// Typed business segments — replaces raw Vec<DEG> at all internal boundaries
// ═══════════════════════════════════════════════════════════════════════════════

/// A typed FinTS business segment. Every field is validated at construction.
/// This is the ONLY way to construct segments within the crate — raw DEG
/// builders are never called directly from protocol or workflow code.
#[derive(Debug, Clone)]
pub(crate) enum Segment {
    /// HKIDN: Identifikation (dialog init)
    Identify {
        blz: Blz,
        user_id: UserId,
        system_id: SystemId,
    },
    /// HKVVB: Verarbeitungsvorbereitung
    ProcessPrep {
        bpd_version: u16,
        upd_version: u16,
        product_id: ProductId,
    },
    /// HKSYN: Synchronisierung (get system_id)
    Sync,
    /// HKSAL: Saldenabfrage (balance request)
    Balance { account: Account },
    /// HKKAZ: Kontoumsätze (transaction request)
    Transactions {
        account: Account,
        start_date: NaiveDate,
        end_date: NaiveDate,
        touchdown: Option<TouchdownPoint>,
    },
    /// HKWPD: Wertpapierdepotaufstellung (securities holdings request)
    Holdings {
        account: Account,
        currency: Option<Currency>,
        touchdown: Option<TouchdownPoint>,
    },
    /// HKTAN process 4: initiate TAN for a referenced segment
    TanProcess4 {
        reference_seg: SegmentRef,
        tan_medium: Option<TanMediumName>,
    },
    /// HKTAN process S: poll decoupled TAN status
    TanPollDecoupled {
        task_reference: TaskReference,
        tan_medium: Option<TanMediumName>,
    },
    /// HKTAN process 2: submit TAN response
    TanProcess2 {
        task_reference: TaskReference,
        tan_medium: Option<TanMediumName>,
    },
    /// HKEND: dialog end
    End { dialog_id: DialogId },
}

impl Segment {
    /// Convert to raw DEGs, choosing segment versions from the bank's BPD.
    pub(crate) fn to_degs(&self, params: &BankParams) -> Result<Vec<DEG>> {
        use crate::segments::builder::*;
        let td = |t: &Option<TouchdownPoint>| t.as_ref().map(|t| t.as_str().to_string());
        Ok(match self {
            Segment::Identify {
                blz,
                user_id,
                system_id,
            } => hkidn(0, blz.as_str(), user_id.as_str(), system_id.as_str()),
            Segment::ProcessPrep {
                bpd_version,
                upd_version,
                product_id,
            } => hkvvb(0, *bpd_version, *upd_version, product_id.as_str()),
            Segment::Sync => hksyn(0),
            Segment::Balance { account } => {
                let version = params.negotiate_version("HISALS", HKSAL_VERSIONS, 7)?;
                hksal(0, version, account, None)?
            }
            Segment::Transactions {
                account,
                start_date,
                end_date,
                touchdown,
            } => {
                let version = params.negotiate_version("HIKAZS", HKKAZ_VERSIONS, 7)?;
                hkkaz(
                    0,
                    version,
                    account,
                    *start_date,
                    *end_date,
                    td(touchdown).as_deref(),
                )?
            }
            Segment::Holdings {
                account,
                currency,
                touchdown,
            } => {
                let version = params.negotiate_version("HIWPDS", HKWPD_VERSIONS, 6)?;
                hkwpd(
                    0,
                    version,
                    account,
                    currency.as_ref().map(|c| c.as_str()),
                    td(touchdown).as_deref(),
                )?
            }
            Segment::TanProcess4 {
                reference_seg,
                tan_medium,
            } => hktan_process4(
                0,
                params.hktan_version(),
                reference_seg.as_str(),
                tan_medium.as_ref().map(|t| t.as_str()),
            )?,
            Segment::TanPollDecoupled {
                task_reference,
                tan_medium,
            } => hktan_process_s(
                0,
                params.hktan_version(),
                task_reference.as_str(),
                tan_medium.as_ref().map(|t| t.as_str()),
            )?,
            Segment::TanProcess2 {
                task_reference,
                tan_medium,
            } => hktan_process2(
                0,
                params.hktan_version(),
                task_reference.as_str(),
                tan_medium.as_ref().map(|t| t.as_str()),
            )?,
            Segment::End { dialog_id } => hkend(0, dialog_id.as_str()),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Result of dialog init — response-driven transition
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of `Dialog::init()`. Per the spec, the bank either accepts the dialog
/// (0010/0020) or requires SCA (0030/3955).
pub enum InitResult {
    /// Dialog opened, no TAN needed. Ready for business segments.
    Opened(Dialog<Open>, Response),
    /// Bank requires TAN on init (SCA). Must confirm before business ops.
    TanRequired(Dialog<TanPending>, TanChallenge, Response),
}

// ═══════════════════════════════════════════════════════════════════════════════
// Result of sending a business segment — response-driven transition
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of `Dialog<Open>::send()`. Per the spec, three outcomes are possible.
pub enum SendResult {
    /// 0020: Order executed. Response contains the result data (HISAL, HIKAZ, etc.).
    Success(Response),
    /// 0030/3955: TAN required for this operation. Dialog transitions to TanPending.
    NeedTan(Dialog<TanPending>, TanChallenge, Response),
    /// 3040: More data available (pagination). Response contains partial data
    /// plus a touchdown point string for the next request.
    Touchdown(Response, String),
}

// ═══════════════════════════════════════════════════════════════════════════════
// Result of polling TAN — response-driven transition
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of `Dialog<TanPending>::poll()`.
pub enum PollResult {
    /// TAN confirmed. Dialog returns to Open state.
    Confirmed(Dialog<Open>, Response),
    /// TAN still pending (3955/3956). Dialog remains in TanPending.
    Pending(Dialog<TanPending>),
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parsed bank response
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed response from the bank after sending a message.
#[derive(Debug)]
pub struct Response {
    /// All segments from the response (including inner HNVSD segments).
    pub segments: Vec<RawSegment>,
    /// Global response codes (from HIRMG).
    pub global_codes: Vec<ResponseCode>,
    /// Segment-specific response codes (from HIRMS).
    pub segment_codes: Vec<ResponseCode>,
}

impl Response {
    pub fn find_segments(&self, seg_type: &str) -> Vec<&RawSegment> {
        self.segments
            .iter()
            .filter(|s| s.segment_type() == seg_type)
            .collect()
    }

    pub fn find_segment(&self, seg_type: &str) -> Option<&RawSegment> {
        self.segments.iter().find(|s| s.segment_type() == seg_type)
    }

    pub fn all_codes(&self) -> impl Iterator<Item = &ResponseCode> {
        self.global_codes.iter().chain(self.segment_codes.iter())
    }

    /// 0030 = order received, TAN required.
    pub fn needs_tan(&self) -> bool {
        self.all_codes()
            .any(|c| c.is_tan_required() || c.is_decoupled())
    }

    /// 3955 = decoupled TAN (pushTAN initiated).
    pub fn is_decoupled(&self) -> bool {
        self.all_codes().any(|c| c.is_decoupled())
    }

    /// 3955/3956 = decoupled TAN still pending.
    pub fn is_decoupled_pending(&self) -> bool {
        self.all_codes().any(|c| c.is_decoupled_pending())
    }

    /// 3076 = no strong authentication required (SCA exemption).
    pub fn has_sca_exemption(&self) -> bool {
        self.all_codes()
            .any(|c| c.kind == ResponseCodeKind::ScaExemption)
    }

    /// 3040 = more data available (touchdown/pagination).
    /// Returns the touchdown point if found.
    pub fn touchdown(&self) -> Option<TouchdownPoint> {
        find_touchdown(&self.segment_codes).or_else(|| find_touchdown(&self.global_codes))
    }

    /// Extract HITAN challenge from response.
    pub fn get_tan_challenge(&self) -> Option<TanChallenge> {
        let hitan = parse_hitan(self.find_segment("HITAN")?);
        if hitan.task_reference.is_empty() && hitan.challenge.is_empty() {
            return None;
        }
        Some(TanChallenge {
            challenge: ChallengeText::new(hitan.challenge),
            challenge_hhduc: hitan.challenge_hhduc.map(HhdUcData),
            task_reference: TaskReference::new(hitan.task_reference),
            decoupled: self.is_decoupled(),
        })
    }

    /// Check for fatal errors. Returns `Ok(())` if no errors.
    pub fn check_errors(&self) -> Result<()> {
        for code in self.all_codes() {
            match &code.kind {
                ResponseCodeKind::PinWrong(_) => return Err(FinTSError::PinWrong),
                ResponseCodeKind::AccountLocked(_) => return Err(FinTSError::AccountLocked),
                ResponseCodeKind::SystemIdInvalid => {
                    return Err(FinTSError::SystemIdInvalid(code.text.clone()))
                }
                k if k.is_error() => {
                    return Err(FinTSError::BankError {
                        kind: code.kind.clone(),
                        message: code.text.clone(),
                    })
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Log codes that need no action from a read-only client.
    pub(crate) fn log_informational_codes(&self) {
        for code in self.all_codes() {
            match code.kind {
                ResponseCodeKind::VopNotRequired | ResponseCodeKind::VopApprovalNotPossible => {
                    debug!(
                        "[FinTS] {} (Verification of Payee) ignored for read-only access: {}",
                        code.code(),
                        code.text
                    );
                }
                ResponseCodeKind::OtherWarning(_) => {
                    debug!("[FinTS] Warning {}: {}", code.code(), code.text);
                }
                _ => {}
            }
        }
    }

    /// Extract allowed TAN security functions from code 3920.
    pub fn allowed_security_functions(&self) -> Vec<SecurityFunction> {
        extract_allowed_security_functions(&self.segment_codes)
            .into_iter()
            .chain(extract_allowed_security_functions(&self.global_codes))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAN challenge
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TanChallenge {
    pub challenge: ChallengeText,
    pub challenge_hhduc: Option<HhdUcData>,
    pub task_reference: TaskReference,
    pub decoupled: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bank parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Cached bank and user parameters discovered during sync/init.
///
/// `bpd_segments` / `upd_segments` hold the raw BPD (HIBPA, HIKOM, HITANS,
/// HIPINS, all `HI…S` parameter segments) and UPD (HIUPA, HIUPD) exactly as
/// the bank sent them; everything else here is derived from them. A response
/// that carries a new HIBPA/HIUPA *replaces* the cached set.
#[derive(Debug, Clone)]
pub struct BankParams {
    pub bpd_version: u16,
    pub upd_version: u16,
    pub bpd_segments: Vec<RawSegment>,
    pub upd_segments: Vec<RawSegment>,
    pub tan_methods: Vec<TanMethod>,
    pub selected_security_function: SecurityFunction,
    pub selected_tan_medium: Option<TanMediumName>,
    pub accounts_from_upd: Vec<SepaAccount>,
    pub operation_tan_required: HashMap<SegmentType, bool>,
    pub allowed_security_functions: Vec<SecurityFunction>,
    pub preferred_security_function: Option<SecurityFunction>,
    /// Set when the bank reported code 3072 (changed access data): the new
    /// user ID to use from the next dialog on.
    pub changed_user_id: Option<UserId>,
}

/// Is this a BPD segment (bank parameter data)?
fn is_bpd_segment(stype: &str) -> bool {
    matches!(
        stype,
        "HIBPA" | "HIKOM" | "HISHV" | "HIKPV" | "HIPINS" | "HITANS"
    ) || (stype.starts_with("HI") && stype.len() == 6 && stype.ends_with('S'))
}

impl BankParams {
    pub fn new() -> Self {
        Self {
            bpd_version: 0,
            upd_version: 0,
            bpd_segments: Vec::new(),
            upd_segments: Vec::new(),
            tan_methods: Vec::new(),
            selected_security_function: SecurityFunction::pin_only(),
            selected_tan_medium: None,
            accounts_from_upd: Vec::new(),
            operation_tan_required: HashMap::new(),
            allowed_security_functions: Vec::new(),
            preferred_security_function: None,
            changed_user_id: None,
        }
    }

    /// Ingest BPD/UPD/HISYN/3920/3072 from a response.
    pub fn ingest_response(&mut self, response: &Response, system_id: &mut SystemId) {
        let segs = &response.segments;

        let bpd: Vec<RawSegment> = segs
            .iter()
            .filter(|s| is_bpd_segment(s.segment_type()))
            .cloned()
            .collect();
        if segs.iter().any(|s| s.segment_type() == "HIBPA") {
            self.set_bpd(bpd);
        } else if !bpd.is_empty() {
            // Parameter segments without a BPD header: merge, as before.
            let mut merged = std::mem::take(&mut self.bpd_segments);
            merged.extend(bpd);
            self.set_bpd(merged);
        }

        if segs.iter().any(|s| s.segment_type() == "HIUPA") {
            self.set_upd(
                segs.iter()
                    .filter(|s| matches!(s.segment_type(), "HIUPA" | "HIUPD"))
                    .cloned()
                    .collect(),
            );
        }

        if let Some(sid) = segs
            .iter()
            .find(|s| s.segment_type() == "HISYN")
            .map(parse_hisyn_system_id)
        {
            if !sid.is_empty() {
                info!("[FinTS] System ID: {}", sid);
                *system_id = SystemId::new(sid);
            }
        }

        let allowed = response.allowed_security_functions();
        if !allowed.is_empty() {
            self.allowed_security_functions = allowed;
        }

        // 3072: access data changed. hbci4java passes the new user/customer ID
        // to the application; we also drop the UPD so the next dialog reloads it.
        for code in response.all_codes() {
            if let ResponseCodeKind::UserDataChanged { user_id, .. } = &code.kind {
                warn!(
                    "[FinTS] 3072 changed access data: {} (new user ID: {:?})",
                    code.text, user_id
                );
                if let Some(uid) = user_id {
                    self.changed_user_id = Some(UserId::new(uid.clone()));
                }
                if !segs.iter().any(|s| s.segment_type() == "HIUPA") {
                    self.invalidate_upd();
                }
            }
        }
    }

    /// Replace the BPD and re-derive version, TAN methods and PIN/TAN rules.
    pub(crate) fn set_bpd(&mut self, segments: Vec<RawSegment>) {
        self.bpd_version = segments
            .iter()
            .find(|s| s.segment_type() == "HIBPA")
            .map(parse_hibpa_version)
            .unwrap_or(self.bpd_version);
        self.tan_methods = segments
            .iter()
            .filter(|s| s.segment_type() == "HITANS")
            .flat_map(parse_hitans)
            .collect();
        self.operation_tan_required = segments
            .iter()
            .filter(|s| s.segment_type() == "HIPINS")
            .flat_map(parse_hipins)
            .collect();
        info!(
            "[FinTS] BPD v{}: {} segments, {} TAN methods, {} PIN/TAN rules",
            self.bpd_version,
            segments.len(),
            self.tan_methods.len(),
            self.operation_tan_required.len()
        );
        self.bpd_segments = segments;
    }

    /// Replace the UPD and re-derive version and accounts.
    pub(crate) fn set_upd(&mut self, segments: Vec<RawSegment>) {
        self.upd_version = segments
            .iter()
            .find(|s| s.segment_type() == "HIUPA")
            .map(parse_hiupa_version)
            .unwrap_or(self.upd_version);
        self.accounts_from_upd = segments
            .iter()
            .filter(|s| s.segment_type() == "HIUPD")
            .filter_map(parse_hiupd)
            .collect();
        info!(
            "[FinTS] UPD v{}: {} accounts",
            self.upd_version,
            self.accounts_from_upd.len()
        );
        self.upd_segments = segments;
    }

    /// Forget the cached UPD so the next HKVVB requests it again (version 0).
    pub fn invalidate_upd(&mut self) {
        self.upd_version = 0;
        self.upd_segments.clear();
        self.accounts_from_upd.clear();
    }

    /// Does the given operation require TAN (per HIPINS)? Default: true (safe).
    pub fn needs_tan(&self, segment_type: &SegmentType) -> bool {
        self.operation_tan_required
            .get(segment_type)
            .copied()
            .unwrap_or(true)
    }

    /// HKTAN version to send: the highest HITANS version (that we can build)
    /// announcing the selected security function; otherwise the highest HITANS
    /// version overall; otherwise 7.
    pub fn hktan_version(&self) -> u16 {
        use crate::segments::builder::HKTAN_VERSIONS;
        let buildable = |m: &&TanMethod| HKTAN_VERSIONS.contains(&m.hktan_version);
        self.tan_methods
            .iter()
            .filter(buildable)
            .filter(|m| m.security_function == self.selected_security_function)
            .map(|m| m.hktan_version)
            .max()
            .or_else(|| {
                self.tan_methods
                    .iter()
                    .filter(buildable)
                    .map(|m| m.hktan_version)
                    .max()
            })
            .unwrap_or(7)
    }

    /// Highest supported version for a segment type in BPD.
    pub fn supported_version(&self, param_segment_type: &str, max_version: u16) -> u16 {
        let v = find_highest_segment_version(&self.bpd_segments, param_segment_type, max_version);
        let result = if v == 0 { max_version } else { v };
        info!(
            "[FinTS] BPD lookup: {} → found v{} (BPD has v{}, max={})",
            param_segment_type, result, v, max_version
        );
        result
    }

    /// Pick the segment version to send: the highest version the bank offers
    /// in its BPD (`param_segment_type`, e.g. "HISALS") that we implement.
    ///
    /// - No BPD known at all → `fallback` (lets callers work before the first sync).
    /// - BPD known but the bank offers no version we implement →
    ///   `SegmentNotSupported` instead of sending something the bank will reject.
    pub fn negotiate_version(
        &self,
        param_segment_type: &str,
        implemented: &[u16],
        fallback: u16,
    ) -> Result<u16> {
        if self.bpd_segments.is_empty() {
            return Ok(fallback);
        }
        let offered: Vec<u16> = self
            .bpd_segments
            .iter()
            .filter(|s| s.segment_type() == param_segment_type)
            .map(|s| s.segment_version())
            .collect();
        let chosen = offered
            .iter()
            .copied()
            .filter(|v| implemented.contains(v))
            .max();
        debug!(
            "[FinTS] Version negotiation {}: bank offers {:?}, we implement {:?} → {:?}",
            param_segment_type, offered, implemented, chosen
        );
        chosen.ok_or_else(|| {
            FinTSError::SegmentNotSupported(if offered.is_empty() {
                format!("bank does not offer {}", param_segment_type)
            } else {
                format!(
                    "bank offers {} v{:?}, client implements v{:?}",
                    param_segment_type, offered, implemented
                )
            })
        })
    }

    /// Select the best security function from 3920 allowed list.
    pub fn select_security_function(&mut self) {
        let allowed = &self.allowed_security_functions;
        if allowed.is_empty() {
            // No 3920 list (yet): honor a cached preference the BPD knows about.
            if let Some(pref) = &self.preferred_security_function {
                if self
                    .tan_methods
                    .iter()
                    .any(|m| &m.security_function == pref)
                {
                    self.selected_security_function = pref.clone();
                }
            }
            return;
        }

        if let Some(ref pref) = self.preferred_security_function {
            if allowed.contains(pref) {
                self.selected_security_function = pref.clone();
                return;
            }
        }

        let pin_only = SecurityFunction::pin_only();
        let methods = &self.tan_methods;
        let chosen = allowed
            .iter()
            .filter(|sf| *sf != &pin_only)
            .max_by_key(|sf| {
                methods
                    .iter()
                    .find(|m| &m.security_function == *sf)
                    .map(|m| if m.is_decoupled { 2i32 } else { 1 })
                    .unwrap_or(0)
            });

        if let Some(sf) = chosen {
            info!("[FinTS] Selected security function: {}", sf);
            self.selected_security_function = sf.clone();
        }
    }

    pub fn is_decoupled(&self) -> bool {
        self.tan_methods
            .iter()
            .find(|m| m.security_function == self.selected_security_function)
            .map(|m| m.is_decoupled)
            .unwrap_or(false)
    }

    pub fn needs_tan_medium(&self) -> bool {
        self.tan_methods
            .iter()
            .find(|m| m.security_function == self.selected_security_function)
            .map(|m| m.needs_tan_medium)
            .unwrap_or(false)
    }

    /// The selected TAN method, if the BPD announces it.
    pub fn selected_tan_method(&self) -> Option<&TanMethod> {
        self.tan_methods
            .iter()
            .filter(|m| m.security_function == self.selected_security_function)
            .max_by_key(|m| m.hktan_version)
    }

    /// Decoupled polling parameters of the selected TAN method (HITANS v7).
    pub fn decoupled_params(&self) -> DecoupledParams {
        let m = self.selected_tan_method();
        let secs = |v: i32| {
            u64::try_from(v)
                .ok()
                .filter(|v| *v > 0)
                .map(std::time::Duration::from_secs)
        };
        DecoupledParams {
            wait_before_first_poll: m.and_then(|m| secs(m.wait_before_first_poll)),
            wait_before_next_poll: m.and_then(|m| secs(m.wait_before_next_poll)),
            // 0 = unlimited per spec; negative = not provided.
            max_polls: m
                .and_then(|m| u32::try_from(m.decoupled_max_polls).ok())
                .filter(|n| *n > 0),
            auto_polling_allowed: m.and_then(|m| m.decoupled_auto_polling),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Decoupled TAN polling
// ═══════════════════════════════════════════════════════════════════════════════

/// Decoupled polling parameters announced by the bank in HITANS v7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DecoupledParams {
    /// Minimum wait before the first status request.
    pub wait_before_first_poll: Option<std::time::Duration>,
    /// Minimum wait between status requests.
    pub wait_before_next_poll: Option<std::time::Duration>,
    /// Maximum number of status requests. `None` = unlimited or not given.
    pub max_polls: Option<u32>,
    /// Whether the bank allows automated polling (`None` = not given).
    pub auto_polling_allowed: Option<bool>,
}

/// Client-side settings for [`Dialog::await_decoupled`].
#[derive(Debug, Clone)]
pub struct DecoupledOptions {
    /// Give up (and end the dialog) after this long. Banks let a pushTAN
    /// expire after a few minutes; this guarantees we never hang.
    pub timeout: std::time::Duration,
    /// Wait before the first status request when the bank gives no value.
    pub default_first_wait: std::time::Duration,
    /// Wait between status requests when the bank gives no value.
    pub default_next_wait: std::time::Duration,
}

impl Default for DecoupledOptions {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(300),
            default_first_wait: std::time::Duration::from_secs(5),
            default_next_wait: std::time::Duration::from_secs(5),
        }
    }
}

/// Progress of a decoupled confirmation, for showing "confirm in the app".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoupledEvent {
    /// Waiting for the user; `challenge` is the bank's text to display.
    AwaitingConfirmation { challenge: ChallengeText },
    /// Sleeping before status request number `poll` (1-based).
    Waiting {
        poll: u32,
        delay: std::time::Duration,
    },
    /// The bank answered 3956: not confirmed yet.
    StillPending { poll: u32 },
    /// Confirmed; the dialog is open.
    Confirmed { polls: u32 },
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dialog<S> — the typestate dialog
// ═══════════════════════════════════════════════════════════════════════════════

pub struct Dialog<S: std::fmt::Debug> {
    connection: FinTSConnection,
    blz: Blz,
    user_id: UserId,
    pin: Pin,
    system_id: SystemId,
    product_id: ProductId,
    dialog_id: DialogId,
    message_number: u16,
    pub params: BankParams,
    _state: PhantomData<S>,
}

impl<S: std::fmt::Debug> std::fmt::Debug for Dialog<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialog")
            .field("blz", &self.blz)
            .field("user_id", &self.user_id)
            .field("system_id", &self.system_id)
            .field("dialog_id", &self.dialog_id)
            .field("message_number", &self.message_number)
            .field("state", &std::any::type_name::<S>())
            .finish()
    }
}

// Note: Pin intentionally Debug-redacted (shows "Pin(****)")

// ── Shared internals (all states) ───────────────────────────────────────────

impl<S: std::fmt::Debug> Dialog<S> {
    pub fn system_id(&self) -> &SystemId {
        &self.system_id
    }
    pub fn bank_params(&self) -> &BankParams {
        &self.params
    }
    pub fn bank_params_mut(&mut self) -> &mut BankParams {
        &mut self.params
    }

    /// Build the standard HKIDN segment for this dialog.
    fn identify_segment(&self) -> Segment {
        Segment::Identify {
            blz: self.blz.clone(),
            user_id: self.user_id.clone(),
            system_id: self.system_id.clone(),
        }
    }

    /// Build the standard HKVVB segment for this dialog.
    fn process_prep_segment(&self) -> Segment {
        Segment::ProcessPrep {
            bpd_version: self.params.bpd_version,
            upd_version: self.params.upd_version,
            product_id: self.product_id.clone(),
        }
    }

    /// Send typed segments with PIN but no TAN.
    async fn send_segments(&mut self, segments: &[Segment]) -> Result<Response> {
        let msg_bytes = message::build_message_from_typed(
            &self.dialog_id,
            self.message_number,
            &self.blz,
            &self.user_id,
            &self.system_id,
            &self.pin,
            &self.params.selected_security_function,
            segments,
            &self.params,
        )?;

        let msg_str = String::from_utf8_lossy(&msg_bytes);
        let redacted = msg_str.replace(self.pin.as_str(), "***PIN***");
        // Truncate on a char boundary: slicing the String by byte index panics on umlauts.
        let preview: String = redacted.chars().take(500).collect();
        info!("[FinTS] Outgoing ({} bytes): {}", msg_bytes.len(), preview);

        let response_bytes = self.exchange(&msg_bytes).await?;
        let response = parse_response(&response_bytes, self.message_number - 1)?;
        response.log_informational_codes();
        Ok(response)
    }

    /// Send typed segments with an explicit TAN value in HNSHA.
    async fn send_segments_with_tan(
        &mut self,
        segments: &[Segment],
        tan: &str,
    ) -> Result<Response> {
        let msg_bytes = message::build_message_from_typed_with_tan(
            &self.dialog_id,
            self.message_number,
            &self.blz,
            &self.user_id,
            &self.system_id,
            &self.pin,
            tan,
            &self.params.selected_security_function,
            segments,
            &self.params,
        )?;
        let response_bytes = self.exchange(&msg_bytes).await?;
        let response = parse_response(&response_bytes, self.message_number - 1)?;
        response.log_informational_codes();
        Ok(response)
    }

    async fn send_end(&mut self) -> Result<()> {
        if !self.dialog_id.is_assigned() {
            return Ok(());
        }
        debug!("Ending dialog {}", self.dialog_id);
        let msg_bytes = message::build_end_message(
            &self.dialog_id,
            self.message_number,
            &self.blz,
            &self.user_id,
            &self.system_id,
            &self.pin,
            &self.params.selected_security_function,
            &self.params,
        )?;
        let _ = self.exchange(&msg_bytes).await;
        self.dialog_id = DialogId::unassigned();
        Ok(())
    }

    /// Send through the connection's quirk chain; bumps the message number.
    async fn exchange(&mut self, msg_bytes: &[u8]) -> Result<Vec<u8>> {
        let dialog_id = self.dialog_id.as_str().to_string();
        let ctx = crate::quirks::QuirkContext {
            hbci_version: "300",
            dialog_id: &dialog_id,
            message_number: self.message_number,
        };
        self.message_number += 1;
        self.connection.exchange(msg_bytes, &ctx).await
    }

    fn extract_dialog_id(&mut self, response: &Response) {
        if let Some(hnhbk) = response.find_segment("HNHBK") {
            let new_id = hnhbk.deg(3).get_str(0);
            if !new_id.is_empty() && new_id != "0" {
                self.dialog_id = DialogId::new(new_id);
            }
        }
    }

    fn transition<T: std::fmt::Debug>(self) -> Dialog<T> {
        Dialog {
            connection: self.connection,
            blz: self.blz,
            user_id: self.user_id,
            pin: self.pin,
            system_id: self.system_id,
            product_id: self.product_id,
            dialog_id: self.dialog_id,
            message_number: self.message_number,
            params: self.params,
            _state: PhantomData,
        }
    }
}

// ── Dialog<New> ─────────────────────────────────────────────────────────────

impl Dialog<New> {
    pub fn new(
        url: &str,
        blz: &Blz,
        user_id: &UserId,
        pin: &Pin,
        product_id: &ProductId,
    ) -> Result<Self> {
        Ok(Self {
            connection: FinTSConnection::new(url)?,
            blz: blz.clone(),
            user_id: user_id.clone(),
            pin: pin.clone(),
            system_id: SystemId::unassigned(),
            product_id: product_id.clone(),
            dialog_id: DialogId::unassigned(),
            message_number: 1,
            params: BankParams::new(),
            _state: PhantomData,
        })
    }

    pub fn with_system_id(mut self, system_id: &SystemId) -> Self {
        self.system_id = system_id.clone();
        self
    }

    pub fn with_params(mut self, params: &BankParams) -> Self {
        self.params = params.clone();
        self
    }

    /// Use a custom quirk chain instead of hbci4java's default rewriters
    /// (e.g. `QuirkChain::default().with(MyBankFix)`, or `QuirkChain::none()`).
    pub fn with_quirks(mut self, quirks: crate::quirks::QuirkChain) -> Self {
        self.connection.set_quirks(quirks);
        self
    }

    pub fn with_tan_medium(mut self, medium: &TanMediumName) -> Self {
        self.params.selected_tan_medium = Some(medium.clone());
        self
    }

    /// Synchronization dialog (spec: Initialisierung mit Synchronisierung).
    ///
    /// Sends HKIDN + HKVVB + HKSYN (mode=0 for new system_id).
    /// The bank responds with BPD, UPD, HITANS, HIPINS, and HISYN(system_id).
    /// This dialog is ONLY for synchronization — no business segments allowed.
    pub async fn sync(mut self) -> Result<(Dialog<Synced>, Response)> {
        info!(
            "[FinTS] Sync dialog: BLZ={} user={} system_id={}",
            self.blz, self.user_id, self.system_id
        );

        let segments = [
            self.identify_segment(),
            self.process_prep_segment(),
            Segment::Sync,
        ];

        let response = self.send_segments(&segments).await?;
        self.extract_dialog_id(&response);
        self.params.ingest_response(&response, &mut self.system_id);
        self.params.select_security_function();

        // Check for fatal errors (sync dialog should not require TAN)
        if !response.needs_tan() {
            response.check_errors()?;
        }

        // Log all BPD parameter segments for diagnostics
        let bpd_summary: Vec<String> = self
            .params
            .bpd_segments
            .iter()
            .map(|s| format!("{}:v{}", s.segment_type(), s.segment_version()))
            .collect();
        info!(
            "[FinTS] Sync complete: BPD v{}, {} TAN methods, system_id={}",
            self.params.bpd_version,
            self.params.tan_methods.len(),
            self.system_id
        );
        info!(
            "[FinTS] BPD segments ({}): {}",
            bpd_summary.len(),
            bpd_summary.join(", ")
        );

        Ok((self.transition(), response))
    }

    /// Normal dialog initialization (spec: Dialoginitialisierung).
    ///
    /// Sends HKIDN + HKVVB + HKTAN(process=4, ref=HKIDN).
    /// Response-driven: returns `InitResult::Opened` or `InitResult::TanRequired`
    /// based on the bank's response codes.
    pub async fn init(mut self) -> Result<InitResult> {
        let medium = self.params.selected_tan_medium.clone();
        info!(
            "[FinTS] Init dialog: BLZ={} security_fn={}",
            self.blz, self.params.selected_security_function
        );

        let segments = [
            self.identify_segment(),
            self.process_prep_segment(),
            Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKIDN"),
                tan_medium: medium,
            },
        ];

        let response = self.send_segments(&segments).await?;
        self.extract_dialog_id(&response);
        self.params.ingest_response(&response, &mut self.system_id);

        let allowed = response.allowed_security_functions();
        if !allowed.is_empty() {
            self.params.allowed_security_functions = allowed;
            self.params.select_security_function();
        }

        for c in response.all_codes() {
            info!("[FinTS] Init: {} - {}", c.code(), c.text);
        }

        // Response-driven transition per spec:
        if response.needs_tan() {
            if let Some(challenge) = response.get_tan_challenge() {
                // 0030/3955: TAN required on init → TanPending
                let challenge = TanChallenge {
                    decoupled: challenge.decoupled || self.params.is_decoupled(),
                    ..challenge
                };
                info!(
                    "[FinTS] Init requires TAN: decoupled={}",
                    challenge.decoupled
                );
                return Ok(InitResult::TanRequired(
                    self.transition(),
                    challenge,
                    response,
                ));
            }
        }

        // 0010/0020 or 3076: dialog opened, no TAN needed → Open
        response.check_errors()?;
        info!("[FinTS] Init opened without TAN");
        Ok(InitResult::Opened(self.transition(), response))
    }

    /// Initialize WITHOUT HKTAN — PIN-only. Used when bank doesn't require SCA.
    pub async fn init_no_tan(mut self) -> Result<(Dialog<Open>, Response)> {
        info!("[FinTS] Init (no HKTAN)");
        let segments = [self.identify_segment(), self.process_prep_segment()];

        let response = self.send_segments(&segments).await?;
        self.extract_dialog_id(&response);
        self.params.ingest_response(&response, &mut self.system_id);
        response.check_errors()?;
        Ok((self.transition(), response))
    }
}

// ── Dialog<Synced> ──────────────────────────────────────────────────────────

impl Dialog<Synced> {
    /// End the sync dialog. Returns bank params and system_id for use in normal dialogs.
    pub async fn end(mut self) -> Result<(BankParams, SystemId)> {
        self.send_end().await.ok();
        Ok((self.params, self.system_id))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Account — validated account identifier (IBAN + BIC, both required)
// ═══════════════════════════════════════════════════════════════════════════════

/// A validated bank account identifier (Kontoverbindung International).
///
/// Both IBAN and BIC are required and non-empty. This is enforced at
/// construction time — you cannot create an `Account` with a missing BIC.
/// All typed business operations on `Dialog<Open>` take `&Account`,
/// making it a compile error to pass raw strings that might be empty.
///
/// ```
/// use fints::protocol::Account;
///
/// // This works:
/// let acc = Account::new("DE89370400440532013000", "COBADEFFXXX").unwrap();
///
/// // This fails at construction time:
/// let bad = Account::new("DE89370400440532013000", "");
/// assert!(bad.is_err());
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Account {
    iban: Iban,
    bic: Bic,
    /// National account number (Kontonummer), needed for KTV-based segment versions.
    number: Option<String>,
    /// Sub-account feature (Unterkontomerkmal).
    subaccount: Option<String>,
    /// Bank code of the account.
    blz: Option<Blz>,
}

impl Account {
    /// Create a validated account. Returns `Err` if IBAN or BIC is empty.
    ///
    /// For German IBANs (`DEkk BBBBBBBB CCCCCCCCCC`) the national account
    /// number and BLZ are derived automatically, so older segment versions that
    /// address accounts nationally (HKSAL v5/6, HKKAZ v5/6, HKWPD) work too.
    pub fn new(iban: &str, bic: &str) -> Result<Self> {
        let iban = iban.trim();
        if iban.is_empty() {
            return Err(FinTSError::Dialog("IBAN must not be empty".into()));
        }
        if bic.trim().is_empty() {
            return Err(FinTSError::Dialog(
                "BIC must not be empty. Please set the BIC in the account settings.".into(),
            ));
        }
        let compact: String = iban
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let (number, blz) = match german_iban_parts(&compact) {
            Some((blz, number)) => (Some(number), Some(Blz::new(blz))),
            None => (None, None),
        };
        Ok(Self {
            iban: Iban::new(compact),
            bic: Bic::new(bic.trim()),
            number,
            subaccount: None,
            blz,
        })
    }

    /// Create an account addressed only nationally (account/depot number + BLZ).
    ///
    /// Depots usually appear in the UPD without an IBAN; HKWPD addresses them
    /// this way. Segment versions that need an IBAN (KTI) fail for such accounts.
    pub fn national(number: &str, subaccount: Option<&str>, blz: &Blz, bic: &str) -> Result<Self> {
        if number.trim().is_empty() || blz.as_str().is_empty() {
            return Err(FinTSError::Dialog(
                "Account number and BLZ must not be empty".into(),
            ));
        }
        Ok(Self {
            iban: Iban::new(""),
            bic: Bic::new(bic.trim()),
            number: None,
            subaccount: None,
            blz: None,
        }
        .with_national(number.trim(), subaccount, blz))
    }

    /// Build an account from UPD/SEPA account info, keeping the bank's national
    /// account number when present. Falls back to `bank_bic` if the UPD has no BIC.
    pub fn from_sepa(acc: &SepaAccount, bank_bic: &str) -> Result<Self> {
        let bic = if acc.bic.as_str().is_empty() {
            bank_bic
        } else {
            acc.bic.as_str()
        };
        let base = if acc.iban.as_str().is_empty() {
            return Self::national(&acc.account_number, Some(&acc.sub_account), &acc.blz, bic);
        } else {
            Self::new(acc.iban.as_str(), bic)?
        };
        Ok(
            if !acc.account_number.is_empty() && !acc.blz.as_str().is_empty() {
                base.with_national(&acc.account_number, Some(&acc.sub_account), &acc.blz)
            } else {
                base
            },
        )
    }

    /// Set the national account identification explicitly (e.g. from HIUPD),
    /// overriding what was derived from the IBAN.
    pub fn with_national(mut self, number: &str, subaccount: Option<&str>, blz: &Blz) -> Self {
        self.number = Some(number.to_string());
        self.subaccount = subaccount.filter(|s| !s.is_empty()).map(str::to_string);
        self.blz = Some(blz.clone());
        self
    }

    pub fn iban(&self) -> &str {
        self.iban.as_str()
    }
    pub fn bic(&self) -> &str {
        self.bic.as_str()
    }
    pub fn account_number(&self) -> Option<&str> {
        self.number.as_deref()
    }
    pub fn subaccount(&self) -> Option<&str> {
        self.subaccount.as_deref()
    }
    pub fn blz(&self) -> Option<&str> {
        self.blz.as_ref().map(|b| b.as_str())
    }
}

/// Split a German IBAN into (BLZ, account number without leading zeros).
fn german_iban_parts(iban: &str) -> Option<(String, String)> {
    if iban.len() != 22 || !iban.starts_with("DE") || !iban[2..].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let blz = iban[4..12].to_string();
    let trimmed = iban[12..22].trim_start_matches('0');
    let number = if trimmed.is_empty() { "0" } else { trimmed };
    Some((blz, number.to_string()))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Typed business operation results
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a balance request.
pub enum BalanceResult {
    /// Balance retrieved successfully.
    Success(AccountBalance),
    /// Bank requires TAN for this operation.
    NeedTan(TanChallenge),
    /// No balance data in response (unexpected but not fatal).
    Empty,
}

/// Result of a transaction request (single page).
pub struct TransactionPage {
    /// MT940 booked transaction data.
    pub booked: Mt940Data,
    /// MT940 pending transaction data.
    pub pending: Mt940Data,
    /// If Some, more data is available — call `transactions()` again with this value.
    pub touchdown: Option<TouchdownPoint>,
}

/// Result of a transaction request.
pub enum TransactionResult {
    /// Transaction data retrieved (may need more pages via touchdown).
    Success(TransactionPage),
    /// Bank requires TAN for this operation.
    NeedTan(TanChallenge),
}

/// Result of a single securities holdings request page.
pub struct HoldingsPage {
    /// Parsed securities positions.
    pub holdings: Vec<SecurityHolding>,
    /// If Some, more data is available — call `holdings()` again with this value.
    pub touchdown: Option<TouchdownPoint>,
}

/// Result of a holdings request.
pub enum HoldingsResult {
    /// Holdings data retrieved (may need more pages via touchdown).
    Success(HoldingsPage),
    /// Bank requires TAN for this operation.
    NeedTan(TanChallenge),
    /// No holdings data in response (depot may be empty or segment not supported).
    Empty,
}

// ── Dialog<Open> ─────────────────────────────────────────────────────────────

impl Dialog<Open> {
    /// Request account balance (HKSAL).
    ///
    /// Takes a validated `Account` — IBAN and BIC are guaranteed non-empty.
    /// Automatically selects the correct HKSAL version from BPD and bundles
    /// HKTAN:4 when HIPINS says TAN is required for this operation.
    pub async fn balance(&mut self, account: &Account) -> Result<BalanceResult> {
        let hksal = SegmentType::new("HKSAL");
        let needs_tan = self.params.needs_tan(&hksal);
        let mut segments = vec![Segment::Balance {
            account: account.clone(),
        }];
        if needs_tan {
            info!("[FinTS] balance: HKSAL + HKTAN:4 (HIPINS: TAN required)");
            segments.push(Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKSAL"),
                tan_medium: self.params.selected_tan_medium.clone(),
            });
        } else {
            info!("[FinTS] balance: HKSAL (HIPINS: PIN-only)");
        }

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            if c.is_error() || c.is_warning() {
                info!("[FinTS] HKSAL: {} - {}", c.code(), c.text);
            }
        }

        // TAN required but no exemption
        if response.needs_tan() && !response.has_sca_exemption() {
            if let Some(challenge) = response.get_tan_challenge() {
                return Ok(BalanceResult::NeedTan(challenge));
            }
        }

        // Check errors
        response.check_errors()?;

        // Parse HISAL
        if let Some(hisal) = response.find_segment("HISAL") {
            if let Some(balance) = parse_hisal(hisal) {
                return Ok(BalanceResult::Success(balance));
            }
        }

        Ok(BalanceResult::Empty)
    }

    /// Request account transactions (HKKAZ) — single page.
    ///
    /// Takes a validated `Account`. For pagination, pass the `touchdown` value
    /// from a previous `TransactionPage` — pass `None` for the first request.
    /// HKTAN:4 is only bundled on the first request (not on touchdown pages).
    pub async fn transactions(
        &mut self,
        account: &Account,
        start_date: NaiveDate,
        end_date: NaiveDate,
        touchdown: Option<&TouchdownPoint>,
    ) -> Result<TransactionResult> {
        let is_first = touchdown.is_none();
        let hkkaz = SegmentType::new("HKKAZ");
        let needs_tan = self.params.needs_tan(&hkkaz);

        let mut segments = vec![Segment::Transactions {
            account: account.clone(),
            start_date,
            end_date,
            touchdown: touchdown.cloned(),
        }];

        if is_first && needs_tan {
            info!("[FinTS] transactions: HKKAZ + HKTAN:4 (HIPINS: TAN required)");
            segments.push(Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKKAZ"),
                tan_medium: self.params.selected_tan_medium.clone(),
            });
        } else if is_first {
            info!("[FinTS] transactions: HKKAZ (HIPINS: PIN-only)");
        }

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            if c.is_error() || c.is_warning() {
                info!("[FinTS] HKKAZ: {} - {}", c.code(), c.text);
            }
        }

        // TAN required but no exemption
        if response.needs_tan() && !response.has_sca_exemption() {
            if let Some(challenge) = response.get_tan_challenge() {
                return Ok(TransactionResult::NeedTan(challenge));
            }
        }

        // Check errors
        response.check_errors()?;

        // Extract MT940 data
        let mt940 = extract_mt940_data(&response.segments);
        let td = response.touchdown();

        Ok(TransactionResult::Success(TransactionPage {
            booked: Mt940Data(mt940.booked),
            pending: Mt940Data(mt940.pending),
            touchdown: td,
        }))
    }

    /// Request securities holdings (HKWPD).
    ///
    /// Takes a validated `Account` — IBAN and BIC are guaranteed non-empty.
    /// Automatically selects the correct HKWPD version from BPD.
    /// Pass `touchdown` from a previous `HoldingsPage` for pagination,
    /// or `None` for the first request.
    pub async fn holdings(
        &mut self,
        account: &Account,
        currency: Option<&Currency>,
        touchdown: Option<&TouchdownPoint>,
    ) -> Result<HoldingsResult> {
        let is_first = touchdown.is_none();
        let hkwpd = SegmentType::new("HKWPD");
        let needs_tan = self.params.needs_tan(&hkwpd);

        let mut segments = vec![Segment::Holdings {
            account: account.clone(),
            currency: currency.cloned(),
            touchdown: touchdown.cloned(),
        }];

        if is_first && needs_tan {
            info!("[FinTS] holdings: HKWPD + HKTAN:4 (HIPINS: TAN required)");
            segments.push(Segment::TanProcess4 {
                reference_seg: SegmentRef::new("HKWPD"),
                tan_medium: self.params.selected_tan_medium.clone(),
            });
        } else if is_first {
            info!("[FinTS] holdings: HKWPD (HIPINS: PIN-only)");
        }

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            if c.is_error() || c.is_warning() {
                info!("[FinTS] HKWPD: {} - {}", c.code(), c.text);
            }
        }

        // TAN required but no exemption
        if response.needs_tan() && !response.has_sca_exemption() {
            if let Some(challenge) = response.get_tan_challenge() {
                return Ok(HoldingsResult::NeedTan(challenge));
            }
        }

        // Check errors
        response.check_errors()?;

        // Parse HIWPD segments
        let holdings = parse_hiwpd(&response.segments);
        let td = response.touchdown();

        if holdings.is_empty() && td.is_none() {
            return Ok(HoldingsResult::Empty);
        }

        Ok(HoldingsResult::Success(HoldingsPage {
            holdings,
            touchdown: td,
        }))
    }

    /// End the dialog.
    pub async fn end(mut self) -> Result<()> {
        self.send_end().await
    }
}

// ── Dialog<TanPending> ──────────────────────────────────────────────────────

impl Dialog<TanPending> {
    /// Wait for a decoupled (app) confirmation by polling HKTAN process S.
    ///
    /// Follows hbci4java's `shouldPerformDecoupledRefresh`: wait the bank's
    /// "before first" delay, then its "before next" delay between requests,
    /// subtracting the time already spent (e.g. in the event callback), and
    /// fail once the bank's maximum number of status requests is reached.
    ///
    /// Ends on: confirmation (→ `Dialog<Open>`), a bank error (e.g. expired
    /// TAN), the bank's max polls (`DecoupledMaxPolls`), `opts.timeout`
    /// (`TanTimeout`), or `cancel` (`Cancelled`). On timeout and cancel the
    /// dialog is ended with HKEND, best effort.
    ///
    /// `on_event` is called for UI updates; to feed a channel, pass
    /// `|e| { let _ = tx.send(e); }`.
    pub async fn await_decoupled(
        self,
        challenge: &TanChallenge,
        cancel: tokio_util::sync::CancellationToken,
        opts: &DecoupledOptions,
        mut on_event: impl FnMut(DecoupledEvent) + Send,
    ) -> Result<(Dialog<Open>, Response)> {
        use std::time::Instant;

        let params = self.params.decoupled_params();
        if params.auto_polling_allowed == Some(false) {
            warn!("[FinTS] Bank discourages automated decoupled polling; polling at the bank's minimum interval anyway");
        }
        let first_wait = params
            .wait_before_first_poll
            .unwrap_or(opts.default_first_wait);
        let next_wait = params
            .wait_before_next_poll
            .unwrap_or(opts.default_next_wait);
        let deadline = Instant::now() + opts.timeout;

        on_event(DecoupledEvent::AwaitingConfirmation {
            challenge: challenge.challenge.clone(),
        });

        let mut dialog = self;
        let mut last_request = Instant::now();
        let mut polls: u32 = 0;
        loop {
            if let Some(max) = params.max_polls {
                if polls >= max {
                    dialog.cancel().await.ok();
                    return Err(FinTSError::DecoupledMaxPolls(max));
                }
            }
            let min_gap = if polls == 0 { first_wait } else { next_wait };
            let delay = min_gap.saturating_sub(last_request.elapsed());
            if Instant::now() + delay > deadline {
                info!(
                    "[FinTS] Decoupled TAN not confirmed within {:?}",
                    opts.timeout
                );
                dialog.cancel().await.ok();
                return Err(FinTSError::TanTimeout);
            }
            on_event(DecoupledEvent::Waiting {
                poll: polls + 1,
                delay,
            });
            tokio::select! {
                _ = cancel.cancelled() => {
                    dialog.cancel().await.ok();
                    return Err(FinTSError::Cancelled);
                }
                _ = tokio::time::sleep(delay) => {}
            }

            polls += 1;
            let result = tokio::select! {
                _ = cancel.cancelled() => {
                    // The request may be in flight; the dialog state is unknown, so don't reuse it.
                    return Err(FinTSError::Cancelled);
                }
                r = dialog.poll(&challenge.task_reference) => r?,
            };
            last_request = Instant::now();
            match result {
                PollResult::Confirmed(open, response) => {
                    on_event(DecoupledEvent::Confirmed { polls });
                    return Ok((open, response));
                }
                PollResult::Pending(d) => {
                    on_event(DecoupledEvent::StillPending { poll: polls });
                    dialog = d;
                }
            }
        }
    }

    /// Poll decoupled TAN status (HKTAN process S).
    /// Per spec: sends HKTAN alone, no business segments.
    /// Returns `Confirmed` (→ Open) or `Pending` (→ still TanPending).
    pub async fn poll(mut self, task_reference: &TaskReference) -> Result<PollResult> {
        let segments = [Segment::TanPollDecoupled {
            task_reference: task_reference.clone(),
            tan_medium: self.params.selected_tan_medium.clone(),
        }];

        let response = self.send_segments(&segments).await?;

        for c in response.all_codes() {
            info!("[FinTS] Poll: {} - {}", c.code(), c.text);
        }

        // 3955/3956: still pending
        if response.is_decoupled_pending() {
            return Ok(PollResult::Pending(self));
        }

        // Check for errors (9xxx)
        response.check_errors()?;

        // 0020: confirmed → Open
        self.params.ingest_response(&response, &mut self.system_id);
        Ok(PollResult::Confirmed(self.transition(), response))
    }

    /// Submit TAN for process 2 (non-decoupled: chipTAN, SMS-TAN).
    /// TAN value is included in HNSHA.
    pub async fn submit_tan(
        mut self,
        task_reference: &TaskReference,
        tan: &str,
    ) -> Result<(Dialog<Open>, Response)> {
        let segments = [Segment::TanProcess2 {
            task_reference: task_reference.clone(),
            tan_medium: self.params.selected_tan_medium.clone(),
        }];

        let response = self.send_segments_with_tan(&segments, tan).await?;
        response.check_errors()?;
        self.params.ingest_response(&response, &mut self.system_id);
        Ok((self.transition(), response))
    }

    /// Cancel: end dialog without completing TAN.
    pub async fn cancel(mut self) -> Result<()> {
        self.send_end().await
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Response parsing
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_response(data: &[u8], expected_msg_num: u16) -> Result<Response> {
    let outer_segments = parser::parse_message(data)?;

    if let Some(hnhbk) = outer_segments.iter().find(|s| s.segment_type() == "HNHBK") {
        let resp_num = hnhbk.deg(4).get_str(0);
        let expected = expected_msg_num.to_string();
        if resp_num != expected && !resp_num.is_empty() {
            warn!(
                "Message number mismatch: expected {}, got {}",
                expected, resp_num
            );
        }
    }

    let mut all_segments = Vec::new();
    for seg in &outer_segments {
        if seg.segment_type() == "HNVSD" {
            if let Some(binary) = seg.deg(1).get(0).as_bytes() {
                match parser::parse_inner_segments(binary) {
                    Ok(inner) => all_segments.extend(inner),
                    Err(e) => warn!("Failed to parse HNVSD: {}", e),
                }
            }
        } else {
            all_segments.push(seg.clone());
        }
    }

    let mut global_codes = Vec::new();
    let mut segment_codes = Vec::new();
    for seg in &all_segments {
        match seg.segment_type() {
            "HIRMG" => global_codes.extend(ResponseCode::parse_from_segment(seg)),
            "HIRMS" => segment_codes.extend(ResponseCode::parse_from_segment(seg)),
            _ => {}
        }
    }

    Ok(Response {
        segments: all_segments,
        global_codes,
        segment_codes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segments::builder::{HKKAZ_VERSIONS, HKSAL_VERSIONS, HKWPD_VERSIONS};

    fn params_with_bpd(raw: &str) -> BankParams {
        let mut p = BankParams::new();
        p.bpd_segments = parser::parse_message(raw.as_bytes()).unwrap();
        p
    }

    #[test]
    fn negotiate_picks_highest_common_version() {
        let p = params_with_bpd("HISALS:1:5:4+1+1'HISALS:2:7:4+1+1+1'HISALS:3:9:4+1+1+1'");
        assert_eq!(p.negotiate_version("HISALS", HKSAL_VERSIONS, 7).unwrap(), 7);
    }

    #[test]
    fn negotiate_falls_back_without_bpd() {
        assert_eq!(
            BankParams::new()
                .negotiate_version("HIKAZS", HKKAZ_VERSIONS, 7)
                .unwrap(),
            7
        );
    }

    #[test]
    fn negotiate_errors_when_bank_lacks_segment_or_versions() {
        let p = params_with_bpd("HISALS:1:7:4+1+1+1'HIWPDS:2:3:4+1+1+1'");
        assert!(matches!(
            p.negotiate_version("HIKAZS", HKKAZ_VERSIONS, 7),
            Err(FinTSError::SegmentNotSupported(_))
        ));
        assert!(matches!(
            p.negotiate_version("HIWPDS", HKWPD_VERSIONS, 6),
            Err(FinTSError::SegmentNotSupported(_))
        ));
    }

    #[test]
    fn hktan_version_prefers_highest_buildable_for_selected_method() {
        let mut p = BankParams::new();
        let m = |sf: &str, v: u16| TanMethod {
            security_function: SecurityFunction::new(sf),
            tan_process: TanProcess::TwoStep,
            name: sf.into(),
            needs_tan_medium: false,
            decoupled_max_polls: -1,
            wait_before_first_poll: 0,
            wait_before_next_poll: 0,
            is_decoupled: false,
            hktan_version: v,
            zka_name: None,
            decoupled_auto_polling: None,
        };
        p.tan_methods = vec![m("902", 6), m("902", 7), m("902", 8), m("912", 6)];
        p.selected_security_function = SecurityFunction::new("902");
        assert_eq!(p.hktan_version(), 7);
        // PIN-only (999) is not in HITANS: use the highest buildable HITANS version.
        p.selected_security_function = SecurityFunction::pin_only();
        assert_eq!(p.hktan_version(), 7);
    }

    /// Run every response-side parser over a message; none may panic.
    fn exercise_parsers(data: &[u8]) {
        if let Ok(resp) = parse_response(data, 1) {
            let _ = resp.check_errors();
            let _ = resp.get_tan_challenge();
            let _ = resp.touchdown();
            let mut params = BankParams::new();
            let mut sid = SystemId::unassigned();
            params.ingest_response(&resp, &mut sid);
            params.select_security_function();
            for seg in &resp.segments {
                let _ = parse_hisal(seg);
                let _ = parse_hitan(seg);
                let _ = parse_hiupd(seg);
                let _ = parse_hitans(seg);
            }
            let _ = parse_hiwpd(&resp.segments);
            let _ = extract_mt940_data(&resp.segments);
        }
    }

    proptest::proptest! {
        #[test]
        fn response_pipeline_never_panics_on_random_bytes(data in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            exercise_parsers(&data);
        }

        #[test]
        fn response_pipeline_never_panics_on_segment_shaped_input(
            parts in proptest::collection::vec(
                proptest::prop_oneof![
                    proptest::strategy::Just("HIRMG:2:2+".to_string()),
                    proptest::strategy::Just("HIRMS:3:2:3+".to_string()),
                    proptest::strategy::Just("HITANS:4:7:4+1+1+1+".to_string()),
                    proptest::strategy::Just("HISAL:5:7:3+".to_string()),
                    proptest::strategy::Just("HITAN:6:7:4+".to_string()),
                    proptest::strategy::Just("HIUPD:7:6:4+".to_string()),
                    proptest::strategy::Just("HIWPD:8:6:3+".to_string()),
                    proptest::strategy::Just("HNVSD:999:1+".to_string()),
                    proptest::strategy::Just("@5@".to_string()),
                    proptest::strategy::Just("@99999999999999999999@".to_string()),
                    "[0-9A-Z:+?' ,]{0,12}",
                ],
                0..24,
            )
        ) {
            exercise_parsers(parts.concat().as_bytes());
        }
    }

    #[test]
    fn code_3072_records_new_user_id_and_drops_upd() {
        let mut p = BankParams::new();
        p.set_upd(
            parser::parse_message(
                b"HIUPA:5:4:4+old+7+0'HIUPD:6:6:4+1::280:1+DE111234567800000001+old++EUR+X'",
            )
            .unwrap(),
        );
        assert_eq!(p.upd_version, 7);

        let resp = parse_response(
            b"HIRMG:2:2+0010::ok'HIRMS:3:2:3+3072::Zugangsdaten geaendert:new-user:new-customer'",
            1,
        )
        .unwrap();
        let mut sid = SystemId::new("S");
        p.ingest_response(&resp, &mut sid);
        assert_eq!(p.changed_user_id, Some(UserId::new("new-user")));
        assert_eq!(p.upd_version, 0, "UPD must be re-requested");
        assert!(p.accounts_from_upd.is_empty());
        assert!(resp.check_errors().is_ok(), "3072 is a warning");
    }

    #[test]
    fn new_bpd_replaces_cached_bpd_instead_of_appending() {
        let mut p = params_with_bpd("");
        let bpd = "HIBPA:1:3:4+10+280:1+Bank+1+1+300'HITANS:2:6:4+1+1+1+J:N:0:910:2:HHD1.3.0:HHD:1.3.0:chipTAN:6:1:TAN:3:J:2:N:0:0:N:N:00:0:N:1'";
        let resp = parse_response(bpd.as_bytes(), 1).unwrap();
        let mut sid = SystemId::unassigned();
        p.ingest_response(&resp, &mut sid);
        p.ingest_response(&resp, &mut sid);
        assert_eq!(p.bpd_version, 10);
        assert_eq!(
            p.tan_methods.len(),
            1,
            "resent BPD must not duplicate TAN methods"
        );
    }

    #[test]
    fn unknown_9xxx_is_a_hard_error_with_code_and_text() {
        let resp = parse_response(b"HIRMG:2:2+9999::Interner Fehler beim Institut'", 1).unwrap();
        let err = resp.check_errors().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Bank error 9999: Interner Fehler beim Institut"
        );
    }

    #[test]
    fn account_derives_national_parts_from_german_iban() {
        let a = Account::new("DE89 3704 0044 0532 0130 00", "COBADEFFXXX").unwrap();
        assert_eq!(a.iban(), "DE89370400440532013000");
        assert_eq!(a.blz(), Some("37040044"));
        assert_eq!(a.account_number(), Some("532013000"));

        let foreign = Account::new("AT611904300234573201", "BKAUATWW").unwrap();
        assert_eq!(foreign.account_number(), None);

        let explicit = foreign.with_national("234573201", Some("01"), &Blz::new("19043"));
        assert_eq!(explicit.subaccount(), Some("01"));
    }
}
