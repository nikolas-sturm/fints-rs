//! FinTS data types and Data Element Group definitions.
//!
//! Provides typed representations of common FinTS structures
//! that appear across multiple segments.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::parser::{DataElement, RawSegment, DEG};

// ═══════════════════════════════════════════════════════════════════════════════
// Newtypes — prevent parameter swaps at compile time
// ═══════════════════════════════════════════════════════════════════════════════

macro_rules! newtype_string {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str { &self.0 }
        }
    };
}

newtype_string!(/// Bank code (Bankleitzahl), e.g. "12030000".
    Blz);
newtype_string!(/// FinTS user ID / login name.
    UserId);
newtype_string!(/// System ID assigned by the bank via HKSYN.
    SystemId);
newtype_string!(/// FinTS product registration ID.
    ProductId);
newtype_string!(/// Dialog ID assigned by the bank in HNHBK.
    DialogId);
newtype_string!(/// Security function code, e.g. "940" for pushTAN, "999" for PIN-only.
    SecurityFunction);
newtype_string!(/// Task reference from HITAN, used in HKTAN process 2/S.
    TaskReference);
newtype_string!(/// Segment type identifier, e.g. "HKSAL", "HKKAZ".
    SegmentType);
newtype_string!(/// TAN medium name (e.g. device name for pushTAN).
    TanMediumName);
newtype_string!(/// Touchdown/pagination point returned by the bank (code 3040).
    TouchdownPoint);
newtype_string!(/// Segment type reference for HKTAN process 4 (e.g. "HKIDN", "HKSAL").
    SegmentRef);
newtype_string!(/// Currency code (ISO 4217), e.g. "EUR".
    Currency);
newtype_string!(/// IBAN (International Bank Account Number).
    Iban);
newtype_string!(/// BIC (Bank Identifier Code).
    Bic);
newtype_string!(/// Human-readable bank name.
    BankName);
newtype_string!(/// FinTS server URL.
    FinTSUrl);
newtype_string!(/// TAN challenge text to display to the user.
    ChallengeText);

/// HHD-UC binary data for optical/QR TAN methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HhdUcData(pub Vec<u8>);

/// MT940/SWIFT binary data (WINDOWS-1252 encoded).
#[derive(Debug, Clone)]
pub struct Mt940Data(pub Vec<u8>);

impl Mt940Data {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn extend(&mut self, data: Vec<u8>) {
        if !self.0.is_empty() && !self.0.ends_with(b"\r\n") {
            self.0.extend_from_slice(b"\r\n");
        }
        self.0.extend(data);
    }
}

/// PIN — redacts on Display to prevent logging.
#[derive(Clone)]
pub struct Pin(String);

impl Pin {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin(****)")
    }
}

impl fmt::Display for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("****")
    }
}

// ── Constants ───────────────────────────────────────────────────────────────

impl SystemId {
    /// The uninitialized system ID — means "not yet assigned by bank".
    pub fn unassigned() -> Self {
        Self("0".into())
    }
    pub fn is_assigned(&self) -> bool {
        !self.0.is_empty() && self.0 != "0"
    }
}

impl DialogId {
    pub fn unassigned() -> Self {
        Self("0".into())
    }
    pub fn is_assigned(&self) -> bool {
        !self.0.is_empty() && self.0 != "0"
    }
}

impl SecurityFunction {
    /// PIN-only (no two-step TAN).
    pub fn pin_only() -> Self {
        Self("999".into())
    }
}

/// TAN process as defined by FinTS spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TanProcess {
    /// One-step: TAN entered with the business message.
    OneStep,
    /// Two-step: business message first, then TAN in a second message.
    TwoStep,
}

impl TanProcess {
    pub fn from_str_val(s: &str) -> Self {
        match s {
            "1" => TanProcess::OneStep,
            _ => TanProcess::TwoStep,
        }
    }
}

/// Classified response code with typed parameters.
/// The parameters are embedded in the variant — no raw `Vec<String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCodeKind {
    /// 0010 — Message received.
    MessageReceived,
    /// 0020 — Order executed.
    OrderExecuted,
    /// 0030 — Order received, TAN required.
    TanRequired,
    /// 0100 — Dialog ended.
    DialogEnded,
    /// 0900 — TAN valid.
    TanValid,
    /// 3040 — More data available. Contains the touchdown point.
    Touchdown(TouchdownPoint),
    /// 3060 — Partial warnings.
    PartialWarnings,
    /// 3076 — No strong authentication required (SCA exemption).
    ScaExemption,
    /// 3920 — Allowed security functions. Contains the list.
    AllowedSecurityFunctions(Vec<SecurityFunction>),
    /// 3955 — Decoupled TAN initiated (confirm in app).
    DecoupledInitiated,
    /// 3956 — Decoupled TAN not yet confirmed.
    DecoupledPending,
    /// 9010 — General error.
    GeneralError,
    /// 9040 — Authentication missing.
    AuthenticationMissing,
    /// 9050 — Partial errors.
    PartialErrors,
    /// 9110 — Unexpected order in sync dialog.
    UnexpectedInSync,
    /// 9160 — Data element missing.
    DataElementMissing,
    /// 9340 — PIN wrong.
    PinWrong,
    /// 9800 — Dialog aborted.
    DialogAborted,
    /// 9942 — Account/user locked.
    AccountLocked,
    /// Other success code (0xxx).
    OtherSuccess(String),
    /// Other warning code (3xxx).
    OtherWarning(String),
    /// Other error code (9xxx).
    OtherError(String),
    /// Unrecognized code.
    Unknown(String),
}

impl ResponseCodeKind {
    fn default_unknown() -> Self {
        Self::Unknown(String::new())
    }

    pub fn from_code(code: &str, parameters: &[String]) -> Self {
        match code {
            "0010" => Self::MessageReceived,
            "0020" => Self::OrderExecuted,
            "0030" => Self::TanRequired,
            "0100" => Self::DialogEnded,
            "0900" => Self::TanValid,
            "3040" => Self::Touchdown(TouchdownPoint::new(
                parameters.first().map(|s| s.as_str()).unwrap_or(""),
            )),
            "3060" => Self::PartialWarnings,
            "3076" => Self::ScaExemption,
            "3920" => Self::AllowedSecurityFunctions(
                parameters
                    .iter()
                    .map(|s| SecurityFunction::new(s))
                    .collect(),
            ),
            "3955" => Self::DecoupledInitiated,
            "3956" => Self::DecoupledPending,
            "9010" => Self::GeneralError,
            "9040" => Self::AuthenticationMissing,
            "9050" => Self::PartialErrors,
            "9110" => Self::UnexpectedInSync,
            "9160" => Self::DataElementMissing,
            "9340" => Self::PinWrong,
            "9800" => Self::DialogAborted,
            "9942" => Self::AccountLocked,
            _ if code.starts_with('0') => Self::OtherSuccess(code.to_string()),
            _ if code.starts_with('3') => Self::OtherWarning(code.to_string()),
            _ if code.starts_with('9') => Self::OtherError(code.to_string()),
            _ => Self::Unknown(code.to_string()),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::MessageReceived
                | Self::OrderExecuted
                | Self::TanRequired
                | Self::DialogEnded
                | Self::TanValid
                | Self::OtherSuccess(_)
        )
    }

    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            Self::Touchdown(_)
                | Self::PartialWarnings
                | Self::ScaExemption
                | Self::AllowedSecurityFunctions(_)
                | Self::DecoupledInitiated
                | Self::DecoupledPending
                | Self::OtherWarning(_)
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Self::GeneralError
                | Self::AuthenticationMissing
                | Self::PartialErrors
                | Self::UnexpectedInSync
                | Self::DataElementMissing
                | Self::PinWrong
                | Self::DialogAborted
                | Self::AccountLocked
                | Self::OtherError(_)
        )
    }
}

// ---- Helper functions for reading DEs from segments ----

/// Read a string DE from a segment at (deg_idx, de_idx).
pub(crate) fn read_str(seg: &RawSegment, deg: usize, de: usize) -> String {
    seg.deg(deg).get(de).as_text()
}

/// Read an optional string — returns None if empty.
pub(crate) fn read_opt_str(seg: &RawSegment, deg: usize, de: usize) -> Option<String> {
    let s = seg.deg(deg).get(de).as_text();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Read an integer from a DE.
pub(crate) fn read_int(seg: &RawSegment, deg: usize, de: usize) -> i64 {
    seg.deg(deg)
        .get(de)
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Read a u16 from a DE.
pub(crate) fn read_u16(seg: &RawSegment, deg: usize, de: usize) -> u16 {
    seg.deg(deg)
        .get(de)
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Read a FinTS date (YYYYMMDD format) from a DE.
pub(crate) fn read_date(seg: &RawSegment, deg: usize, de: usize) -> Option<NaiveDate> {
    let s = seg.deg(deg).get(de).as_text();
    if s.len() == 8 {
        NaiveDate::parse_from_str(&s, "%Y%m%d").ok()
    } else {
        None
    }
}

/// Read a FinTS amount (comma as decimal separator) from a DE.
pub(crate) fn read_amount(seg: &RawSegment, deg: usize, de: usize) -> Option<Decimal> {
    let s = seg.deg(deg).get(de).as_text();
    if s.is_empty() {
        return None;
    }
    let normalized = s.replace(',', ".");
    Decimal::from_str(&normalized).ok()
}

/// Read binary data from a DE.
pub(crate) fn read_binary(seg: &RawSegment, deg: usize, de: usize) -> Option<Vec<u8>> {
    seg.deg(deg).get(de).as_bytes().map(|b| b.to_vec())
}

/// Read a boolean (J/N) from a DE.
pub(crate) fn read_bool(seg: &RawSegment, deg: usize, de: usize) -> bool {
    seg.deg(deg).get(de).as_text() == "J"
}

// ---- DE construction helpers ----

/// Create a text DE.
pub fn de_text(s: &str) -> DataElement {
    if s.is_empty() {
        DataElement::Empty
    } else {
        DataElement::Text(s.to_string())
    }
}

/// Create a numeric DE from a number.
pub fn de_num<T: ToString>(n: T) -> DataElement {
    DataElement::Text(n.to_string())
}

/// Create a FinTS date DE (YYYYMMDD format).
pub fn de_date(date: NaiveDate) -> DataElement {
    DataElement::Text(date.format("%Y%m%d").to_string())
}

/// Create an empty DE.
pub fn de_empty() -> DataElement {
    DataElement::Empty
}

/// Create a binary DE.
pub fn de_binary(data: Vec<u8>) -> DataElement {
    DataElement::Binary(data)
}

/// Create a boolean DE (J/N).
pub fn de_bool(val: bool) -> DataElement {
    DataElement::Text(if val { "J" } else { "N" }.to_string())
}

/// Create a DEG from data elements.
pub fn deg(elements: Vec<DataElement>) -> DEG {
    DEG(elements)
}

/// Create a single-element DEG.
pub fn deg1(de: DataElement) -> DEG {
    DEG(vec![de])
}

// ---- High-level response types ----

/// A single response code from HIRMG/HIRMS.
/// All data is typed — the `kind` field carries any parameters.
#[derive(Debug, Clone)]
pub struct ResponseCode {
    /// Classified response code with typed parameters.
    pub kind: ResponseCodeKind,
    /// Human-readable description from the bank.
    pub text: String,
}

impl ResponseCode {
    /// Create a ResponseCode with auto-classified kind.
    pub fn new(code: &str, text: &str) -> Self {
        Self {
            kind: ResponseCodeKind::from_code(code, &[]),
            text: text.to_string(),
        }
    }

    /// Create a ResponseCode with parameters.
    pub fn with_params(code: &str, text: &str, params: Vec<String>) -> Self {
        Self {
            kind: ResponseCodeKind::from_code(code, &params),
            text: text.to_string(),
        }
    }

    /// Parse response codes from a segment's DEGs (skip header at index 0).
    pub fn parse_from_segment(seg: &RawSegment) -> Vec<ResponseCode> {
        let mut codes = Vec::new();
        for i in 1..seg.deg_count() {
            let d = seg.deg(i);
            if d.len() >= 3 {
                let code = d.get_str(0);
                if code.is_empty() {
                    continue;
                }
                let text = d.get_str(2);
                let mut params = Vec::new();
                for j in 3..d.len() {
                    let p = d.get(j).as_text();
                    if !p.is_empty() {
                        params.push(p);
                    }
                }
                codes.push(ResponseCode {
                    kind: ResponseCodeKind::from_code(&code, &params),
                    text,
                });
            }
        }
        codes
    }

    /// Raw code string for logging/display.
    pub fn code(&self) -> &str {
        match &self.kind {
            ResponseCodeKind::MessageReceived => "0010",
            ResponseCodeKind::OrderExecuted => "0020",
            ResponseCodeKind::TanRequired => "0030",
            ResponseCodeKind::DialogEnded => "0100",
            ResponseCodeKind::TanValid => "0900",
            ResponseCodeKind::Touchdown(_) => "3040",
            ResponseCodeKind::PartialWarnings => "3060",
            ResponseCodeKind::ScaExemption => "3076",
            ResponseCodeKind::AllowedSecurityFunctions(_) => "3920",
            ResponseCodeKind::DecoupledInitiated => "3955",
            ResponseCodeKind::DecoupledPending => "3956",
            ResponseCodeKind::GeneralError => "9010",
            ResponseCodeKind::AuthenticationMissing => "9040",
            ResponseCodeKind::PartialErrors => "9050",
            ResponseCodeKind::UnexpectedInSync => "9110",
            ResponseCodeKind::DataElementMissing => "9160",
            ResponseCodeKind::PinWrong => "9340",
            ResponseCodeKind::DialogAborted => "9800",
            ResponseCodeKind::AccountLocked => "9942",
            ResponseCodeKind::OtherSuccess(c)
            | ResponseCodeKind::OtherWarning(c)
            | ResponseCodeKind::OtherError(c)
            | ResponseCodeKind::Unknown(c) => c,
        }
    }

    pub fn is_success(&self) -> bool {
        self.kind.is_success()
    }
    pub fn is_warning(&self) -> bool {
        self.kind.is_warning()
    }
    pub fn is_error(&self) -> bool {
        self.kind.is_error()
    }
    pub fn is_tan_required(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::TanRequired)
    }
    pub fn is_touchdown(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::Touchdown(_))
    }
    pub fn is_allowed_tan_methods(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::AllowedSecurityFunctions(_))
    }
    pub fn is_decoupled(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::DecoupledInitiated)
    }
    pub fn is_decoupled_pending(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::DecoupledPending)
    }
    pub fn is_pin_wrong(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::PinWrong)
    }
    pub fn is_general_error(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::GeneralError)
    }
    pub fn is_locked(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::AccountLocked)
    }
}

/// A TAN method as reported by the bank in HITANS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TanMethod {
    /// Security function code (e.g. "912" for pushTAN)
    pub security_function: SecurityFunction,
    /// TAN process type.
    pub tan_process: TanProcess,
    /// Human-readable name (e.g. "pushTAN-2.0")
    pub name: String,
    /// Whether TAN medium name must be sent
    pub needs_tan_medium: bool,
    /// Maximum number of decoupled status polls (HKTAN process S).
    /// `0` = unlimited (per spec), `-1` = not provided by the bank.
    pub decoupled_max_polls: i32,
    /// Seconds to wait before first decoupled poll (0 = not provided)
    pub wait_before_first_poll: i32,
    /// Seconds to wait between decoupled polls (0 = not provided)
    pub wait_before_next_poll: i32,
    /// Whether this is a decoupled method
    pub is_decoupled: bool,
    /// HKTAN version (= version of the HITANS segment that announced this method)
    pub hktan_version: u16,
    /// DK TAN method identifier (formerly "ZKA TAN-Verfahren"), e.g. "Decoupled" or "HHD".
    #[serde(default)]
    pub zka_name: Option<String>,
    /// Whether the bank allows automated decoupled status polling (HITANS v7).
    /// `Some(false)` means the user should confirm manually in the client before we poll.
    #[serde(default)]
    pub decoupled_auto_polling: Option<bool>,
}

/// SEPA account info as returned by HISPA / HIUPD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SepaAccount {
    pub iban: Iban,
    pub bic: Bic,
    pub account_number: String,
    pub sub_account: String,
    pub blz: Blz,
    pub owner: Option<String>,
    pub product_name: Option<String>,
    pub currency: Option<Currency>,
}

/// Account balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBalance {
    pub amount: Decimal,
    pub date: NaiveDate,
    pub currency: Currency,
    pub credit_line: Option<Decimal>,
    pub available: Option<Decimal>,
    /// Pending (vorgemerkter) balance amount, if provided by the bank.
    pub pending_amount: Option<Decimal>,
    /// Date of the pending balance, if provided.
    pub pending_date: Option<NaiveDate>,
}

/// Whether a transaction is booked or pending (vorgemerkt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    Booked,
    Pending,
}

// ── Securities / Depot types ────────────────────────────────────────────────

newtype_string!(/// ISIN (International Securities Identification Number), e.g. "DE0005140008".
    Isin);
newtype_string!(/// WKN (Wertpapierkennnummer), e.g. "514000".
    Wkn);

/// A single securities position in a depot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHolding {
    /// ISIN of the security.
    pub isin: Option<Isin>,
    /// WKN (German securities identification number).
    pub wkn: Option<Wkn>,
    /// Human-readable name of the security.
    pub name: String,
    /// Number of shares/units held (can be fractional for funds).
    pub quantity: Decimal,
    /// Current market price per unit.
    pub price: Option<Decimal>,
    /// Currency of the price.
    pub price_currency: Option<Currency>,
    /// Date of the price quote.
    pub price_date: Option<NaiveDate>,
    /// Total market value (quantity * price).
    pub market_value: Option<Decimal>,
    /// Currency of the market value.
    pub market_value_currency: Option<Currency>,
    /// Original purchase value (Einstandswert), if available.
    pub acquisition_value: Option<Decimal>,
    /// Profit/loss amount, if available.
    pub profit_loss: Option<Decimal>,
    /// Exchange/market where the price was quoted.
    pub exchange: Option<String>,
    /// Depot number this holding belongs to.
    pub depot_id: Option<String>,
    /// Raw parsed data for debugging/extension.
    pub raw: serde_json::Value,
}

/// A parsed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub date: NaiveDate,
    pub valuta_date: Option<NaiveDate>,
    pub amount: Decimal,
    pub currency: Currency,
    pub applicant_name: Option<String>,
    pub applicant_iban: Option<Iban>,
    pub applicant_bic: Option<Bic>,
    pub purpose: Option<String>,
    pub posting_text: Option<String>,
    pub reference: Option<String>,
    pub raw: serde_json::Value,
    /// Whether this transaction is booked or pending.
    pub status: TransactionStatus,
}
