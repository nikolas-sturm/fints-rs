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

/// What a TAN challenge's HHD-UC data carries, ready for a UI to render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TanMedia {
    /// photoTAN / QR-TAN: an image (usually PNG) to show to the TAN app or reader.
    Image { mime_type: String, data: Vec<u8> },
    /// chipTAN optical (HHD 1.4 flicker code): the challenge data as the bank
    /// sent it; a flicker renderer turns it into the animation.
    Flicker(String),
}

impl HhdUcData {
    /// Decode the challenge data.
    ///
    /// Matrix codes (photoTAN, QR-TAN) are laid out as a 2-byte big-endian
    /// MIME type length, the MIME type, a 2-byte big-endian image length and
    /// the image. Printable ASCII that isn't a matrix code is an HHD flicker
    /// code. Anything else yields `None`.
    pub fn decode(&self) -> Option<TanMedia> {
        let b = self.0.as_slice();
        if let Some(media) = Self::decode_matrix(b) {
            return Some(media);
        }
        let printable = !b.is_empty() && b.iter().all(|c| (0x20..0x7f).contains(c));
        printable.then(|| TanMedia::Flicker(String::from_utf8_lossy(b).trim().to_string()))
    }

    fn decode_matrix(b: &[u8]) -> Option<TanMedia> {
        let be16 = |at: usize| -> Option<usize> {
            Some(usize::from(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?])))
        };
        let mime_len = be16(0)?;
        let mime = b.get(2..2 + mime_len)?;
        let looks_like_mime = (3..=100).contains(&mime_len)
            && mime.contains(&b'/')
            && mime.iter().all(|c| c.is_ascii_graphic());
        if !looks_like_mime {
            return None;
        }
        let data_len = be16(2 + mime_len)?;
        let data = b.get(4 + mime_len..4 + mime_len + data_len)?;
        Some(TanMedia::Image {
            mime_type: String::from_utf8_lossy(mime).into_owned(),
            data: data.to_vec(),
        })
    }
}

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
    /// 3072 — Access data changed: the bank assigned a new user ID / customer ID.
    /// hbci4java hands these to the application; we also drop the cached UPD.
    UserDataChanged {
        user_id: Option<String>,
        customer_id: Option<String>,
    },
    /// 3076 — No strong authentication required (SCA exemption).
    ScaExemption,
    /// 3091 — Verification of Payee not required (VoP exemption). Irrelevant for read-only use.
    VopNotRequired,
    /// 3920 — Allowed security functions. Contains the list.
    AllowedSecurityFunctions(Vec<SecurityFunction>),
    /// 3955 — Decoupled TAN initiated (confirm in app).
    DecoupledInitiated,
    /// 3956 — Decoupled TAN not yet confirmed.
    DecoupledPending,
    /// 3945 — Verification of Payee approval cannot be granted. Irrelevant for read-only use.
    VopApprovalNotPossible,
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
    /// 9340 / 9910 / 9942 — PIN wrong (hbci4java: 9340 "Signatur falsch", 9942 "PIN falsch").
    /// Carries the actual code.
    PinWrong(String),
    /// 9391 — System ID invalid: a new customer system ID must be fetched (re-sync).
    SystemIdInvalid,
    /// 9800 — Dialog aborted.
    DialogAborted,
    /// 9930 / 9931 — PIN or access locked (hbci4java: "PIN ist gesperrt",
    /// "Konto gesperrt wegen falscher PIN"). Carries the actual code.
    AccountLocked(String),
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
            "3072" => Self::UserDataChanged {
                user_id: parameters.first().filter(|s| !s.is_empty()).cloned(),
                // Like hbci4java: customer ID defaults to the user ID.
                customer_id: parameters.get(1).or(parameters.first()).filter(|s| !s.is_empty()).cloned(),
            },
            "3076" => Self::ScaExemption,
            "3091" => Self::VopNotRequired,
            "3945" => Self::VopApprovalNotPossible,
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
            "9340" | "9910" | "9942" => Self::PinWrong(code.to_string()),
            "9391" => Self::SystemIdInvalid,
            "9800" => Self::DialogAborted,
            "9930" | "9931" => Self::AccountLocked(code.to_string()),
            _ if code.starts_with('0') => Self::OtherSuccess(code.to_string()),
            _ if code.starts_with('3') => Self::OtherWarning(code.to_string()),
            _ if code.starts_with('9') => Self::OtherError(code.to_string()),
            _ => Self::Unknown(code.to_string()),
        }
    }

    /// The four-digit FinTS return code.
    pub fn code(&self) -> &str {
        match self {
            Self::MessageReceived => "0010",
            Self::OrderExecuted => "0020",
            Self::TanRequired => "0030",
            Self::DialogEnded => "0100",
            Self::TanValid => "0900",
            Self::Touchdown(_) => "3040",
            Self::PartialWarnings => "3060",
            Self::UserDataChanged { .. } => "3072",
            Self::ScaExemption => "3076",
            Self::VopNotRequired => "3091",
            Self::AllowedSecurityFunctions(_) => "3920",
            Self::VopApprovalNotPossible => "3945",
            Self::DecoupledInitiated => "3955",
            Self::DecoupledPending => "3956",
            Self::GeneralError => "9010",
            Self::AuthenticationMissing => "9040",
            Self::PartialErrors => "9050",
            Self::UnexpectedInSync => "9110",
            Self::DataElementMissing => "9160",
            Self::SystemIdInvalid => "9391",
            Self::DialogAborted => "9800",
            Self::PinWrong(c)
            | Self::AccountLocked(c)
            | Self::OtherSuccess(c)
            | Self::OtherWarning(c)
            | Self::OtherError(c)
            | Self::Unknown(c) => c,
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
                | Self::UserDataChanged { .. }
                | Self::ScaExemption
                | Self::VopNotRequired
                | Self::VopApprovalNotPossible
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
                | Self::PinWrong(_)
                | Self::SystemIdInvalid
                | Self::DialogAborted
                | Self::AccountLocked(_)
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
        self.kind.code()
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
        matches!(self.kind, ResponseCodeKind::PinWrong(_))
    }
    pub fn is_general_error(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::GeneralError)
    }
    pub fn is_locked(&self) -> bool {
        matches!(self.kind, ResponseCodeKind::AccountLocked(_))
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
    /// "Kontoart" from the UPD (HIUPD v6), 1-99. See [`SepaAccount::account_class`].
    #[serde(default)]
    pub account_type: Option<u8>,
}

impl SepaAccount {
    /// What kind of account this is, from the UPD account type ranges the
    /// FinTS specification defines. `None` when the bank doesn't say.
    pub fn account_class(&self) -> Option<AccountClass> {
        AccountClass::from_account_type(self.account_type?)
    }
}

/// Account type ranges ("Kontoart") of the FinTS UPD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountClass {
    /// 1-9: Kontokorrent / Girokonto.
    Checking,
    /// 10-19: Sparkonto.
    Savings,
    /// 20-29: Festgeld / Termineinlage.
    FixedDeposit,
    /// 30-39: Wertpapierdepot.
    Depot,
    /// 40-49: Kredit / Darlehen.
    Loan,
    /// 50-59: Kreditkarte.
    CreditCard,
    /// 60-69: Fonds-Depot bei einer Kapitalanlagegesellschaft.
    FundDepot,
    /// 70-79: Bausparvertrag.
    HomeSavings,
    /// 80-89: Versicherungsvertrag.
    Insurance,
    /// 90-99: Sonstige.
    Other,
}

impl AccountClass {
    pub fn from_account_type(account_type: u8) -> Option<Self> {
        Some(match account_type {
            1..=9 => Self::Checking,
            10..=19 => Self::Savings,
            20..=29 => Self::FixedDeposit,
            30..=39 => Self::Depot,
            40..=49 => Self::Loan,
            50..=59 => Self::CreditCard,
            60..=69 => Self::FundDepot,
            70..=79 => Self::HomeSavings,
            80..=89 => Self::Insurance,
            90..=99 => Self::Other,
            _ => return None,
        })
    }
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
    /// Booking date (Buchungstag): the MT940 entry date, or the value date
    /// when the bank leaves the entry date out.
    pub date: NaiveDate,
    /// Value date (Valuta, Wertstellung).
    pub valuta_date: Option<NaiveDate>,
    /// Signed from the account holder's view: negative = debit.
    pub amount: Decimal,
    pub currency: Currency,
    pub applicant_name: Option<String>,
    pub applicant_iban: Option<Iban>,
    pub applicant_bic: Option<Bic>,
    /// Purpose text: `:86:` subfields ?20-?29 and ?60-?63 joined as sent,
    /// so SEPA keywords (`EREF+`, `MREF+`, `CRED+`, `SVWZ+`) stay intact.
    pub purpose: Option<String>,
    /// Booking text (Buchungstext), e.g. "SEPA-BASISLASTSCHRIFT".
    pub posting_text: Option<String>,
    /// Customer reference from `:61:`, often "NONREF".
    pub reference: Option<String>,
    /// Bank reference from `:61:` (after `//`), if the bank sends one.
    #[serde(default)]
    pub bank_reference: Option<String>,
    /// Geschäftsvorfallcode (GVC): the three-digit business transaction
    /// code from `:86:`, e.g. `166` for an incoming SEPA credit transfer.
    #[serde(default)]
    pub gvc: Option<String>,
    /// Primanota number from `:86:` ?10.
    #[serde(default)]
    pub prima_nota: Option<String>,
    pub raw: serde_json::Value,
    /// Whether this transaction is booked or pending.
    pub status: TransactionStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_phototan_matrix() {
        let png = [0x89, b'P', b'N', b'G', 1, 2, 3];
        let mut raw = vec![0, 9];
        raw.extend_from_slice(b"image/png");
        raw.extend_from_slice(&(png.len() as u16).to_be_bytes());
        raw.extend_from_slice(&png);
        assert_eq!(
            HhdUcData(raw).decode(),
            Some(TanMedia::Image { mime_type: "image/png".into(), data: png.to_vec() })
        );
    }

    #[test]
    fn decodes_flicker_code() {
        let raw = b"0388A01239230520422070812345678904".to_vec();
        assert_eq!(
            HhdUcData(raw).decode(),
            Some(TanMedia::Flicker("0388A01239230520422070812345678904".into()))
        );
    }

    #[test]
    fn rejects_truncated_or_binary_garbage() {
        // Claims a 9-byte MIME type and a 100-byte image, but stops early.
        let mut raw = vec![0, 9];
        raw.extend_from_slice(b"image/png");
        raw.extend_from_slice(&[0, 100, 1, 2]);
        assert_eq!(HhdUcData(raw).decode(), None);
        assert_eq!(HhdUcData(vec![]).decode(), None);
    }

    #[test]
    fn account_classes() {
        assert_eq!(AccountClass::from_account_type(1), Some(AccountClass::Checking));
        assert_eq!(AccountClass::from_account_type(10), Some(AccountClass::Savings));
        assert_eq!(AccountClass::from_account_type(39), Some(AccountClass::Depot));
        assert_eq!(AccountClass::from_account_type(55), Some(AccountClass::CreditCard));
        assert_eq!(AccountClass::from_account_type(0), None);
        assert_eq!(AccountClass::from_account_type(100), None);
    }
}
