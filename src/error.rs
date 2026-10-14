use thiserror::Error;

/// Errors that can occur during FinTS operations.
#[derive(Error, Debug)]
pub enum FinTSError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Serialization error: {0}")]
    Serialize(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("HTTP error (status {status}): {message}")]
    Http { status: u16, message: String },

    #[error("Dialog error: {0}")]
    Dialog(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("TAN required but no TAN handler provided")]
    TanRequired,

    #[error("TAN rejected by bank: {0}")]
    TanRejected(String),

    #[error("TAN timeout: user did not confirm within the allowed time")]
    TanTimeout,

    /// Any 9xxx code the bank returned, including ones we don't know:
    /// carries the code and the bank's own text.
    #[error("Bank error {}: {message}", kind.code())]
    BankError {
        kind: crate::types::ResponseCodeKind,
        message: String,
    },

    #[error("Segment not supported by bank: {0}")]
    SegmentNotSupported(String),

    #[error("Invalid response from bank: {0}")]
    InvalidResponse(String),

    #[error("MT940 parse error: {0}")]
    Mt940(String),

    #[error("PIN wrong")]
    PinWrong,

    #[error("Account locked")]
    AccountLocked,

    /// The bank rejected the system ID (9391); a fresh synchronization is needed.
    #[error("System ID rejected by bank: {0}")]
    SystemIdInvalid(String),

    /// The bank reported more decoupled status requests than it allows.
    #[error("Decoupled TAN: bank's maximum of {0} status requests reached")]
    DecoupledMaxPolls(u32),

    /// The caller cancelled a pending operation (e.g. decoupled TAN polling).
    #[error("Cancelled")]
    Cancelled,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Request error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, FinTSError>;
