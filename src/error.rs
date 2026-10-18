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

impl FinTSError {
    /// The bank rejected the credentials or locked the access. Never retry
    /// these on your own: a few wrong PINs in a row lock the online banking
    /// login until the bank unlocks it.
    pub fn is_credentials_error(&self) -> bool {
        match self {
            Self::PinWrong | Self::AccountLocked | Self::Auth(_) => true,
            Self::BankError { kind, .. } => matches!(
                kind,
                crate::types::ResponseCodeKind::PinWrong(_)
                    | crate::types::ResponseCodeKind::AccountLocked(_)
            ),
            _ => false,
        }
    }

    /// The bank needs the user: a TAN, or an app confirmation that didn't
    /// arrive in time. Retrying without the user present won't help.
    pub fn needs_user(&self) -> bool {
        matches!(
            self,
            Self::TanRequired
                | Self::TanRejected(_)
                | Self::TanTimeout
                | Self::DecoupledMaxPolls(_)
        )
    }

    /// A temporary failure worth retrying later unchanged: network trouble,
    /// timeouts, server errors, rate limiting.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Io(_) => true,
            Self::Http { status, .. } => *status >= 500 || *status == 408 || *status == 429,
            Self::Reqwest(e) => {
                e.is_timeout() || e.is_connect() || e.status().is_some_and(|s| s.is_server_error())
            }
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, FinTSError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ResponseCodeKind;

    #[test]
    fn classification() {
        assert!(FinTSError::PinWrong.is_credentials_error());
        assert!(FinTSError::AccountLocked.is_credentials_error());
        let locked = FinTSError::BankError {
            kind: ResponseCodeKind::AccountLocked("9931".into()),
            message: "gesperrt".into(),
        };
        assert!(locked.is_credentials_error() && !locked.is_retryable());

        assert!(FinTSError::TanRequired.needs_user());
        assert!(FinTSError::TanTimeout.needs_user());
        assert!(!FinTSError::PinWrong.needs_user());

        assert!(FinTSError::Transport("reset".into()).is_retryable());
        assert!(FinTSError::Http {
            status: 503,
            message: "maintenance".into()
        }
        .is_retryable());
        assert!(!FinTSError::Http {
            status: 404,
            message: "gone".into()
        }
        .is_retryable());
        assert!(!FinTSError::PinWrong.is_retryable());
    }
}
