//! # fints — Native Rust FinTS 3.0 PinTan Client
//!
//! A pure Rust implementation of the FinTS 3.0 (formerly HBCI) banking protocol
//! for German online banking.
//!
//! ## Architecture
//!
//! 1. **Protocol layer** (`protocol`): Typestate `Dialog<S>` — the dialog's auth
//!    state is in the type system. Business ops on an unauthenticated dialog = compile error.
//!
//! 2. **Workflow layer** (`workflow`): Bank workflows via the `BankOps` trait,
//!    dispatched by BLZ (`bank_ops`/`AnyBank`; DKB, ING and a generic implementation).
//!
//! 3. **Flow layer** (`flow`): High-level `Flow` for connect → TAN confirm → fetch.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use fints::{CancellationToken, DecoupledOptions, Flow, UserId, Pin, ProductId, SessionState};
//!
//! # async fn example(saved: Option<SessionState>) -> fints::Result<()> {
//! // BLZ 50010517 = ING; any other registry BLZ works too.
//! let (mut flow, _info) = Flow::initiate(
//!     "50010517", &UserId::new("user"), &Pin::new("pin"), &ProductId::new("PRODUCT_ID"),
//!     saved.as_ref(), None, None,
//! ).await?;
//! if flow.needs_tan() {
//!     // pushTAN: wait for the confirmation in the banking app
//!     flow.await_decoupled(CancellationToken::new(), &DecoupledOptions::default(), |_| {}).await?;
//! }
//! let result = flow.confirm_and_fetch("DE123...", "INGDDEFFXXX", 365).await?;
//! println!("Balance: {:?}, {} transactions", result.balance, result.transactions.len());
//! let state = flow.session_state(); // persist (encrypted) for the next run
//! # Ok(())
//! # }
//! ```

// ── Infrastructure ──
pub mod banks;
#[rustfmt::skip] // written by generate_banks.py
pub mod banks_generated;
pub mod error;
pub(crate) mod message;
pub(crate) mod parser;
pub(crate) mod segments;
pub(crate) mod serializer;
pub(crate) mod transport;
pub mod types;

// ── Tooling ──
pub mod audit;
pub mod debug;

// ── Architecture ──
pub mod flow;
pub mod protocol;
pub mod quirks;
pub mod session;
pub mod workflow;

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports
// ═══════════════════════════════════════════════════════════════════════════════

// Flow layer
pub use flow::{ChallengeInfo, FetchOptions, Flow, SyncResult};

// Workflow layer
pub use workflow::{bank_ops, bank_ops_with_config, AnyBank, BankOps, Dkb, GenericBank, Ing};
pub use workflow::{
    fetch_default, fetch_holdings_default, fetch_transactions, fetch_transactions_range,
    initiate_default,
};
pub use workflow::{FetchOpts, FetchResult, InitiateNoTanResult, InitiateOutcome, InitiateResult};

// Protocol layer
pub use protocol::{
    Account, BalanceResult, BankParams, DecoupledEvent, DecoupledOptions, DecoupledParams, Dialog,
    HoldingsPage, HoldingsResult, InitResult, New, Open, PollResult, Response, SendResult, Synced,
    TanChallenge, TanPending, TransactionPage, TransactionResult,
};

// Domain types
pub use banks::{all_banks, bank_by_blz, BankConfig};
pub use error::{FinTSError, Result};
pub use session::SessionState;
pub use tokio_util::sync::CancellationToken;
pub use types::{
    AccountBalance, AccountClass, BankName, Bic, Blz, ChallengeText, Currency, DialogId, FinTSUrl,
    HhdUcData, Iban, Isin, Mt940Data, Pin, ProductId, ResponseCode, ResponseCodeKind,
    SecurityFunction, SecurityHolding, SegmentRef, SegmentType, SepaAccount, SystemId, TanMedia,
    TanMediumName, TanMethod, TanProcess, TaskReference, TouchdownPoint, Transaction,
    TransactionStatus, UserId, Wkn,
};

// Debug / audit tooling
pub use audit::{
    audit_client_message, audit_server_response, AuditReport, Violation, ViolationSeverity,
};
pub use debug::{decode_message, format_decoded, DecodedMessage, DecodedSegment, VerbosityLevel};
