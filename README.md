# fints-rs

[![crates.io](https://img.shields.io/crates/v/fints-rs.svg)](https://crates.io/crates/fints-rs)
[![docs.rs](https://docs.rs/fints-rs/badge.svg)](https://docs.rs/fints-rs)

A pure Rust implementation of the **FinTS 3.0** (formerly HBCI) banking protocol for German online banking.

## Features

- Full FinTS 3.0 PinTan implementation (two-step and decoupled TAN)
- Decoupled TAN (pushTAN) polling in the library, following the bank's HITANS
  timing rules, with cancellation, timeout and progress events
- Persistable `SessionState` (system ID, BPD/UPD, TAN method): later runs skip
  the sync dialog and keep a stable system ID
- Typestate protocol layer — invalid dialog state transitions are **compile-time errors**
- Bank-specific workflows (DKB, ING, generic FinTS banks)
- Segment versions negotiated from the bank's BPD; layouts checked against hbci4java's `hbci-300.xml`
- Quirk layer with hbci4java's message rewriters for misbehaving banks
- Built-in registry of 1700+ German banks with FinTS endpoints (updated 20.05.2026)
- Account balance, transaction history (MT940), and securities/depot holdings (MT535)
- Transactions with booking and value date, GVC, prima nota, bank reference and the
  full SEPA purpose (`EREF+`, `MREF+`, `CRED+`, `SVWZ+` kept intact)
- TAN entry for chipTAN/photoTAN/smsTAN, with photoTAN images and flicker codes decoded
- PIN and TAN masked in logs and debug output
- CLI client for interactive banking from the terminal
- Mock server for integration testing
- Debug & audit tooling for protocol inspection

## Installation

### As a library

Add to your `Cargo.toml`:

```toml
[dependencies]
fints-rs = "0.2"
```

The crate is published as `fints-rs` on crates.io but the library name is `fints`, so all imports use `use fints::...`.

### CLI client

```bash
cargo install fints-rs --features cli
```

This installs the `fints-client` binary.

## Library Usage

### Quick start

```rust,no_run
use fints::{Account, CancellationToken, DecoupledEvent, DecoupledOptions, FetchOpts,
            Flow, Pin, ProductId, SessionState, UserId};

#[tokio::main]
async fn main() -> fints::Result<()> {
    // State from the previous run (stored encrypted), or None the first time.
    let saved: Option<SessionState> = None;

    // Step 1: open a dialog. BLZ 50010517 = ING; any registry BLZ works.
    let (mut flow, _info) = Flow::initiate(
        "50010517",
        &UserId::new("your_user_id"),
        &Pin::new("your_pin"),
        &ProductId::new("YOUR_PRODUCT_ID"),
        saved.as_ref(), None, None,
    ).await?;

    // Step 2: SCA. pushTAN: wait for the app confirmation.
    //         chipTAN/photoTAN/smsTAN: show _info.media(), then submit the TAN.
    if flow.needs_tan() {
        flow.await_decoupled(CancellationToken::new(), &DecoupledOptions::default(), |event| {
            if let DecoupledEvent::AwaitingConfirmation { challenge } = event {
                println!("Please confirm in your banking app: {challenge}");
            }
        }).await?;
    }

    // Step 3: fetch any number of accounts in the same dialog.
    let accounts = flow.accounts().to_vec();
    for acc in &accounts {
        let account = Account::from_sepa(acc, "INGDDEFFXXX")?;
        let result = flow.fetch(&account, &FetchOpts::all(90)).await?;
        println!("{}: {:?}, {} transactions, {} holdings",
            acc.iban, result.balance.map(|b| b.amount),
            result.transactions.len(), result.holdings.len());
    }

    // Step 4: end the dialog and persist the updated state for next time.
    let state = flow.finish().await?;
    let _json = state.to_json()?; // store encrypted; it identifies you to the bank
    Ok(())
}
```

A runnable version is in [`examples/sync_accounts.rs`](examples/sync_accounts.rs).

Notes:

- **Session state.** `SessionState` holds the system ID, BPD/UPD and the chosen
  TAN method. It is not a credential, but store it encrypted. With it, the next
  `initiate` skips the sync dialog and the bank keeps seeing the same system ID
  (a new one per run can trigger extra SCA). If the bank rejects the system ID
  (9391), the library re-synchronizes once by itself. When the bank reports a
  changed user ID (3072), `state.user_id` holds the new one and
  `state.previous_user_id` the old one.
- **Decoupled TAN.** `await_decoupled` polls HKTAN process S at the bank's
  announced intervals and stops on confirmation, a bank error, the bank's maximum
  number of polls, `DecoupledOptions::timeout`, or the `CancellationToken`. Run it in
  a background task (`Flow` is `Send`) and never block an HTTP request on a pushTAN.
- **TAN entry.** For non-decoupled methods, `ChallengeInfo::media()` returns the
  photoTAN/QR image or the chipTAN flicker code to show, and `flow.submit_tan(tan)`
  authenticates the dialog. A rejected TAN ends the flow; start over with `initiate`.
- **Date ranges.** `FetchOpts::all(days)` fetches the last `days` days;
  `.with_range(from, to)` fetches an explicit window, e.g. for incremental syncs.
  `Transaction::date` is the booking date and `valuta_date` the value date.
- **Errors.** `FinTSError::is_credentials_error()` (never retry: wrong PINs lock the
  login), `needs_user()` (a TAN is needed) and `is_retryable()` classify failures.
- **One-shot helpers.** `confirm_and_fetch(iban, bic, days)` still exists: it polls
  the TAN status once, fetches one account and ends the dialog.

### Bank lookup

```rust
use fints::{all_banks, bank_by_blz};

// Look up a bank by BLZ
if let Some(bank) = bank_by_blz("12030000") {
    println!("{} — {}", bank.name, bank.url);
}

// List all known banks
for bank in all_banks() {
    println!("{}: {} ({})", bank.blz, bank.name, bank.url);
}
```

### Low-level protocol access

The typestate `Dialog` API enforces correct protocol usage at compile time:

```rust
use fints::protocol::Dialog;
use fints::types::*;

// Dialog<New> → sync → Dialog<Synced> → open → Dialog<Open> → business ops
// Calling business methods on Dialog<New> won't compile.
```

States: `New` → `Synced` → `Open` → `TanPending` → back to `Open` after TAN.

### Bank quirks

Every message passes through a `QuirkChain` (default: hbci4java's rewriters, e.g.
wrong status-segment order, wrong segment numbers, missing message reference).
Add bank-specific fixes with `Dialog::with_quirks(QuirkChain::default().with(MyFix))`
by implementing the `fints::quirks::Quirk` trait.

## CLI Usage

### First-time setup

```bash
fints-client --bank dkb setup
# or by BLZ:
fints-client --bank 12030000 setup
```

This performs a sync dialog, discovers accounts and TAN methods, and saves a session file for future use.

### Sync (balance + transactions + holdings)

```bash
fints-client --bank dkb sync
fints-client --bank dkb sync --days 365
fints-client --bank dkb sync --all-accounts
```

### Balance only

```bash
fints-client --bank dkb balance
fints-client --bank dkb balance --iban DE12345678901234567890
```

### Transactions

```bash
fints-client --bank dkb transactions
fints-client --bank dkb transactions --from 2024-01-01 --to 2024-12-31
fints-client --bank dkb transactions --output json
fints-client --bank dkb transactions --output csv
```

### Holdings (securities/depot)

```bash
fints-client --bank dkb holdings
```

### Custom bank (by URL)

```bash
fints-client --bank custom --url https://banking.example.de/fints --blz 12345678 sync
```

### Session management

```bash
fints-client sessions list
fints-client sessions inspect dkb
fints-client sessions delete dkb
```

### Debug & audit tools

```bash
# Inspect bank capabilities
fints-client --bank dkb inspect

# Decode a raw FinTS message
echo "<base64_message>" | fints-client decode --b64

# Audit a bank's protocol compliance
fints-client audit --blz 12030000
```

### Output formats

All data commands support `--output human` (default), `--output json`, and `--output csv`.

### Environment variables

| Variable | Description |
|---|---|
| `FINTS_PRODUCT_ID` | Override the default FinTS product registration ID |
| `FINTS_SESSION_DIR` | Override the session storage directory |

### Global options

```
--bank <BLZ|name>     Bank identifier (BLZ or shorthand like "dkb")
--user <USER_ID>      FinTS user ID
--pin <PIN>           PIN (prefer interactive prompt instead)
--product-id <ID>     FinTS product registration ID
--verbose / -v        Show decoded FinTS segments
--debug-wire          Show hex wire dumps
--no-persist          Don't save session; print resume token instead
--resume-token <TOK>  Resume from a previously printed token
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    Flow API                     │  ← High-level 2-step TAN flow
├─────────────────────────────────────────────────┤
│                 Workflow layer                  │  ← Bank-specific logic (DKB, ING, Generic)
│            BankOps trait + AnyBank              │
├─────────────────────────────────────────────────┤
│               Protocol layer                   │  ← Typestate Dialog<S> state machine
│     Dialog<New|Synced|Open|TanPending>          │
├──────────────────┬──────────────────────────────┤
│    Segments      │     Message builder          │  ← HKSAL, HKKAZ, HKTAN, ...
├──────────────────┼──────────────────────────────┤
│  Parser          │     Serializer               │  ← Wire format (DEG/DE encoding)
├──────────────────┴──────────────────────────────┤
│        Quirks (hbci4java rewriters)             │  ← Patch malformed bank messages
├─────────────────────────────────────────────────┤
│              Transport (HTTPS)                  │  ← Base64 over HTTPS POST
└─────────────────────────────────────────────────┘
```

## Feature flags

| Feature | Description |
|---|---|
| `cli` | Enables the `fints-client` binary (clap, rpassword, comfy-table, csv, flate2) |
| `server` | Enables the `fints-server` mock server binary (axum) |

No features are enabled by default — the library is lightweight with minimal dependencies.

## FinTS Product Registration

To use FinTS with German banks in production, you need a registered product ID from the [Deutsche Kreditwirtschaft](https://www.fints.org/de/hersteller/produktregistrierung). Set it via:

- `ProductId::new("YOUR_ID")` in code
- `--product-id YOUR_ID` on the CLI
- `FINTS_PRODUCT_ID=YOUR_ID` environment variable

## License

MIT, except for code and data ported from [hbci4java](https://github.com/hbci4j/hbci4java),
which is LGPL-2.1-or-later and kept in separate files: `src/quirks/hbci4java.rs` and
`tests/fixtures/hbci4java/`. See [NOTICE](NOTICE) and [LICENSES/](LICENSES/).
