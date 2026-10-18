//! End-to-end example: open a dialog, confirm pushTAN in the app, fetch all
//! accounts from the UPD, and persist the session state for the next run.
//!
//! ```text
//! FINTS_BLZ=50010517 FINTS_USER=... FINTS_PIN=... FINTS_PRODUCT_ID=... \
//!   cargo run --example sync_accounts -- [state.json] [days]
//! ```
//!
//! The state file is written in plain JSON here for simplicity. A real
//! application should store it encrypted: it identifies you to the bank.

use std::time::Duration;

use fints::{
    Account, CancellationToken, DecoupledEvent, DecoupledOptions, FetchOpts, Flow, Pin, ProductId,
    SessionState, UserId,
};

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("set {name}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let blz = env("FINTS_BLZ")?;
    let user = UserId::new(env("FINTS_USER")?);
    let pin = Pin::new(env("FINTS_PIN")?);
    let product = ProductId::new(env("FINTS_PRODUCT_ID")?);
    let mut args = std::env::args().skip(1);
    let state_file = args.next().unwrap_or_else(|| "fints-state.json".into());
    let days: u32 = args.next().and_then(|d| d.parse().ok()).unwrap_or(90);

    let saved = std::fs::read_to_string(&state_file)
        .ok()
        .map(|s| SessionState::from_json(&s))
        .transpose()?;
    if saved.as_ref().is_some_and(|s| s.can_skip_sync()) {
        println!("Using cached session state from {state_file}");
    }

    let (mut flow, info) =
        Flow::initiate(&blz, &user, &pin, &product, saved.as_ref(), None, None).await?;

    if flow.needs_tan() {
        let cancel = CancellationToken::new();
        let on_ctrl_c = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                on_ctrl_c.cancel();
            }
        });
        let opts = DecoupledOptions {
            timeout: Duration::from_secs(300),
            ..Default::default()
        };
        flow.await_decoupled(cancel, &opts, |event| match event {
            DecoupledEvent::AwaitingConfirmation { challenge } => {
                println!("Confirm in your banking app: {challenge}")
            }
            DecoupledEvent::StillPending { poll } => println!("  still pending (poll {poll})"),
            DecoupledEvent::Confirmed { .. } => println!("  confirmed"),
            DecoupledEvent::Waiting { .. } => {}
        })
        .await?;
    } else if info.no_tan_required {
        println!("No TAN needed (SCA exemption)");
    }

    let bank_bic = fints::bank_by_blz(&blz)
        .map(|b| b.bic.as_str().to_string())
        .unwrap_or_default();
    for acc in flow.accounts().to_vec() {
        let label = if acc.iban.as_str().is_empty() {
            &acc.account_number
        } else {
            acc.iban.as_str()
        };
        let account = match Account::from_sepa(&acc, &bank_bic) {
            Ok(a) => a,
            Err(e) => {
                println!("{label}: skipped ({e})");
                continue;
            }
        };
        match flow.fetch(&account, &FetchOpts::all(days)).await {
            Ok(r) => println!(
                "{label} ({}): balance {:?}, {} transactions, {} holdings",
                acc.product_name.as_deref().unwrap_or("?"),
                r.balance.map(|b| format!("{} {}", b.amount, b.currency)),
                r.transactions.len(),
                r.holdings.len(),
            ),
            Err(e) => println!("{label}: {e}"),
        }
    }

    let state = flow.finish().await?;
    if let Some(old) = &state.previous_user_id {
        println!(
            "Bank changed the user ID from {old} to {} — update your credentials",
            state.user_id
        );
    }
    std::fs::write(&state_file, state.to_json()?)?;
    println!("Session state saved to {state_file}");
    Ok(())
}
