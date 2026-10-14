//! Decoupled TAN (pushTAN) polling against a scripted bank.
//!
//! A tiny HTTP server answers each FinTS request with the next canned
//! response, so we can drive `Dialog::await_decoupled` through 3955 → 3956 …
//! → 0020 and its failure modes without a real bank.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use fints::protocol::{BankParams, Dialog, InitResult};
use fints::{
    Blz, CancellationToken, DecoupledEvent, DecoupledOptions, FinTSError, Pin, ProductId,
    SecurityFunction, TanMethod, TanProcess, UserId,
};

/// Wrap response segments in a minimal FinTS message.
fn msg(body: &str) -> String {
    format!("HNHBK:1:3+000000000000+300+DLG-1+1'{body}HNHBS:9:1+1'")
}

const INIT_PUSH_SENT: &str = "HIRMG:2:2+0010::Nachricht entgegengenommen'\
    HIRMS:3:2:4+3955::Bitte bestaetigen Sie den Vorgang in Ihrer App'\
    HITAN:4:7:4+4++TASK-42+Bitte in der App freigeben'";
const PENDING: &str = "HIRMG:2:2+0010::ok'HIRMS:3:2:3+3956::Freigabe ausstehend'";
const CONFIRMED: &str = "HIRMG:2:2+0010::ok'HIRMS:3:2:3+0020::Auftrag ausgefuehrt'";
const EXPIRED: &str = "HIRMG:2:2+9050::Teilweise fehlerhaft'HIRMS:3:2:3+9999::TAN abgelaufen'";

/// Serve canned responses in order (the last one repeats). Returns the URL
/// and a log of the raw requests the client sent.
async fn scripted_bank(responses: Vec<&'static str>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let body = msg(responses[n.min(responses.len() - 1)]);
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read headers, then Content-Length bytes of body.
                let (header_end, content_length) = loop {
                    let r = sock.read(&mut chunk).await.unwrap_or(0);
                    if r == 0 { return; }
                    buf.extend_from_slice(&chunk[..r]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                        let len = head.lines()
                            .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        break (pos + 4, len);
                    }
                };
                while buf.len() < header_end + content_length {
                    let r = sock.read(&mut chunk).await.unwrap_or(0);
                    if r == 0 { break; }
                    buf.extend_from_slice(&chunk[..r]);
                }
                let decoded = B64.decode(&buf[header_end..]).unwrap_or_default();
                log.lock().unwrap().push(String::from_utf8_lossy(&decoded).into_owned());
                let encoded = B64.encode(body.as_bytes());
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", encoded.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(encoded.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (url, requests)
}

fn decoupled_method(max_polls: i32) -> TanMethod {
    TanMethod {
        security_function: SecurityFunction::new("902"),
        tan_process: TanProcess::TwoStep,
        name: "pushTAN 2.0".into(),
        needs_tan_medium: false,
        decoupled_max_polls: max_polls,
        // 0 = not announced → DecoupledOptions defaults (kept tiny for tests).
        wait_before_first_poll: 0,
        wait_before_next_poll: 0,
        is_decoupled: true,
        hktan_version: 7,
        zka_name: Some("Decoupled".into()),
        decoupled_auto_polling: Some(true),
    }
}

fn fast_opts(timeout: Duration) -> DecoupledOptions {
    DecoupledOptions {
        timeout,
        default_first_wait: Duration::from_millis(10),
        default_next_wait: Duration::from_millis(10),
    }
}

/// Open a dialog against the scripted bank and get to TanPending.
async fn pending_dialog(
    url: &str,
    max_polls: i32,
) -> (Dialog<fints::TanPending>, fints::TanChallenge) {
    let mut params = BankParams::new();
    params.tan_methods = vec![decoupled_method(max_polls)];
    params.allowed_security_functions = vec![SecurityFunction::new("902")];
    params.select_security_function();
    let dialog = Dialog::new(url, &Blz::new("50010517"), &UserId::new("u"), &Pin::new("12345"), &ProductId::new("P"))
        .unwrap()
        .with_params(&params);
    match dialog.init().await.unwrap() {
        InitResult::TanRequired(d, challenge, _) => (d, challenge),
        InitResult::Opened(..) => panic!("expected a TAN challenge"),
    }
}

#[tokio::test]
async fn polls_until_confirmed_and_reports_progress() {
    let (url, requests) = scripted_bank(vec![INIT_PUSH_SENT, PENDING, PENDING, CONFIRMED]).await;
    let (dialog, challenge) = pending_dialog(&url, -1).await;
    assert!(challenge.decoupled);
    assert_eq!(challenge.task_reference.as_str(), "TASK-42");

    let mut events = Vec::new();
    let (_open, _resp) = dialog
        .await_decoupled(&challenge, CancellationToken::new(), &fast_opts(Duration::from_secs(5)), |e| events.push(e))
        .await
        .expect("should confirm");

    assert!(matches!(events.first(), Some(DecoupledEvent::AwaitingConfirmation { .. })));
    let pending = events.iter().filter(|e| matches!(e, DecoupledEvent::StillPending { .. })).count();
    assert_eq!(pending, 2);
    assert_eq!(events.last(), Some(&DecoupledEvent::Confirmed { polls: 3 }));

    // Every poll is HKTAN process S with the task reference, and nothing else.
    let reqs = requests.lock().unwrap();
    assert_eq!(reqs.len(), 4);
    for poll in &reqs[1..] {
        assert!(poll.contains("HKTAN:3:7+S++++TASK-42+N'"), "poll was: {poll}");
        assert!(!poll.contains("HKIDN"), "polls must not re-init: {poll}");
    }
}

#[tokio::test]
async fn stops_at_banks_max_polls() {
    let (url, requests) = scripted_bank(vec![INIT_PUSH_SENT, PENDING]).await;
    let (dialog, challenge) = pending_dialog(&url, 2).await;
    let err = dialog
        .await_decoupled(&challenge, CancellationToken::new(), &fast_opts(Duration::from_secs(5)), |_| {})
        .await
        .unwrap_err();
    assert!(matches!(err, FinTSError::DecoupledMaxPolls(2)), "got {err:?}");
    // init + 2 polls + HKEND
    let reqs = requests.lock().unwrap();
    assert_eq!(reqs.iter().filter(|r| r.contains("HKTAN") && r.contains("+S+")).count(), 2);
    assert!(reqs.last().unwrap().contains("HKEND"), "dialog should be ended");
}

#[tokio::test]
async fn times_out_cleanly_instead_of_hanging() {
    let (url, requests) = scripted_bank(vec![INIT_PUSH_SENT, PENDING]).await;
    let (dialog, challenge) = pending_dialog(&url, 0).await; // 0 = unlimited per spec
    let started = std::time::Instant::now();
    let err = dialog
        .await_decoupled(&challenge, CancellationToken::new(), &fast_opts(Duration::from_millis(150)), |_| {})
        .await
        .unwrap_err();
    assert!(matches!(err, FinTSError::TanTimeout), "got {err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(requests.lock().unwrap().last().unwrap().contains("HKEND"));
}

#[tokio::test]
async fn cancellation_stops_waiting() {
    let (url, _requests) = scripted_bank(vec![INIT_PUSH_SENT, PENDING]).await;
    let (dialog, challenge) = pending_dialog(&url, -1).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let opts = DecoupledOptions {
        timeout: Duration::from_secs(30),
        default_first_wait: Duration::from_secs(10),
        default_next_wait: Duration::from_secs(10),
    };
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    let started = std::time::Instant::now();
    let err = dialog.await_decoupled(&challenge, cancel, &opts, |_| {}).await.unwrap_err();
    assert!(matches!(err, FinTSError::Cancelled), "got {err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn bank_error_while_pending_is_returned() {
    let (url, _requests) = scripted_bank(vec![INIT_PUSH_SENT, PENDING, EXPIRED]).await;
    let (dialog, challenge) = pending_dialog(&url, -1).await;
    let err = dialog
        .await_decoupled(&challenge, CancellationToken::new(), &fast_opts(Duration::from_secs(5)), |_| {})
        .await
        .unwrap_err();
    match err {
        FinTSError::BankError { message, .. } => assert!(message.contains("abgelaufen") || message.contains("fehlerhaft")),
        other => panic!("expected bank error, got {other:?}"),
    }
}

#[tokio::test]
async fn respects_bank_wait_before_first_poll() {
    let (url, _requests) = scripted_bank(vec![INIT_PUSH_SENT, CONFIRMED]).await;
    let mut params = BankParams::new();
    let mut m = decoupled_method(-1);
    m.wait_before_first_poll = 1; // seconds, from HITANS
    params.tan_methods = vec![m];
    params.allowed_security_functions = vec![SecurityFunction::new("902")];
    params.select_security_function();
    let dialog = Dialog::new(&url, &Blz::new("1"), &UserId::new("u"), &Pin::new("1"), &ProductId::new("P"))
        .unwrap()
        .with_params(&params);
    let InitResult::TanRequired(dialog, challenge, _) = dialog.init().await.unwrap() else { panic!() };

    let mut waits = Vec::new();
    let started = std::time::Instant::now();
    dialog
        .await_decoupled(&challenge, CancellationToken::new(), &fast_opts(Duration::from_secs(5)), |e| {
            if let DecoupledEvent::Waiting { delay, .. } = e { waits.push(delay) }
        })
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(900), "bank's 1s minimum wait must be honored");
    assert!(waits[0] > Duration::from_millis(900) && waits[0] <= Duration::from_secs(1));
}
