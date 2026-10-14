//! Compile-time tests for the protocol state machine.
//!
//! These tests verify that the typestate pattern enforces the correct
//! transitions at compile time. If any of these tests compile, the
//! state machine allows the transition. Tests that should NOT compile
//! are documented in comments.
//!
//! Based on FinTS 3.0 Formals (2017-10-06), Chapter C.

use fints::protocol::*;
use fints::types::ResponseCode;

// ═══════════════════════════════════════════════════════════════════════════════
// Compile-time safety tests
//
// The following would NOT compile (verified manually):
//
//   fn send_before_auth(d: Dialog<New>) {
//       d.send(vec![]);  // ERROR: no method `send` on Dialog<New>
//   }
//
//   fn send_while_tan_pending(d: Dialog<TanPending>) {
//       d.send(vec![]);  // ERROR: no method `send` on Dialog<TanPending>
//   }
//
//   fn poll_on_open(d: Dialog<Open>) {
//       d.poll("ref");   // ERROR: no method `poll` on Dialog<Open>
//   }
//
//   fn end_on_new(d: Dialog<New>) {
//       d.end();          // ERROR: no method `end` on Dialog<New>
//   }
//
//   fn init_twice(d: Dialog<Open>) {
//       d.init();         // ERROR: no method `init` on Dialog<Open>
//   }
//
//   fn sync_on_open(d: Dialog<Open>) {
//       d.sync();         // ERROR: no method `sync` on Dialog<Open>
//   }
//
// ═══════════════════════════════════════════════════════════════════════════════

// ── Response parsing tests ──────────────────────────────────────────────────

#[test]
fn test_response_codes_success() {
    let code = ResponseCode::new("0020", "Auftrag ausgefuehrt");
    assert!(code.is_success());
    assert!(!code.is_warning());
    assert!(!code.is_error());
}

#[test]
fn test_response_codes_warning() {
    let code = ResponseCode::with_params(
        "3920",
        "Zugelassene Verfahren",
        vec!["912".into(), "913".into()],
    );
    assert!(code.is_warning());
    assert!(!code.is_error());
    assert!(code.is_allowed_tan_methods());
}

#[test]
fn test_response_codes_error() {
    let code = ResponseCode::new("9340", "PIN gesperrt");
    assert!(code.is_error());
    assert!(code.is_pin_wrong());
}

#[test]
fn test_response_needs_tan_0030() {
    let response = Response {
        segments: vec![],
        global_codes: vec![ResponseCode::new("0030", "Auftrag entgegengenommen")],
        segment_codes: vec![],
    };
    assert!(response.needs_tan());
}

#[test]
fn test_response_decoupled_3955() {
    let response = Response {
        segments: vec![],
        global_codes: vec![],
        segment_codes: vec![ResponseCode::new("3955", "Freigabe ausstehend")],
    };
    assert!(response.needs_tan());
    assert!(response.is_decoupled());
}

#[test]
fn test_response_decoupled_pending_3956() {
    let response = Response {
        segments: vec![],
        global_codes: vec![],
        segment_codes: vec![ResponseCode::new(
            "3956",
            "Decoupled: noch nicht bestaetigt",
        )],
    };
    assert!(response.is_decoupled_pending());
}

#[test]
fn test_response_sca_exemption_3076() {
    let response = Response {
        segments: vec![],
        global_codes: vec![],
        segment_codes: vec![ResponseCode::new(
            "3076",
            "Keine starke Authentifizierung erforderlich",
        )],
    };
    assert!(response.has_sca_exemption());
    assert!(!response.needs_tan());
}

#[test]
fn test_response_touchdown_3040() {
    let response = Response {
        segments: vec![],
        global_codes: vec![],
        segment_codes: vec![ResponseCode::with_params(
            "3040",
            "Aufsetzpunkt",
            vec!["12345".into()],
        )],
    };
    assert_eq!(
        response.touchdown(),
        Some(fints::TouchdownPoint::new("12345"))
    );
}

#[test]
fn test_response_no_touchdown() {
    let response = Response {
        segments: vec![],
        global_codes: vec![ResponseCode::new("0020", "Auftrag ausgefuehrt")],
        segment_codes: vec![],
    };
    assert_eq!(response.touchdown(), None);
}

#[test]
fn test_response_check_errors_pin_wrong() {
    let response = Response {
        segments: vec![],
        global_codes: vec![ResponseCode::new("9340", "PIN falsch")],
        segment_codes: vec![],
    };
    let err = response.check_errors().unwrap_err();
    assert!(matches!(err, fints::FinTSError::PinWrong));
}

#[test]
fn test_response_check_errors_account_locked() {
    let response = Response {
        segments: vec![],
        global_codes: vec![ResponseCode::new("9942", "Zugang gesperrt")],
        segment_codes: vec![],
    };
    let err = response.check_errors().unwrap_err();
    assert!(matches!(err, fints::FinTSError::AccountLocked));
}

#[test]
fn test_response_check_errors_bank_error() {
    let response = Response {
        segments: vec![],
        global_codes: vec![ResponseCode::new("9800", "Dialog abgebrochen")],
        segment_codes: vec![],
    };
    let err = response.check_errors().unwrap_err();
    match err {
        fints::FinTSError::BankError { kind, message } => {
            assert_eq!(kind, fints::ResponseCodeKind::DialogAborted);
            assert_eq!(message, "Dialog abgebrochen");
        }
        _ => panic!("Expected BankError"),
    }
}

#[test]
fn test_response_allowed_security_functions_3920() {
    let response = Response {
        segments: vec![],
        global_codes: vec![],
        segment_codes: vec![ResponseCode::with_params(
            "3920",
            "Zugelassene Verfahren",
            vec!["912".into(), "940".into(), "942".into()],
        )],
    };
    let allowed = response.allowed_security_functions();
    let expected: Vec<fints::SecurityFunction> = vec![
        fints::SecurityFunction::new("912"),
        fints::SecurityFunction::new("940"),
        fints::SecurityFunction::new("942"),
    ];
    assert_eq!(allowed, expected);
}

// ── BankParams tests ────────────────────────────────────────────────────────

#[test]
fn test_bank_params_needs_tan_default_true() {
    // Unknown operations should default to requiring TAN (safe default)
    let params = BankParams::new();
    assert!(params.needs_tan(&fints::SegmentType::new("HKXYZ")));
}

#[test]
fn test_bank_params_needs_tan_from_hipins() {
    let mut params = BankParams::new();
    params
        .operation_tan_required
        .insert(fints::SegmentType::new("HKSAL"), false);
    params
        .operation_tan_required
        .insert(fints::SegmentType::new("HKCCS"), true);

    assert!(!params.needs_tan(&fints::SegmentType::new("HKSAL")));
    assert!(params.needs_tan(&fints::SegmentType::new("HKCCS")));
    assert!(params.needs_tan(&fints::SegmentType::new("HKXYZ")));
}

#[test]
fn test_bank_params_select_security_function_prefers_decoupled() {
    let mut params = BankParams::new();
    params.allowed_security_functions = vec![
        fints::SecurityFunction::new("912"),
        fints::SecurityFunction::new("940"),
    ];
    params.tan_methods = vec![
        fints::TanMethod {
            security_function: fints::SecurityFunction::new("912"),
            tan_process: fints::types::TanProcess::TwoStep,
            name: "chipTAN".into(),
            needs_tan_medium: false,
            decoupled_max_polls: -1,
            wait_before_first_poll: 0,
            wait_before_next_poll: 0,
            is_decoupled: false,
            hktan_version: 7,
            zka_name: None,
            decoupled_auto_polling: None,
        },
        fints::TanMethod {
            security_function: fints::SecurityFunction::new("940"),
            tan_process: fints::types::TanProcess::TwoStep,
            name: "pushTAN".into(),
            needs_tan_medium: true,
            decoupled_max_polls: 20,
            wait_before_first_poll: 5,
            wait_before_next_poll: 5,
            is_decoupled: true,
            hktan_version: 7,
            zka_name: None,
            decoupled_auto_polling: None,
        },
    ];
    params.select_security_function();
    assert_eq!(
        params.selected_security_function,
        fints::SecurityFunction::new("940")
    );
    assert!(params.is_decoupled());
}

#[test]
fn test_bank_params_select_respects_user_preference() {
    let mut params = BankParams::new();
    params.allowed_security_functions = vec![
        fints::SecurityFunction::new("912"),
        fints::SecurityFunction::new("940"),
    ];
    params.preferred_security_function = Some(fints::SecurityFunction::new("912"));
    params.tan_methods = vec![fints::TanMethod {
        security_function: fints::SecurityFunction::new("912"),
        tan_process: fints::types::TanProcess::TwoStep,
        name: "chipTAN".into(),
        needs_tan_medium: false,
        decoupled_max_polls: -1,
        wait_before_first_poll: 0,
        wait_before_next_poll: 0,
        is_decoupled: false,
        hktan_version: 7,
        zka_name: None,
        decoupled_auto_polling: None,
    }];
    params.select_security_function();
    assert_eq!(
        params.selected_security_function,
        fints::SecurityFunction::new("912")
    );
}

// ── SecurityHolding tests ───────────────────────────────────────────────────

#[test]
fn test_security_holding_type() {
    use rust_decimal::Decimal;
    let holding = fints::SecurityHolding {
        isin: Some(fints::Isin::new("DE0005140008")),
        wkn: Some(fints::Wkn::new("514000")),
        name: "DEUTSCHE BANK AG".to_string(),
        quantity: Decimal::new(100, 0),
        price: Some(Decimal::new(4250, 2)),
        price_currency: Some(fints::Currency::new("EUR")),
        price_date: Some(chrono::NaiveDate::from_ymd_opt(2026, 3, 15).unwrap()),
        market_value: Some(Decimal::new(4250, 0)),
        market_value_currency: Some(fints::Currency::new("EUR")),
        acquisition_value: Some(Decimal::new(3800, 0)),
        profit_loss: Some(Decimal::new(450, 0)),
        exchange: Some("XETRA".to_string()),
        depot_id: Some("12345678".to_string()),
        raw: serde_json::json!({}),
    };

    assert_eq!(holding.isin.as_ref().unwrap().as_str(), "DE0005140008");
    assert_eq!(holding.wkn.as_ref().unwrap().as_str(), "514000");
    assert_eq!(holding.name, "DEUTSCHE BANK AG");
    assert_eq!(holding.quantity, Decimal::new(100, 0));
    assert_eq!(holding.price, Some(Decimal::new(4250, 2)));
    assert_eq!(holding.exchange, Some("XETRA".to_string()));
}

#[test]
fn test_security_holding_serializable() {
    use rust_decimal::Decimal;
    let holding = fints::SecurityHolding {
        isin: Some(fints::Isin::new("DE0005140008")),
        wkn: None,
        name: "TEST AG".to_string(),
        quantity: Decimal::new(50, 0),
        price: Some(Decimal::new(100, 0)),
        price_currency: Some(fints::Currency::new("EUR")),
        price_date: None,
        market_value: Some(Decimal::new(5000, 0)),
        market_value_currency: Some(fints::Currency::new("EUR")),
        acquisition_value: None,
        profit_loss: None,
        exchange: None,
        depot_id: None,
        raw: serde_json::json!({}),
    };

    // SecurityHolding must be serializable (used in Flow API results)
    let json = serde_json::to_string(&holding).unwrap();
    assert!(json.contains("DE0005140008"));
    assert!(json.contains("TEST AG"));

    // And deserializable
    let deserialized: fints::SecurityHolding = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.isin.as_ref().unwrap().as_str(), "DE0005140008");
    assert_eq!(deserialized.name, "TEST AG");
}

#[test]
fn test_isin_newtype() {
    let isin = fints::Isin::new("DE0005140008");
    assert_eq!(isin.as_str(), "DE0005140008");
    assert_eq!(format!("{}", isin), "DE0005140008");
}

#[test]
fn test_wkn_newtype() {
    let wkn = fints::Wkn::new("514000");
    assert_eq!(wkn.as_str(), "514000");
    assert_eq!(format!("{}", wkn), "514000");
}

#[test]
fn test_fetch_result_includes_holdings() {
    // FetchResult must have a holdings field
    let result = fints::FetchResult {
        balance: None,
        transactions: vec![],
        holdings: vec![],
    };
    assert!(result.holdings.is_empty());
}

#[test]
fn test_sync_result_includes_holdings() {
    // SyncResult must have a holdings field
    let result = fints::SyncResult {
        iban: fints::Iban::new("DE89370400440532013000"),
        bic: fints::Bic::new("COBADEFFXXX"),
        balance: None,
        transactions: vec![],
        holdings: vec![],
        system_id: None,
    };
    assert!(result.holdings.is_empty());
}

// ── Type-level transition proof ─────────────────────────────────────────────
// These tests verify the TYPE SIGNATURES of the state machine.
// They don't call actual bank servers — they verify the API shape.

/// Verify that InitResult::Opened gives Dialog<Open> and InitResult::TanRequired gives Dialog<TanPending>.
/// This is a compile-time test — if it compiles, the types are correct.
fn _type_test_init_result_transitions(result: InitResult) {
    match result {
        InitResult::Opened(dialog, _response) => {
            // dialog: Dialog<Open> — can call send() and end()
            let _: Dialog<Open> = dialog;
        }
        InitResult::TanRequired(dialog, _challenge, _response) => {
            // dialog: Dialog<TanPending> — can call poll() and submit_tan()
            let _: Dialog<TanPending> = dialog;
        }
    }
}

/// Verify that PollResult::Confirmed gives Dialog<Open>.
fn _type_test_poll_result_transitions(result: PollResult) {
    match result {
        PollResult::Confirmed(dialog, _response) => {
            let _: Dialog<Open> = dialog;
        }
        PollResult::Pending(dialog) => {
            let _: Dialog<TanPending> = dialog;
        }
    }
}

/// Verify that SendResult::NeedTan gives Dialog<TanPending>.
fn _type_test_send_result_transitions(result: SendResult) {
    match result {
        SendResult::Success(_response) => {
            // No dialog transition — stays Open
        }
        SendResult::NeedTan(dialog, _challenge, _response) => {
            let _: Dialog<TanPending> = dialog;
        }
        SendResult::Touchdown(_response, _point) => {
            // No dialog transition — stays Open (for send_raw_keep)
        }
    }
}

/// Verify that HoldingsResult has the expected variants.
fn _type_test_holdings_result(result: fints::HoldingsResult) {
    match result {
        fints::HoldingsResult::Success(page) => {
            let _: Vec<fints::SecurityHolding> = page.holdings;
            let _: Option<fints::TouchdownPoint> = page.touchdown;
        }
        fints::HoldingsResult::NeedTan(_challenge) => {
            // TAN required for depot query
        }
        fints::HoldingsResult::Empty => {
            // Empty depot or unsupported
        }
    }
}

// ── Account validation tests ────────────────────────────────────────────────

#[test]
fn test_account_valid() {
    let acc = Account::new("DE89370400440532013000", "COBADEFFXXX");
    assert!(acc.is_ok());
    let acc = acc.unwrap();
    assert_eq!(acc.iban(), "DE89370400440532013000");
    assert_eq!(acc.bic(), "COBADEFFXXX");
}

#[test]
fn test_account_empty_bic_rejected() {
    // This is THE bug that caused the 9160 error. Empty BIC must be rejected.
    let result = Account::new("DE89370400440532013000", "");
    assert!(result.is_err(), "Account with empty BIC must be rejected");
}

#[test]
fn test_account_empty_iban_rejected() {
    let result = Account::new("", "COBADEFFXXX");
    assert!(result.is_err(), "Account with empty IBAN must be rejected");
}

#[test]
fn test_account_both_empty_rejected() {
    let result = Account::new("", "");
    assert!(result.is_err());
}
