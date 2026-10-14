//! Additional protocol tests covering edge cases and previously untested paths.

use fints::protocol::{Account, BankParams};
use fints::types::TanProcess;
use fints::types::{
    DialogId, ResponseCodeKind, SecurityFunction, SegmentType, SystemId, TanMethod, TouchdownPoint,
};

// ─── Task A.1 & A.2: Account validation and accessors ───────────────────────

#[test]
fn test_account_iban_validation() {
    // Empty IBAN must fail
    let result = Account::new("", "COBADEFFXXX");
    assert!(result.is_err(), "Account with empty IBAN must be rejected");

    // Empty BIC must fail
    let result = Account::new("DE89370400440532013000", "");
    assert!(result.is_err(), "Account with empty BIC must be rejected");

    // Both non-empty must succeed
    let result = Account::new("DE89370400440532013000", "COBADEFFXXX");
    assert!(
        result.is_ok(),
        "Account with valid IBAN and BIC must succeed"
    );
}

#[test]
fn test_account_display() {
    let acc = Account::new("DE89370400440532013000", "COBADEFFXXX").unwrap();
    assert_eq!(acc.iban(), "DE89370400440532013000");
    assert_eq!(acc.bic(), "COBADEFFXXX");
}

// ─── Task A.3: All known response codes ─────────────────────────────────────

#[test]
fn test_response_code_all_known_codes() {
    let cases: &[(&str, ResponseCodeKind)] = &[
        ("0010", ResponseCodeKind::MessageReceived),
        ("0020", ResponseCodeKind::OrderExecuted),
        ("0030", ResponseCodeKind::TanRequired),
        ("0100", ResponseCodeKind::DialogEnded),
        ("0900", ResponseCodeKind::TanValid),
        // 3040 needs parameter — tested separately
        ("3060", ResponseCodeKind::PartialWarnings),
        ("3076", ResponseCodeKind::ScaExemption),
        // 3920 needs parameters — tested separately
        ("3955", ResponseCodeKind::DecoupledInitiated),
        ("3956", ResponseCodeKind::DecoupledPending),
        ("9010", ResponseCodeKind::GeneralError),
        ("9040", ResponseCodeKind::AuthenticationMissing),
        ("9050", ResponseCodeKind::PartialErrors),
        ("9110", ResponseCodeKind::UnexpectedInSync),
        ("9160", ResponseCodeKind::DataElementMissing),
        ("9340", ResponseCodeKind::PinWrong),
        ("9800", ResponseCodeKind::DialogAborted),
        ("9942", ResponseCodeKind::AccountLocked),
    ];
    for (code, expected) in cases {
        let kind = ResponseCodeKind::from_code(code, &[]);
        assert_eq!(
            &kind, expected,
            "Code {} did not match expected variant",
            code
        );
    }
}

// ─── Task A.4: Unknown codes fall into correct catch-all variants ────────────

#[test]
fn test_response_code_unknown() {
    // 0xxx → OtherSuccess
    let kind = ResponseCodeKind::from_code("0999", &[]);
    assert!(matches!(kind, ResponseCodeKind::OtherSuccess(_)));
    assert!(kind.is_success());

    // 3xxx → OtherWarning
    let kind = ResponseCodeKind::from_code("3999", &[]);
    assert!(matches!(kind, ResponseCodeKind::OtherWarning(_)));
    assert!(kind.is_warning());

    // 9xxx → OtherError
    let kind = ResponseCodeKind::from_code("9999", &[]);
    assert!(matches!(kind, ResponseCodeKind::OtherError(_)));
    assert!(kind.is_error());

    // Other first digit → Unknown
    let kind = ResponseCodeKind::from_code("1234", &[]);
    assert!(matches!(kind, ResponseCodeKind::Unknown(_)));

    let kind = ResponseCodeKind::from_code("XXXX", &[]);
    assert!(matches!(kind, ResponseCodeKind::Unknown(_)));
}

// ─── Task A.5: 3920 with multiple security functions ─────────────────────────

#[test]
fn test_response_code_3920_parameters() {
    let params = vec!["912".to_string(), "913".to_string(), "940".to_string()];
    let kind = ResponseCodeKind::from_code("3920", &params);
    match kind {
        ResponseCodeKind::AllowedSecurityFunctions(fns) => {
            assert_eq!(fns.len(), 3);
            assert_eq!(fns[0], SecurityFunction::new("912"));
            assert_eq!(fns[1], SecurityFunction::new("913"));
            assert_eq!(fns[2], SecurityFunction::new("940"));
        }
        other => panic!("Expected AllowedSecurityFunctions, got {:?}", other),
    }
}

// ─── Task A.6: 3040 with parameter produces Touchdown ────────────────────────

#[test]
fn test_response_code_3040_touchdown() {
    let params = vec!["ABCDEFG12345".to_string()];
    let kind = ResponseCodeKind::from_code("3040", &params);
    match kind {
        ResponseCodeKind::Touchdown(tp) => {
            assert_eq!(tp, TouchdownPoint::new("ABCDEFG12345"));
        }
        other => panic!("Expected Touchdown, got {:?}", other),
    }
}

// ─── Task A.7: BankParams::needs_tan defaults to true for unknown segment ────

#[test]
fn test_bankparams_needs_tan_default() {
    let params = BankParams::new();
    // Unknown segment type defaults to true (safe default)
    assert!(params.needs_tan(&SegmentType::new("HKXYZ")));
    assert!(params.needs_tan(&SegmentType::new("HKABC")));
    assert!(params.needs_tan(&SegmentType::new("UNKN")));
}

// ─── Task A.8: select_security_function prefers decoupled ────────────────────

#[test]
fn test_bankparams_select_security_function_prefers_decoupled() {
    let mut params = BankParams::new();
    params.allowed_security_functions =
        vec![SecurityFunction::new("912"), SecurityFunction::new("940")];
    params.tan_methods = vec![
        TanMethod {
            security_function: SecurityFunction::new("912"),
            tan_process: TanProcess::TwoStep,
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
        TanMethod {
            security_function: SecurityFunction::new("940"),
            tan_process: TanProcess::TwoStep,
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
        SecurityFunction::new("940")
    );
    assert!(params.is_decoupled());
}

// ─── Task A.9: select_security_function uses preferred when allowed ───────────

#[test]
fn test_bankparams_select_security_function_uses_preference() {
    let mut params = BankParams::new();
    params.allowed_security_functions =
        vec![SecurityFunction::new("912"), SecurityFunction::new("940")];
    // User prefers 912 (chipTAN), even though 940 (pushTAN/decoupled) would rank higher
    params.preferred_security_function = Some(SecurityFunction::new("912"));
    params.tan_methods = vec![
        TanMethod {
            security_function: SecurityFunction::new("912"),
            tan_process: TanProcess::TwoStep,
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
        TanMethod {
            security_function: SecurityFunction::new("940"),
            tan_process: TanProcess::TwoStep,
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
        SecurityFunction::new("912")
    );
}

// ─── Task A.10: decoupled_params defaults when no method matches ──────────────

#[test]
fn test_bankparams_decoupled_params_defaults() {
    let params = BankParams::new();
    // No tan methods → should return (5, 5, 20) defaults
    let (first, next, max) = params.decoupled_params();
    assert_eq!(first, 5);
    assert_eq!(next, 5);
    assert_eq!(max, 20);
}

// ─── Task A.11: SystemId assignment ──────────────────────────────────────────

#[test]
fn test_system_id_assigned() {
    let unassigned = SystemId::unassigned();
    assert!(
        !unassigned.is_assigned(),
        "SystemId::unassigned() should not be assigned"
    );

    let assigned = SystemId::new("12345ABC");
    assert!(
        assigned.is_assigned(),
        "Non-'0' system ID should be assigned"
    );

    // "0" is the special unassigned marker
    let zero = SystemId::new("0");
    assert!(
        !zero.is_assigned(),
        "'0' is the unassigned system ID marker"
    );
}

// ─── Task A.12: DialogId assignment ──────────────────────────────────────────

#[test]
fn test_dialog_id_assigned() {
    let unassigned = DialogId::unassigned();
    assert!(
        !unassigned.is_assigned(),
        "DialogId::unassigned() should not be assigned"
    );

    let assigned = DialogId::new("dialog-abc-123");
    assert!(
        assigned.is_assigned(),
        "Non-'0' dialog ID should be assigned"
    );

    // "0" is the special unassigned marker
    let zero = DialogId::new("0");
    assert!(
        !zero.is_assigned(),
        "'0' is the unassigned dialog ID marker"
    );
}
