//! Segment builders: functions that create `Vec<DEG>` for each request segment type.
//!
//! All builders are `pub(crate)` — they are internal implementation details.
//! External consumers should use the typed methods on `Dialog<Open>` instead.

use chrono::{Local, NaiveDate};

use crate::error::{FinTSError, Result};
use crate::parser::DEG;
use crate::protocol::Account;
use crate::types::*;

/// HKSAL versions we can build. v8 has the same request layout as v7.
pub(crate) const HKSAL_VERSIONS: &[u16] = &[5, 6, 7, 8];
/// HKKAZ versions we can build.
pub(crate) const HKKAZ_VERSIONS: &[u16] = &[5, 6, 7];
/// HKWPD versions we can build. Neither hbci4java nor python-fints know a v7.
pub(crate) const HKWPD_VERSIONS: &[u16] = &[5, 6];
/// HKTAN versions we can build.
pub(crate) const HKTAN_VERSIONS: &[u16] = &[5, 6, 7];

// ---- Account identification ----
//
// FinTS uses three account DEGs depending on segment version (hbci-300.xml):
//   KTV2 (HBCI 2.2):  number:subnumber:country:blz
//   KTV3 (FinTS 3.0): number:subnumber:KIK(country:blz)  — same flat wire form as KTV2
//   KTVInt / KTI1:    iban:bic[:number:subnumber:country:blz]
//
// We send KTI as `IBAN:BIC` only (trailing optionals stripped), which is what
// DKB accepts today. National formats need the account number and BLZ, which
// `Account` derives from German IBANs or takes explicitly.

/// National account DEG (KTV2 / KTV3): `number:subnumber:280:blz`.
fn ktv(account: &Account, segment: &str, version: u16) -> Result<DEG> {
    match (account.account_number(), account.blz()) {
        (Some(number), Some(blz)) => Ok(deg(vec![
            de_text(number),
            de_text(account.subaccount().unwrap_or("")),
            de_text("280"),
            de_text(blz),
        ])),
        _ => Err(FinTSError::SegmentNotSupported(format!(
            "{segment} v{version} needs a national account number and BLZ, \
             which cannot be derived from IBAN {}; use Account::with_national()",
            account.iban()
        ))),
    }
}

/// International account DEG (KTVInt / KTI1): `IBAN:BIC`.
fn kti(account: &Account, segment: &str, version: u16) -> Result<DEG> {
    if account.iban().is_empty() || account.bic().is_empty() {
        return Err(FinTSError::SegmentNotSupported(format!(
            "{segment} v{version} addresses accounts by IBAN and BIC, but this account has none"
        )));
    }
    Ok(deg(vec![de_text(account.iban()), de_text(account.bic())]))
}

fn unsupported(segment: &str, version: u16) -> FinTSError {
    FinTSError::SegmentNotSupported(format!("{segment} v{version} is not implemented"))
}

// ---- Segment Header ----

/// Create a segment header DEG: `TYPE:NUMBER:VERSION`
pub(crate) fn seg_header(seg_type: &str, number: u16, version: u16) -> DEG {
    deg(vec![de_text(seg_type), de_num(number), de_num(version)])
}

/// Create a segment header with reference: `TYPE:NUMBER:VERSION:REFERENCE`
pub(crate) fn seg_header_ref(seg_type: &str, number: u16, version: u16, reference: u16) -> DEG {
    deg(vec![
        de_text(seg_type),
        de_num(number),
        de_num(version),
        de_num(reference),
    ])
}

// ---- HNHBK (Nachrichtenkopf) - Message Header, version 3 ----

/// Build HNHBK:1:3 (message header).
/// `message_size` should be 12-digit zero-padded. Caller must update this after final serialization.
pub(crate) fn hnhbk(message_size: u32, dialog_id: &str, message_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HNHBK", 1, 3),
        deg1(de_text(&format!("{:012}", message_size))), // message size (12 digits)
        deg1(de_text("300")),                            // HBCI version 3.0
        deg1(de_text(dialog_id)),                        // dialog ID
        deg1(de_num(message_number)),                    // message number
    ]
}

// ---- HNHBS (Nachrichtenabschluss) - Message Trailer, version 1 ----

pub(crate) fn hnhbs(segment_number: u16, message_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HNHBS", segment_number, 1),
        deg1(de_num(message_number)),
    ]
}

// ---- HNVSK (Verschlüsselungskopf) - Encryption Header, version 3 ----

/// Build HNVSK:998:3 with PinTan dummy encryption parameters.
pub(crate) fn hnvsk(blz: &str, user_id: &str, system_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HNVSK", 998, 3),
        // Security profile: PIN:1
        deg(vec![de_text("PIN"), de_text("1")]),
        // Security function: 998 (encryption)
        deg1(de_text("998")),
        // Security role: 1 = ISS (issuer)
        deg1(de_text("1")),
        // Security identification: role=2(MS), cid=empty, system_id
        deg(vec![de_text("2"), de_empty(), de_text(system_id)]),
        // Security timestamp: type=1 (STS), date (YYYYMMDD), time (HHMMSS)
        {
            let now = Local::now();
            deg(vec![
                de_text("1"),
                de_text(&now.format("%Y%m%d").to_string()),
                de_text(&now.format("%H%M%S").to_string()),
            ])
        },
        // Encryption algorithm: dummy 2-key 3DES CBC
        // usage=2, op_mode=2, alg=13, key=@8@00000000, param_name=5, param_iv_name=1
        deg(vec![
            de_text("2"),
            de_text("2"),
            de_text("13"),
            de_binary(vec![0u8; 8]),
            de_text("5"),
            de_text("1"),
        ]),
        // Key name: country:blz:user_id:V(cipher):0:0
        deg(vec![
            de_text("280"),
            de_text(blz),
            de_text(user_id),
            de_text("V"),
            de_text("0"),
            de_text("0"),
        ]),
        // Compression: 0 = NULL
        deg1(de_text("0")),
    ]
}

// ---- HNVSD (Verschlüsselte Daten) - Encrypted Data Container, version 1 ----

/// Build HNVSD:999:1 wrapping inner segment bytes.
pub(crate) fn hnvsd(inner_bytes: &[u8]) -> Vec<DEG> {
    vec![
        seg_header("HNVSD", 999, 1),
        deg1(de_binary(inner_bytes.to_vec())),
    ]
}

// ---- HNSHK (Signaturkopf) - Signature Header, version 4 ----

/// Build HNSHK:n:4 with PinTan signature parameters.
pub(crate) fn hnshk(
    segment_number: u16,
    security_function: &str,
    security_reference: u32,
    blz: &str,
    user_id: &str,
    system_id: &str,
) -> Vec<DEG> {
    vec![
        seg_header("HNSHK", segment_number, 4),
        // Security profile: PIN:1
        deg(vec![de_text("PIN"), de_text("1")]),
        // Security function (e.g. "999" for one-step, "912" for pushTAN)
        deg1(de_text(security_function)),
        // Security reference (random number linking HNSHK <-> HNSHA)
        deg1(de_num(security_reference)),
        // Security application area: 1 = SHM
        deg1(de_text("1")),
        // Security role: 1 = ISS
        deg1(de_text("1")),
        // Security identification: role=2(MS), cid=empty, system_id
        deg(vec![de_text("2"), de_empty(), de_text(system_id)]),
        // Security reference number: 1
        deg1(de_text("1")),
        // Security timestamp: type=1 (STS), date (YYYYMMDD), time (HHMMSS)
        {
            let now = Local::now();
            deg(vec![
                de_text("1"),
                de_text(&now.format("%Y%m%d").to_string()),
                de_text(&now.format("%H%M%S").to_string()),
            ])
        },
        // Hash algorithm: dummy (usage=1, alg=999, param=1)
        deg(vec![de_text("1"), de_text("999"), de_text("1")]),
        // Signature algorithm: dummy (usage=6, alg=10, mode=16)
        deg(vec![de_text("6"), de_text("10"), de_text("16")]),
        // Key name: country:blz:user_id:S(signing):0:0
        deg(vec![
            de_text("280"),
            de_text(blz),
            de_text(user_id),
            de_text("S"),
            de_text("0"),
            de_text("0"),
        ]),
    ]
}

// ---- HNSHA (Signaturabschluss) - Signature Trailer, version 2 ----

/// Build HNSHA:n:2 with PIN and optional TAN.
pub(crate) fn hnsha(
    segment_number: u16,
    security_reference: u32,
    pin: &str,
    tan: Option<&str>,
) -> Vec<DEG> {
    let mut user_sig_elements = vec![de_text(pin)];
    if let Some(t) = tan {
        // For empty TAN (after decoupled confirmation), force an empty-but-present field.
        // de_text("") returns DataElement::Empty which the serializer omits entirely.
        // We need DataElement::Text("") to produce the ':' separator in the output.
        if t.is_empty() {
            user_sig_elements.push(crate::parser::DataElement::Text(String::new()));
        } else {
            user_sig_elements.push(de_text(t));
        }
    }
    vec![
        seg_header("HNSHA", segment_number, 2),
        // Security reference (must match HNSHK)
        deg1(de_num(security_reference)),
        // Validation result: empty
        deg1(de_empty()),
        // User defined signature: PIN[:TAN]
        deg(user_sig_elements),
    ]
}

// ---- HKIDN (Identifikation) - version 2 ----

pub(crate) fn hkidn(segment_number: u16, blz: &str, user_id: &str, system_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HKIDN", segment_number, 2),
        // Bank identifier: country(280):blz
        deg(vec![de_text("280"), de_text(blz)]),
        // Customer ID
        deg1(de_text(user_id)),
        // System ID (0 = not yet assigned)
        deg1(de_text(system_id)),
        // System ID required: 1
        deg1(de_text("1")),
    ]
}

// ---- HKVVB (Verarbeitungsvorbereitung) - Processing Preparation, version 3 ----

pub(crate) fn hkvvb(
    segment_number: u16,
    bpd_version: u16,
    upd_version: u16,
    product_id: &str,
) -> Vec<DEG> {
    vec![
        seg_header("HKVVB", segment_number, 3),
        // BPD version (0 = request full BPD)
        deg1(de_num(bpd_version)),
        // UPD version (0 = request full UPD)
        deg1(de_num(upd_version)),
        // Dialog language: 1 = German
        deg1(de_text("1")),
        // Product ID
        deg1(de_text(product_id)),
        // Product version
        deg1(de_text("1.0")),
    ]
}

// ---- HKSYN (Synchronisierung) - Synchronization, version 3 ----

/// Build HKSYN:n:3 to request a new system ID.
pub(crate) fn hksyn(segment_number: u16) -> Vec<DEG> {
    vec![
        seg_header("HKSYN", segment_number, 3),
        // Synchronization mode: 0 = request new system ID
        deg1(de_text("0")),
    ]
}

// ---- HKEND (Dialogende) - Dialog End, version 1 ----

pub(crate) fn hkend(segment_number: u16, dialog_id: &str) -> Vec<DEG> {
    vec![
        seg_header("HKEND", segment_number, 1),
        deg1(de_text(dialog_id)),
    ]
}

// ---- HKTAN (TAN-Verfahren) - TAN Segment, version 5-7 ----

/// The fields of HKTAN a read-only PIN/TAN client ever fills.
pub(crate) struct HktanRequest<'a> {
    /// TAN process: "4" (start SCA for a segment), "2" (submit TAN), "S" (decoupled status).
    pub process: &'a str,
    /// Segment the TAN is for (process 4 only), e.g. "HKIDN", "HKKAZ".
    pub segment_ref: Option<&'a str>,
    /// Task reference from HITAN (process 2 / S).
    pub task_reference: Option<&'a str>,
    /// "Weitere TAN folgt" — must be N for process 2/S, absent for process 4.
    pub further_tan_follows: Option<bool>,
    /// TAN medium name, when the method requires one.
    pub tan_medium: Option<&'a str>,
}

/// Build HKTAN per TAN2Step5/6/7.
///
/// ```text
/// v6/v7: process:segcode:account:orderhash:orderref:notlasttan:storno:smsaccount:challengeklass:klassparams:tanmedia
/// v5:    process:segcode:account:orderhash:orderref:listidx:notlasttan:storno:smsaccount:challengeklass:klassparams:tanmedia
/// ```
/// (shown colon-joined for brevity; on the wire these are separate DEGs.)
pub(crate) fn hktan(segment_number: u16, version: u16, req: &HktanRequest<'_>) -> Result<Vec<DEG>> {
    if !HKTAN_VERSIONS.contains(&version) {
        return Err(unsupported("HKTAN", version));
    }
    let mut degs = vec![
        seg_header("HKTAN", segment_number, version),
        deg1(de_text(req.process)),
        deg1(de_text(req.segment_ref.unwrap_or(""))),
        deg1(de_empty()), // order account
        deg1(de_empty()), // order hash
        deg1(de_text(req.task_reference.unwrap_or(""))),
    ];
    if version == 5 {
        degs.push(deg1(de_empty())); // TAN list index
    }
    degs.push(deg1(
        req.further_tan_follows
            .map(de_bool)
            .unwrap_or_else(de_empty),
    ));
    degs.push(deg1(de_empty())); // storno
    degs.push(deg1(de_empty())); // SMS charge account
    degs.push(deg1(de_empty())); // challenge class
    degs.push(deg1(de_empty())); // challenge class params
    degs.push(deg1(de_text(req.tan_medium.unwrap_or(""))));
    Ok(degs)
}

/// Build HKTAN for process 4 (request challenge) — used in dialog init and business segments.
pub(crate) fn hktan_process4(
    segment_number: u16,
    version: u16,
    segment_type: &str,
    tan_medium_name: Option<&str>,
) -> Result<Vec<DEG>> {
    hktan(
        segment_number,
        version,
        &HktanRequest {
            process: "4",
            segment_ref: Some(segment_type),
            task_reference: None,
            further_tan_follows: None,
            tan_medium: tan_medium_name,
        },
    )
}

/// Build HKTAN for process 2 (submit TAN) — completing a two-step operation.
pub(crate) fn hktan_process2(
    segment_number: u16,
    version: u16,
    task_reference: &str,
    tan_medium_name: Option<&str>,
) -> Result<Vec<DEG>> {
    hktan(
        segment_number,
        version,
        &HktanRequest {
            process: "2",
            segment_ref: None,
            task_reference: Some(task_reference),
            further_tan_follows: Some(false),
            tan_medium: tan_medium_name,
        },
    )
}

/// Build HKTAN for process S (decoupled status poll).
pub(crate) fn hktan_process_s(
    segment_number: u16,
    version: u16,
    task_reference: &str,
    tan_medium_name: Option<&str>,
) -> Result<Vec<DEG>> {
    hktan(
        segment_number,
        version,
        &HktanRequest {
            process: "S",
            segment_ref: None,
            task_reference: Some(task_reference),
            further_tan_follows: Some(false),
            tan_medium: tan_medium_name,
        },
    )
}

// ---- HKTAB (TAN-Medium anfordern) - TAN Media List Request, version 4/5 ----

/// Build HKTAB to request the list of registered TAN media (devices).
/// Returns HITAB response with device names needed for pushTAN.
pub(crate) fn hktab(segment_number: u16, version: u16) -> Vec<DEG> {
    vec![
        seg_header("HKTAB", segment_number, version),
        // TAN medium class: A = all
        deg1(de_text("A")),
    ]
}

// ---- HKSPA (SEPA-Kontoverbindung anfordern) - SEPA Account Info, version 1-3 ----

pub(crate) fn hkspa(segment_number: u16, version: u16) -> Vec<DEG> {
    vec![seg_header("HKSPA", segment_number, version)]
}

// ---- HKSAL (Saldenabfrage) - Balance Request, version 5-8 ----

/// Build HKSAL per Saldo5–8: `account+allaccounts(N)+maxentries+offset`.
/// v5 uses KTV2, v6 KTV3, v7/v8 KTVInt.
pub(crate) fn hksal(
    segment_number: u16,
    version: u16,
    account: &Account,
    touchdown: Option<&str>,
) -> Result<Vec<DEG>> {
    let acct = match version {
        5 | 6 => ktv(account, "HKSAL", version)?,
        7 | 8 => kti(account, "HKSAL", version)?,
        _ => return Err(unsupported("HKSAL", version)),
    };
    Ok(vec![
        seg_header("HKSAL", segment_number, version),
        acct,
        deg1(de_bool(false)),                   // all accounts
        deg1(de_empty()),                       // max entries
        deg1(de_text(touchdown.unwrap_or(""))), // touchdown point
    ])
}

// ---- HKKAZ (Kontoumsätze anfordern) - Statement Request (MT940), version 5-7 ----

/// Build HKKAZ per KUmsZeit5–7: `account+allaccounts(N)+start+end+maxentries+offset`.
/// v5 uses KTV2, v6 KTV3, v7 KTVInt.
pub(crate) fn hkkaz(
    segment_number: u16,
    version: u16,
    account: &Account,
    start_date: NaiveDate,
    end_date: NaiveDate,
    touchdown: Option<&str>,
) -> Result<Vec<DEG>> {
    let acct = match version {
        5 | 6 => ktv(account, "HKKAZ", version)?,
        7 => kti(account, "HKKAZ", version)?,
        _ => return Err(unsupported("HKKAZ", version)),
    };
    Ok(vec![
        seg_header("HKKAZ", segment_number, version),
        acct,
        deg1(de_bool(false)),
        deg1(de_date(start_date)),
        deg1(de_date(end_date)),
        deg1(de_empty()),                       // max entries
        deg1(de_text(touchdown.unwrap_or(""))), // touchdown point
    ])
}

// ---- HKWPD (Depotaufstellung anfordern) - Securities Holdings Request, version 5-6 ----

/// Build HKWPD per WPDepotList5/6: `depot+currency+quality+maxentries+offset`.
/// v5 uses KTV2, v6 KTV3 — the depot is always addressed by national account number.
/// The bank answers with HIWPD carrying an MT535 statement.
pub(crate) fn hkwpd(
    segment_number: u16,
    version: u16,
    account: &Account,
    currency: Option<&str>,
    touchdown: Option<&str>,
) -> Result<Vec<DEG>> {
    if !HKWPD_VERSIONS.contains(&version) {
        return Err(unsupported("HKWPD", version));
    }
    Ok(vec![
        seg_header("HKWPD", segment_number, version),
        ktv(account, "HKWPD", version)?,
        deg1(de_text(currency.unwrap_or(""))),
        deg1(de_empty()),                       // quality of prices
        deg1(de_empty()),                       // max entries
        deg1(de_text(touchdown.unwrap_or(""))), // touchdown point
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serializer::serialize_segment;

    const IBAN: &str = "DE04120300001084174299";
    const BIC: &str = "BYLADEM1001";

    fn account() -> Account {
        Account::new(IBAN, BIC).unwrap()
    }

    fn wire(degs: Vec<DEG>) -> String {
        String::from_utf8(serialize_segment(&degs).unwrap()).unwrap()
    }

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    // ── Account DEGs ───────────────────────────────────────────────────

    #[test]
    fn kti_serializes_as_iban_colon_bic() {
        let bytes =
            crate::serializer::serialize_deg(&kti(&account(), "HKSAL", 7).unwrap()).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), format!("{IBAN}:{BIC}"));
    }

    #[test]
    fn ktv_derives_number_and_blz_from_german_iban() {
        let bytes =
            crate::serializer::serialize_deg(&ktv(&account(), "HKSAL", 6).unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "1084174299::280:12030000"
        );
    }

    #[test]
    fn ktv_errors_without_national_data() {
        let foreign = Account::new("AT611904300234573201", "BKAUATWW").unwrap();
        let err = ktv(&foreign, "HKSAL", 6).unwrap_err();
        assert!(matches!(err, FinTSError::SegmentNotSupported(_)), "{err}");
    }

    #[test]
    fn national_only_account_builds_ktv_but_not_kti() {
        let depot =
            Account::national("0012345678", None, &Blz::new("50010517"), "INGDDEFFXXX").unwrap();
        assert_eq!(
            wire(hkwpd(3, 6, &depot, None, None).unwrap()),
            "HKWPD:3:6+0012345678::280:50010517'"
        );
        assert!(hksal(3, 7, &depot, None).is_err());
    }

    // ── HKSAL (Saldo5–8) ───────────────────────────────────────────────

    #[test]
    fn hksal_v5_wire_format() {
        assert_eq!(
            wire(hksal(3, 5, &account(), None).unwrap()),
            "HKSAL:3:5+1084174299::280:12030000+N'"
        );
    }

    #[test]
    fn hksal_v6_wire_format() {
        assert_eq!(
            wire(hksal(3, 6, &account(), None).unwrap()),
            "HKSAL:3:6+1084174299::280:12030000+N'"
        );
    }

    #[test]
    fn hksal_v7_wire_format() {
        assert_eq!(
            wire(hksal(3, 7, &account(), None).unwrap()),
            format!("HKSAL:3:7+{IBAN}:{BIC}+N'")
        );
    }

    #[test]
    fn hksal_v8_wire_format() {
        assert_eq!(
            wire(hksal(3, 8, &account(), None).unwrap()),
            format!("HKSAL:3:8+{IBAN}:{BIC}+N'")
        );
    }

    #[test]
    fn hksal_with_touchdown() {
        assert_eq!(
            wire(hksal(3, 7, &account(), Some("T1")).unwrap()),
            format!("HKSAL:3:7+{IBAN}:{BIC}+N++T1'")
        );
    }

    #[test]
    fn hksal_rejects_unknown_version() {
        assert!(hksal(3, 4, &account(), None).is_err());
        assert!(hksal(3, 9, &account(), None).is_err());
    }

    // ── HKKAZ (KUmsZeit5–7) ────────────────────────────────────────────

    #[test]
    fn hkkaz_v5_wire_format() {
        let degs = hkkaz(3, 5, &account(), date(2025, 3, 29), date(2026, 3, 29), None).unwrap();
        assert_eq!(
            wire(degs),
            "HKKAZ:3:5+1084174299::280:12030000+N+20250329+20260329'"
        );
    }

    #[test]
    fn hkkaz_v6_wire_format() {
        let degs = hkkaz(3, 6, &account(), date(2025, 3, 29), date(2026, 3, 29), None).unwrap();
        assert_eq!(
            wire(degs),
            "HKKAZ:3:6+1084174299::280:12030000+N+20250329+20260329'"
        );
    }

    #[test]
    fn hkkaz_v7_wire_format() {
        let degs = hkkaz(3, 7, &account(), date(2025, 3, 29), date(2026, 3, 29), None).unwrap();
        assert_eq!(
            wire(degs),
            format!("HKKAZ:3:7+{IBAN}:{BIC}+N+20250329+20260329'")
        );
    }

    #[test]
    fn hkkaz_v7_with_touchdown() {
        let degs = hkkaz(
            3,
            7,
            &account(),
            date(2025, 3, 29),
            date(2026, 3, 29),
            Some("4711"),
        )
        .unwrap();
        assert_eq!(
            wire(degs),
            format!("HKKAZ:3:7+{IBAN}:{BIC}+N+20250329+20260329++4711'")
        );
    }

    #[test]
    fn hkkaz_rejects_unknown_version() {
        assert!(hkkaz(3, 8, &account(), date(2025, 1, 1), date(2025, 2, 1), None).is_err());
    }

    // ── HKWPD (WPDepotList5/6) ─────────────────────────────────────────

    #[test]
    fn hkwpd_v5_wire_format() {
        assert_eq!(
            wire(hkwpd(3, 5, &account(), None, None).unwrap()),
            "HKWPD:3:5+1084174299::280:12030000'"
        );
    }

    #[test]
    fn hkwpd_v6_wire_format() {
        assert_eq!(
            wire(hkwpd(3, 6, &account(), None, None).unwrap()),
            "HKWPD:3:6+1084174299::280:12030000'"
        );
    }

    #[test]
    fn hkwpd_v6_with_currency() {
        assert_eq!(
            wire(hkwpd(3, 6, &account(), Some("EUR"), None).unwrap()),
            "HKWPD:3:6+1084174299::280:12030000+EUR'"
        );
    }

    #[test]
    fn hkwpd_v6_with_touchdown() {
        // depot + currency(empty) + quality(empty) + max_entries(empty) + touchdown
        assert_eq!(
            wire(hkwpd(3, 6, &account(), None, Some("TOUCH123")).unwrap()),
            "HKWPD:3:6+1084174299::280:12030000++++TOUCH123'"
        );
    }

    #[test]
    fn hkwpd_rejects_v7() {
        assert!(hkwpd(3, 7, &account(), None, None).is_err());
    }

    // ── HKTAN (TAN2Step5–7) ────────────────────────────────────────────

    #[test]
    fn hktan_v7_process4_wire_format() {
        assert_eq!(
            wire(hktan_process4(4, 7, "HKIDN", None).unwrap()),
            "HKTAN:4:7+4+HKIDN'"
        );
    }

    #[test]
    fn hktan_v7_process4_with_medium() {
        assert_eq!(
            wire(hktan_process4(4, 7, "HKKAZ", Some("iPhone")).unwrap()),
            "HKTAN:4:7+4+HKKAZ+++++++++iPhone'"
        );
    }

    #[test]
    fn hktan_v6_process_s_wire_format() {
        assert_eq!(
            wire(hktan_process_s(3, 6, "REF-1", None).unwrap()),
            "HKTAN:3:6+S++++REF-1+N'"
        );
    }

    #[test]
    fn hktan_v7_process2_wire_format() {
        assert_eq!(
            wire(hktan_process2(3, 7, "REF-1", None).unwrap()),
            "HKTAN:3:7+2++++REF-1+N'"
        );
    }

    #[test]
    fn hktan_v5_has_list_index_field() {
        // v5 inserts the TAN list index between order reference and "further TAN follows".
        assert_eq!(
            wire(hktan_process2(3, 5, "REF-1", None).unwrap()),
            "HKTAN:3:5+2++++REF-1++N'"
        );
        assert_eq!(
            wire(hktan_process4(3, 5, "HKIDN", Some("Handy")).unwrap()),
            "HKTAN:3:5+4+HKIDN++++++++++Handy'"
        );
    }

    #[test]
    fn hktan_rejects_v4() {
        assert!(hktan_process4(3, 4, "HKIDN", None).is_err());
    }
}
