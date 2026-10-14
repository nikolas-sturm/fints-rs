//! FinTS 3.0 protocol compliance auditing.
//!
//! Validates messages against FinTS 3.0 spec rules.
//! Used by both client (to audit servers) and server (to audit client requests).

use crate::parser::{parse_inner_segments, parse_message, RawSegment};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

// ── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationSeverity {
    /// Clear spec violation.
    Error,
    /// Potentially non-compliant.
    Warning,
    /// Notable but not necessarily wrong.
    Info,
}

impl ViolationSeverity {
    fn as_str(&self) -> &'static str {
        match self {
            ViolationSeverity::Error => "ERROR",
            ViolationSeverity::Warning => "WARNING",
            ViolationSeverity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub severity: ViolationSeverity,
    /// Short rule ID, e.g. "HNHBK-001".
    pub rule: String,
    /// Human-readable explanation.
    pub description: String,
    /// Which segment triggered this (if applicable).
    pub segment: Option<String>,
}

pub struct AuditReport {
    pub violations: Vec<Violation>,
    pub segments_checked: usize,
    pub timestamp: DateTime<Utc>,
}

impl AuditReport {
    pub fn has_errors(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count()
    }

    /// Produce a human-readable audit report.
    pub fn format_report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "FinTS Audit Report — {} — {} segments checked\n",
            self.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            self.segments_checked
        ));
        out.push_str(&format!(
            "  Errors: {}  Warnings: {}  Total violations: {}\n",
            self.error_count(),
            self.warning_count(),
            self.violations.len()
        ));

        if self.violations.is_empty() {
            out.push_str("  No violations found.\n");
        } else {
            out.push_str("  Violations:\n");
            for v in &self.violations {
                let seg_part = v
                    .segment
                    .as_deref()
                    .map(|s| format!(" [{}]", s))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "    [{:7}] {:12}{} — {}\n",
                    v.severity.as_str(),
                    v.rule,
                    seg_part,
                    v.description
                ));
            }
        }
        out
    }

    /// Produce a machine-readable JSON value.
    pub fn to_json(&self) -> Value {
        let violations: Vec<Value> = self
            .violations
            .iter()
            .map(|v| {
                json!({
                    "severity": v.severity.as_str(),
                    "rule": v.rule,
                    "description": v.description,
                    "segment": v.segment,
                })
            })
            .collect();

        json!({
            "timestamp": self.timestamp.to_rfc3339(),
            "segments_checked": self.segments_checked,
            "error_count": self.error_count(),
            "warning_count": self.warning_count(),
            "violations": violations,
        })
    }
}

// ── Public audit functions ────────────────────────────────────────────────────

/// Audit a client request message (sent by client to bank).
pub fn audit_client_message(data: &[u8]) -> AuditReport {
    let mut ctx = AuditContext::new();

    let segments = match parse_message(data) {
        Ok(s) => s,
        Err(e) => {
            ctx.add(
                ViolationSeverity::Error,
                "PARSE-001",
                &format!("Message could not be parsed: {}", e),
                None,
            );
            return ctx.finish(0);
        }
    };

    let count = segments.len();
    check_hnhbk_rules(&segments, &mut ctx);
    check_hnvsk_rules(&segments, &mut ctx);
    check_hnvsd_rules(&segments, &mut ctx, true);
    check_hnhbs_rule(&segments, &mut ctx);

    ctx.finish(count)
}

/// Audit a server response message (sent by bank to client).
pub fn audit_server_response(data: &[u8]) -> AuditReport {
    let mut ctx = AuditContext::new();

    let segments = match parse_message(data) {
        Ok(s) => s,
        Err(e) => {
            ctx.add(
                ViolationSeverity::Error,
                "PARSE-001",
                &format!("Message could not be parsed: {}", e),
                None,
            );
            return ctx.finish(0);
        }
    };

    let count = segments.len();
    check_hnhbk_rules(&segments, &mut ctx);
    check_hnvsk_rules(&segments, &mut ctx);
    check_hnvsd_rules(&segments, &mut ctx, false);
    check_hirmg_rules(&segments, &mut ctx);
    check_response_code_rules(&segments, &mut ctx);
    check_hnhbs_rule(&segments, &mut ctx);

    ctx.finish(count)
}

// ── Internal audit logic ──────────────────────────────────────────────────────

struct AuditContext {
    violations: Vec<Violation>,
}

impl AuditContext {
    fn new() -> Self {
        AuditContext {
            violations: Vec::new(),
        }
    }

    fn add(
        &mut self,
        severity: ViolationSeverity,
        rule: &str,
        description: &str,
        segment: Option<&str>,
    ) {
        self.violations.push(Violation {
            severity,
            rule: rule.to_string(),
            description: description.to_string(),
            segment: segment.map(str::to_string),
        });
    }

    fn finish(self, segments_checked: usize) -> AuditReport {
        AuditReport {
            violations: self.violations,
            segments_checked,
            timestamp: Utc::now(),
        }
    }
}

/// HNHBK-001..004
fn check_hnhbk_rules(segments: &[RawSegment], ctx: &mut AuditContext) {
    // HNHBK-001: Must have exactly one HNHBK, and it must be first.
    let hnhbk_count = segments
        .iter()
        .filter(|s| s.segment_type() == "HNHBK")
        .count();
    if hnhbk_count == 0 {
        ctx.add(
            ViolationSeverity::Error,
            "HNHBK-001",
            "Message has no HNHBK segment (must be first)",
            Some("HNHBK"),
        );
        return; // remaining HNHBK checks are moot
    }
    if hnhbk_count > 1 {
        ctx.add(
            ViolationSeverity::Error,
            "HNHBK-001",
            "Message has more than one HNHBK segment",
            Some("HNHBK"),
        );
    }
    let Some(hnhbk) = segments.first() else { return };
    if hnhbk.segment_type() != "HNHBK" {
        ctx.add(
            ViolationSeverity::Error,
            "HNHBK-001",
            "HNHBK is not the first segment",
            Some("HNHBK"),
        );
    }

    // HNHBK-002: Size field must be >= 50.
    let size_str = hnhbk.deg(1).get_str(0);
    match size_str.parse::<u64>() {
        Ok(size) if size < 50 => {
            ctx.add(
                ViolationSeverity::Error,
                "HNHBK-002",
                &format!("HNHBK size field is {} (must be >= 50)", size),
                Some("HNHBK"),
            );
        }
        Err(_) => {
            ctx.add(
                ViolationSeverity::Error,
                "HNHBK-002",
                &format!("HNHBK size field is not a valid number: {:?}", size_str),
                Some("HNHBK"),
            );
        }
        _ => {}
    }

    // HNHBK-003: FinTS version must be "300".
    let version = hnhbk.deg(3).get_str(0);
    if version != "300" {
        ctx.add(
            ViolationSeverity::Error,
            "HNHBK-003",
            &format!("FinTS version is {:?} (expected \"300\")", version),
            Some("HNHBK"),
        );
    }

    // HNHBK-004: Message number must be >= 1.
    let msg_num_str = hnhbk.deg(4).get_str(0);
    match msg_num_str.parse::<u64>() {
        Ok(n) if n < 1 => {
            ctx.add(
                ViolationSeverity::Error,
                "HNHBK-004",
                &format!("HNHBK message number is {} (must be >= 1)", n),
                Some("HNHBK"),
            );
        }
        Err(_) => {
            ctx.add(
                ViolationSeverity::Warning,
                "HNHBK-004",
                &format!(
                    "HNHBK message number is not a valid number: {:?}",
                    msg_num_str
                ),
                Some("HNHBK"),
            );
        }
        _ => {}
    }
}

/// HNVSK-001: Must have HNVSK at segment number 998.
fn check_hnvsk_rules(segments: &[RawSegment], ctx: &mut AuditContext) {
    let hnvsk = segments.iter().find(|s| s.segment_type() == "HNVSK");
    match hnvsk {
        None => {
            ctx.add(
                ViolationSeverity::Error,
                "HNVSK-001",
                "No HNVSK segment found",
                Some("HNVSK"),
            );
        }
        Some(seg) if seg.segment_number() != 998 => {
            ctx.add(
                ViolationSeverity::Error,
                "HNVSK-001",
                &format!(
                    "HNVSK segment number is {} (must be 998)",
                    seg.segment_number()
                ),
                Some("HNVSK"),
            );
        }
        _ => {}
    }
}

/// HNVSD-001, HNVSD-002, and inner segment rules.
fn check_hnvsd_rules(segments: &[RawSegment], ctx: &mut AuditContext, is_client: bool) {
    let Some(hnvsd) = segments.iter().find(|s| s.segment_type() == "HNVSD") else {
        ctx.add(
            ViolationSeverity::Error,
            "HNVSD-001",
            "No HNVSD segment found",
            Some("HNVSD"),
        );
        return;
    };
    if hnvsd.segment_number() != 999 {
        ctx.add(
            ViolationSeverity::Error,
            "HNVSD-001",
            &format!(
                "HNVSD segment number is {} (must be 999)",
                hnvsd.segment_number()
            ),
            Some("HNVSD"),
        );
    }

    // HNVSD-002: payload must be parseable.
    let payload_opt = hnvsd.deg(1).get(0).as_bytes().map(|b| b.to_vec());
    match payload_opt {
        None => {
            ctx.add(
                ViolationSeverity::Warning,
                "HNVSD-002",
                "HNVSD payload data element is not binary",
                Some("HNVSD"),
            );
        }
        Some(payload) => match parse_inner_segments(&payload) {
            Err(e) => {
                ctx.add(
                    ViolationSeverity::Error,
                    "HNVSD-002",
                    &format!("HNVSD payload is not parseable: {}", e),
                    Some("HNVSD"),
                );
            }
            Ok(inner) => {
                if is_client {
                    check_inner_client_rules(&inner, ctx);
                }
            }
        },
    }
}

/// HNSHK-001, HNSHA-001, HKIDN-001, HKVVB-001 (inner segment checks for client messages).
fn check_inner_client_rules(inner: &[RawSegment], ctx: &mut AuditContext) {
    let has_hnshk = inner.iter().any(|s| s.segment_type() == "HNSHK");
    if !has_hnshk {
        ctx.add(
            ViolationSeverity::Error,
            "HNSHK-001",
            "Inner segments (HNVSD payload) do not contain HNSHK",
            Some("HNSHK"),
        );
    }

    let has_hnsha = inner.iter().any(|s| s.segment_type() == "HNSHA");
    if !has_hnsha {
        ctx.add(
            ViolationSeverity::Error,
            "HNSHA-001",
            "Inner segments (HNVSD payload) do not contain HNSHA",
            Some("HNSHA"),
        );
    }

    let has_hkidn = inner.iter().any(|s| s.segment_type() == "HKIDN");
    if !has_hkidn {
        ctx.add(
            ViolationSeverity::Error,
            "HKIDN-001",
            "Inner segments (HNVSD payload) do not contain HKIDN",
            Some("HKIDN"),
        );
    }

    let has_hkvvb = inner.iter().any(|s| s.segment_type() == "HKVVB");
    if !has_hkvvb {
        ctx.add(
            ViolationSeverity::Error,
            "HKVVB-001",
            "Inner segments (HNVSD payload) do not contain HKVVB",
            Some("HKVVB"),
        );
    }
}

/// HNHBS-001: Last segment must be HNHBS.
fn check_hnhbs_rule(segments: &[RawSegment], ctx: &mut AuditContext) {
    match segments.last() {
        None => {
            ctx.add(
                ViolationSeverity::Error,
                "HNHBS-001",
                "Message has no segments",
                None,
            );
        }
        Some(last) if last.segment_type() != "HNHBS" => {
            ctx.add(
                ViolationSeverity::Error,
                "HNHBS-001",
                &format!("Last segment is {:?} (must be HNHBS)", last.segment_type()),
                Some("HNHBS"),
            );
        }
        _ => {}
    }
}

/// HIRMG-001, HIRMG-002.
fn check_hirmg_rules(segments: &[RawSegment], ctx: &mut AuditContext) {
    let hirmg_count = segments
        .iter()
        .filter(|s| s.segment_type() == "HIRMG")
        .count();

    if hirmg_count == 0 {
        ctx.add(
            ViolationSeverity::Error,
            "HIRMG-001",
            "Server response has no HIRMG segment",
            Some("HIRMG"),
        );
        return;
    }

    // HIRMG-002: Must have at least one response code.
    for seg in segments.iter().filter(|s| s.segment_type() == "HIRMG") {
        let data_degs: Vec<_> = seg.degs.iter().skip(1).collect();
        if data_degs.is_empty() {
            ctx.add(
                ViolationSeverity::Error,
                "HIRMG-002",
                "HIRMG has no response code DEGs",
                Some("HIRMG"),
            );
        }
    }
}

/// RESP-001, RESP-002: response code format rules.
fn check_response_code_rules(segments: &[RawSegment], ctx: &mut AuditContext) {
    let code_segs: Vec<_> = segments
        .iter()
        .filter(|s| s.segment_type() == "HIRMG" || s.segment_type() == "HIRMS")
        .collect();

    for seg in &code_segs {
        let is_global = seg.segment_type() == "HIRMG";
        let mut success_seen = false;
        let mut error_seen = false;

        for deg in seg.degs.iter().skip(1) {
            let code = deg.get_str(0);
            if code.is_empty() {
                continue;
            }

            // RESP-001: Code must be exactly 4 digits.
            if code.len() != 4 || !code.chars().all(|c| c.is_ascii_digit()) {
                ctx.add(
                    ViolationSeverity::Error,
                    "RESP-001",
                    &format!("Response code {:?} is not 4 digits", code),
                    Some(seg.segment_type()),
                );
            }

            // Track success vs error for RESP-002.
            if let Ok(n) = code.parse::<u16>() {
                if n < 3000 {
                    success_seen = true;
                } else if n >= 9000 {
                    error_seen = true;
                }
            }
        }

        // RESP-002: Must not have both success and error codes at global level.
        if is_global && success_seen && error_seen {
            ctx.add(
                ViolationSeverity::Warning,
                "RESP-002",
                "HIRMG contains both success (< 3000) and error (>= 9000) codes",
                Some("HIRMG"),
            );
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid outer wrapper without inner segments.
    fn minimal_outer(inner_payload: &[u8]) -> Vec<u8> {
        // HNHBK with size ~100, version 300, dialog 0, msg 1
        // HNVSK at seg 998
        // HNVSD at seg 999 with binary payload
        // HNHBS as last
        let payload_len = inner_payload.len();
        let hnvsd_part = format!("HNVSD:999:1+@{}@", payload_len);
        let mut msg = Vec::new();
        msg.extend_from_slice(b"HNHBK:1:3+000000000100+300+0+1+1'");
        msg.extend_from_slice(b"HNVSK:998:3+998+1+1::0+1:20200101:120000+2:2:13:@8@00000000:5:1+280:12345678:user:V:0:0+0'");
        msg.extend_from_slice(hnvsd_part.as_bytes());
        msg.extend_from_slice(inner_payload);
        msg.push(b'\'');
        msg.extend_from_slice(b"HNHBS:6:1+1'");
        msg
    }

    #[test]
    fn test_audit_client_no_hnhbk() {
        let data = b"HNHBS:5:1+1'";
        let report = audit_client_message(data);
        let rules: Vec<_> = report.violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"HNHBK-001"), "Expected HNHBK-001 violation");
    }

    #[test]
    fn test_audit_report_has_errors_and_warnings() {
        let data = b"HNHBS:5:1+1'";
        let report = audit_client_message(data);
        assert!(report.has_errors());
        assert!(report.error_count() > 0);
    }

    #[test]
    fn test_audit_report_format_contains_rule() {
        let data = b"HNHBS:5:1+1'";
        let report = audit_client_message(data);
        let formatted = report.format_report();
        assert!(formatted.contains("HNHBK-001"));
    }

    #[test]
    fn test_audit_report_to_json() {
        let data = b"HNHBS:5:1+1'";
        let report = audit_client_message(data);
        let json = report.to_json();
        assert!(json["violations"].is_array());
        assert!(json["error_count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_audit_server_response_missing_hirmg() {
        // A message with proper HNHBK but no HIRMG.
        let data =
            b"HNHBK:1:3+000000000100+300+0+1+1'HNVSK:998:3+1'HNVSD:999:1+@6@TEST:1'HNHBS:6:1+1'";
        let report = audit_server_response(data);
        let rules: Vec<_> = report.violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"HIRMG-001"), "Expected HIRMG-001 violation");
    }

    #[test]
    fn test_audit_hnhbs_must_be_last() {
        // HNHBS in the middle, not last.
        let data = b"HNHBK:1:3+000000000100+300+0+1+1'HNHBS:3:1+1'HIRMG:4:2+0010::OK.'";
        let report = audit_server_response(data);
        let rules: Vec<_> = report.violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"HNHBS-001"), "Expected HNHBS-001 violation");
    }

    #[test]
    fn test_audit_resp001_bad_code() {
        let data = b"HNHBK:1:3+000000000100+300+0+1+1'HIRMG:3:2+XYZ::Bad code.'HNHBS:4:1+1'";
        let report = audit_server_response(data);
        let rules: Vec<_> = report.violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"RESP-001"), "Expected RESP-001 violation");
    }

    #[test]
    fn test_hnhbk_version_rule() {
        // FinTS version 200 instead of 300.
        let data = b"HNHBK:1:3+000000000100+200+0+1+1'HNHBS:2:1+1'";
        let report = audit_client_message(data);
        let rules: Vec<_> = report.violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"HNHBK-003"), "Expected HNHBK-003 violation");
    }

    #[test]
    fn test_violation_severity_as_str() {
        assert_eq!(ViolationSeverity::Error.as_str(), "ERROR");
        assert_eq!(ViolationSeverity::Warning.as_str(), "WARNING");
        assert_eq!(ViolationSeverity::Info.as_str(), "INFO");
    }
}
