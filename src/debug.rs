//! Protocol debugging and wire format inspection utilities.
//!
//! Used by both the CLI client and mock server for detailed logging.

use crate::error::FinTSError;
use crate::parser::{parse_message, DataElement};

// ── Public types ─────────────────────────────────────────────────────────────

/// Controls how much detail is emitted in formatted output.
pub enum VerbosityLevel {
    /// Only show segment type names.
    Minimal,
    /// Show segment types + data element values (no binary hex).
    Segments,
    /// Show everything including binary hex dumps.
    Full,
}

/// A decoded FinTS segment ready for display.
pub struct DecodedSegment {
    pub segment_type: String,
    pub segment_number: u16,
    pub segment_version: u16,
    pub segment_reference: Option<u16>,
    /// DEGs → DEs as display strings.
    pub degs: Vec<Vec<String>>,
}

/// A decoded FinTS message ready for human display.
pub struct DecodedMessage {
    pub segments: Vec<DecodedSegment>,
    /// Global-level response codes: (code, text).
    pub global_codes: Vec<(String, String)>,
    /// Segment-level response codes: (code, text).
    pub segment_codes: Vec<(String, String)>,
    pub raw_bytes: usize,
}

// ── Core public functions ─────────────────────────────────────────────────────

/// Parse raw bytes into a [`DecodedMessage`].
pub fn decode_message(data: &[u8]) -> Result<DecodedMessage, FinTSError> {
    let data = &redact_credentials(data);
    let raw_segments = parse_message(data)?;
    let raw_bytes = data.len();

    let mut segments: Vec<DecodedSegment> = Vec::new();
    let mut global_codes: Vec<(String, String)> = Vec::new();
    let mut segment_codes: Vec<(String, String)> = Vec::new();

    for raw in &raw_segments {
        let seg_type = raw.segment_type().to_string();
        let seg_num = raw.segment_number();
        let seg_ver = raw.segment_version();
        let seg_ref = raw.segment_reference();

        // Build display-string DEGs (skip header DEG 0).
        let degs: Vec<Vec<String>> = raw
            .degs
            .iter()
            .skip(1)
            .map(|deg| {
                deg.0
                    .iter()
                    .map(|de| de_to_display_string(de, &seg_type, VerbosityLevel::Full))
                    .collect()
            })
            .collect();

        // Collect response codes from HIRMG and HIRMS.
        match seg_type.as_str() {
            "HIRMG" => {
                for deg in raw.degs.iter().skip(1) {
                    let code = deg.get_str(0);
                    let text = deg.get_str(2);
                    if !code.is_empty() {
                        global_codes.push((code, text));
                    }
                }
            }
            "HIRMS" => {
                for deg in raw.degs.iter().skip(1) {
                    let code = deg.get_str(0);
                    let text = deg.get_str(2);
                    if !code.is_empty() {
                        segment_codes.push((code, text));
                    }
                }
            }
            _ => {}
        }

        segments.push(DecodedSegment {
            segment_type: seg_type,
            segment_number: seg_num,
            segment_version: seg_ver,
            segment_reference: seg_ref,
            degs,
        });
    }

    Ok(DecodedMessage {
        segments,
        global_codes,
        segment_codes,
        raw_bytes,
    })
}

/// Produce a human-readable multi-line string for a [`DecodedMessage`].
pub fn format_decoded(msg: &DecodedMessage, verbosity: VerbosityLevel) -> String {
    let mut out = String::new();

    out.push_str(&format!("FinTS message ({} bytes)\n", msg.raw_bytes));

    if !msg.global_codes.is_empty() {
        out.push_str("  Global codes:\n");
        for (code, text) in &msg.global_codes {
            out.push_str(&format!("    {} — {}\n", code, text));
        }
    }
    if !msg.segment_codes.is_empty() {
        out.push_str("  Segment codes:\n");
        for (code, text) in &msg.segment_codes {
            out.push_str(&format!("    {} — {}\n", code, text));
        }
    }

    out.push_str("  Segments:\n");
    for seg in &msg.segments {
        match verbosity {
            VerbosityLevel::Minimal => {
                out.push_str(&format!("    {}\n", seg.segment_type));
            }
            VerbosityLevel::Segments | VerbosityLevel::Full => {
                let ref_part = seg
                    .segment_reference
                    .map(|r| format!(":{}", r))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "    {}:{}:{}{}",
                    seg.segment_type, seg.segment_number, seg.segment_version, ref_part
                ));

                for deg in &seg.degs {
                    let deg_str = deg.join(":");
                    out.push_str(&format!(" + {}", deg_str));
                }
                out.push('\n');
            }
        }
    }

    out
}

/// Classic hex dump: 16 bytes per line, offset | hex | ascii.
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let offset = chunk_idx * 16;
        // Offset column
        out.push_str(&format!("{:08x}  ", offset));
        // Hex columns
        for (i, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", byte));
            if i == 7 {
                out.push(' ');
            }
        }
        // Padding if last line is short
        if chunk.len() < 16 {
            let missing = 16 - chunk.len();
            for i in 0..missing {
                out.push_str("   ");
                if chunk.len() + i == 7 {
                    out.push(' ');
                }
            }
        }
        out.push_str(" |");
        // ASCII column
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

/// Combine a label + optional hex dump + decoded segments.
pub fn format_wire_log(label: &str, data: &[u8], verbosity: VerbosityLevel) -> String {
    let data = &redact_credentials(data);
    let mut out = String::new();
    out.push_str(&format!("=== {} ({} bytes) ===\n", label, data.len()));

    if matches!(verbosity, VerbosityLevel::Full) {
        out.push_str(&hex_dump(data));
        out.push('\n');
    }

    match decode_message(data) {
        Ok(msg) => out.push_str(&format_decoded(&msg, verbosity)),
        Err(e) => out.push_str(&format!("  [parse error: {}]\n", e)),
    }

    out
}

/// Mask PIN and TAN in a FinTS message for logging and display.
///
/// Both travel in the user-defined signature of HNSHA
/// (`HNSHA:n:2+<ref>++<PIN>[:<TAN>]'`), which sits as plain bytes inside the
/// HNVSD envelope. Every byte of that element becomes `*` except the `:`
/// separator; the length stays the same, so `@len@` binary headers still
/// match and the result still parses.
pub fn redact_credentials(message: &[u8]) -> Vec<u8> {
    const TAG: &[u8] = b"HNSHA:";
    let mut out = message.to_vec();
    let mut i = 0;
    while let Some(pos) = out[i..].windows(TAG.len()).position(|w| w == TAG) {
        let mut j = i + pos + TAG.len();
        let mut element = 0; // data elements are separated by unescaped '+'
        while j < out.len() {
            match out[j] {
                b'\'' => break,
                b'+' => element += 1,
                b':' if element >= 3 => {}
                b'?' => {
                    // Escape: the next byte is literal.
                    if element >= 3 {
                        out[j] = b'*';
                        if let Some(next) = out.get_mut(j + 1) {
                            *next = b'*';
                        }
                    }
                    j += 1;
                }
                _ if element >= 3 => out[j] = b'*',
                _ => {}
            }
            j += 1;
        }
        i = j;
    }
    out
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Convert a single `DataElement` to a display string, respecting verbosity
/// and applying HNSHA redaction.
fn de_to_display_string(de: &DataElement, seg_type: &str, verbosity: VerbosityLevel) -> String {
    match de {
        DataElement::Empty => String::new(),
        DataElement::Text(s) => s.clone(),
        DataElement::Binary(b) => {
            if seg_type == "HNSHA" {
                return "[REDACTED IN HNSHA]".to_string();
            }
            match verbosity {
                VerbosityLevel::Minimal | VerbosityLevel::Segments => {
                    format!("[BINARY: {} bytes]", b.len())
                }
                VerbosityLevel::Full => {
                    let hex: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
                    format!("[BINARY: {}]", hex)
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_pin_and_tan_inside_the_envelope() {
        let inner = "HNSHK:2:4+PIN:2+942+123+1+1+2::SYS+1+1:999:1+6:10:16+280:12345678:user:S:0:0'\
                     HKIDN:3:2+280:12345678+user+SYS+1'\
                     HNSHA:4:2+123++ge?+heim:654321'";
        let message = format!(
            "HNHBK:1:3+000000000000+300+0+1'HNVSK:998:3+PIN:2+998+1+1::SYS+1:20260101:120000+2:2:13:@8@00000000:5:1+280:12345678:user:V:0:0+0'\
             HNVSD:999:1+@{}@{}'HNHBS:5:1+1'",
            inner.len(),
            inner
        );
        let redacted = redact_credentials(message.as_bytes());
        let text = String::from_utf8_lossy(&redacted);
        assert_eq!(redacted.len(), message.len());
        assert!(!text.contains("heim") && !text.contains("654321"), "{text}");
        assert!(text.contains("HNSHA:4:2+123++********:******'"), "{text}");
        assert!(text.contains("HKIDN:3:2+280:12345678+user+SYS+1'"), "other segments untouched");
        assert!(decode_message(message.as_bytes()).is_ok(), "still parses after masking");
    }

    #[test]
    fn redaction_leaves_messages_without_hnsha_alone() {
        let data = b"HIRMG:3:2+0010::Nachricht entgegengenommen.'HNHBS:4:1+1'";
        assert_eq!(redact_credentials(data), data.to_vec());
    }

    #[test]
    fn test_decode_simple_message() {
        let data = b"HNHBS:5:1+2'";
        let msg = decode_message(data).expect("decode should succeed");
        assert_eq!(msg.segments.len(), 1);
        assert_eq!(msg.segments[0].segment_type, "HNHBS");
        assert_eq!(msg.segments[0].segment_number, 5);
        assert_eq!(msg.raw_bytes, 12);
    }

    #[test]
    fn test_decode_collects_global_codes() {
        let data = b"HIRMG:3:2+0010::Nachricht entgegengenommen.'HNHBS:4:1+1'";
        let msg = decode_message(data).expect("decode should succeed");
        assert_eq!(msg.global_codes.len(), 1);
        assert_eq!(msg.global_codes[0].0, "0010");
        assert_eq!(msg.global_codes[0].1, "Nachricht entgegengenommen.");
    }

    #[test]
    fn test_format_minimal_verbosity() {
        let data = b"HNHBS:5:1+2'";
        let msg = decode_message(data).expect("decode should succeed");
        let formatted = format_decoded(&msg, VerbosityLevel::Minimal);
        assert!(formatted.contains("HNHBS"));
        // Minimal should not show segment numbers inline with data
        assert!(!formatted.contains("HNHBS:5:1"));
    }

    #[test]
    fn test_format_segments_verbosity() {
        let data = b"HNHBS:5:1+2'";
        let msg = decode_message(data).expect("decode should succeed");
        let formatted = format_decoded(&msg, VerbosityLevel::Segments);
        assert!(formatted.contains("HNHBS:5:1"));
        assert!(formatted.contains("+ 2"));
    }

    #[test]
    fn test_hex_dump_format() {
        let data = b"HNHBS:5:1";
        let dump = hex_dump(data);
        // Should start with offset 00000000
        assert!(dump.starts_with("00000000"));
        // Should have a pipe-delimited ASCII column
        assert!(dump.contains('|'));
        assert!(dump.contains("HNHBS:5:1"));
    }

    #[test]
    fn test_binary_redacted_in_hnsha() {
        let binary = DataElement::Binary(b"secret_pin".to_vec());
        let display = de_to_display_string(&binary, "HNSHA", VerbosityLevel::Full);
        assert_eq!(display, "[REDACTED IN HNSHA]");
    }

    #[test]
    fn test_binary_shown_at_full_verbosity() {
        let binary = DataElement::Binary(vec![0xde, 0xad]);
        let display = de_to_display_string(&binary, "HNVSD", VerbosityLevel::Full);
        assert!(display.contains("dead"));
    }

    #[test]
    fn test_binary_shown_as_size_at_segments_verbosity() {
        let binary = DataElement::Binary(vec![0u8; 42]);
        let display = de_to_display_string(&binary, "HNVSD", VerbosityLevel::Segments);
        assert_eq!(display, "[BINARY: 42 bytes]");
    }

    #[test]
    fn test_format_wire_log_contains_label() {
        let data = b"HNHBS:5:1+2'";
        let log = format_wire_log("OUTBOUND", data, VerbosityLevel::Minimal);
        assert!(log.contains("OUTBOUND"));
        assert!(log.contains("12 bytes"));
    }

    #[test]
    fn test_decode_message_with_segment_reference() {
        let data = b"HIRMS:4:2:3+0010::Nachricht entgegengenommen.'";
        let msg = decode_message(data).expect("decode should succeed");
        assert_eq!(msg.segments[0].segment_reference, Some(3));
        assert_eq!(msg.segment_codes.len(), 1);
    }
}
