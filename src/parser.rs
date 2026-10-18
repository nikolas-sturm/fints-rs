//! FinTS wire format parser.
//!
//! Parses raw FinTS messages (bytes) into a structured 3-level representation:
//! - Level 1: Segments (separated by `'`)
//! - Level 2: Data Element Groups (separated by `+`)
//! - Level 3: Data Elements (separated by `:`)
//!
//! Handles `?`-escaping and `@N@`-prefixed binary data.

use crate::error::{FinTSError, Result};
use serde::{Deserialize, Serialize};

/// A single data element — either text or binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DataElement {
    /// Empty/missing data element.
    Empty,
    /// Text data element (decoded from ISO-8859-1).
    Text(String),
    /// Binary data element (raw bytes prefixed with @len@ in wire format).
    Binary(Vec<u8>),
}

impl DataElement {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            DataElement::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            DataElement::Text(s) => s.clone(),
            DataElement::Empty => String::new(),
            DataElement::Binary(b) => {
                // Try ISO-8859-1 decoding for binary
                let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(b);
                cow.into_owned()
            }
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            DataElement::Binary(b) => Some(b),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, DataElement::Empty)
    }
}

/// A Data Element Group: a list of data elements (colon-separated in wire format).
/// If the DEG contains only one element, it's still stored as a Vec of length 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DEG(pub Vec<DataElement>);

impl DEG {
    pub fn new() -> Self {
        DEG(Vec::new())
    }

    pub fn get(&self, index: usize) -> &DataElement {
        self.0.get(index).unwrap_or(&DataElement::Empty)
    }

    pub fn get_str(&self, index: usize) -> String {
        self.get(index).as_text()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty() || self.0.iter().all(|de| de.is_empty())
    }
}

/// A parsed segment: header info + list of DEGs (plus-separated in wire format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawSegment {
    pub degs: Vec<DEG>,
}

impl RawSegment {
    /// Get the segment type (e.g. "HNHBK", "HKIDN").
    pub fn segment_type(&self) -> &str {
        match self.degs.first().and_then(|deg| deg.0.first()) {
            Some(DataElement::Text(s)) => s.as_str(),
            _ => "",
        }
    }

    /// Get the segment number.
    pub fn segment_number(&self) -> u16 {
        self.degs
            .first()
            .and_then(|deg| deg.0.get(1))
            .and_then(|de| de.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Get the segment version.
    pub fn segment_version(&self) -> u16 {
        self.degs
            .first()
            .and_then(|deg| deg.0.get(2))
            .and_then(|de| de.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Get the segment reference (optional, for responses referencing a request segment).
    pub fn segment_reference(&self) -> Option<u16> {
        self.degs
            .first()
            .and_then(|deg| deg.0.get(3))
            .and_then(|de| de.as_str())
            .and_then(|s| s.parse().ok())
    }

    /// Get a DEG by index (0 = header DEG, 1 = first data DEG, etc.)
    pub fn deg(&self, index: usize) -> &DEG {
        static EMPTY: DEG = DEG(Vec::new());
        self.degs.get(index).unwrap_or(&EMPTY)
    }

    /// Number of DEGs in this segment (including the header).
    pub fn deg_count(&self) -> usize {
        self.degs.len()
    }
}

/// Parse a raw FinTS message (bytes, already base64-decoded) into a list of segments.
pub fn parse_message(data: &[u8]) -> Result<Vec<RawSegment>> {
    let mut segments = Vec::new();
    let mut pos = 0;
    let len = data.len();

    while pos < len {
        // Skip any leading whitespace/newlines
        while pos < len && (data[pos] == b'\r' || data[pos] == b'\n' || data[pos] == b' ') {
            pos += 1;
        }
        if pos >= len {
            break;
        }

        let (segment, new_pos) = parse_segment(data, pos)?;
        segments.push(segment);
        pos = new_pos;
    }

    Ok(segments)
}

/// Parse a single segment starting at `pos`, return the segment and the position after it.
fn parse_segment(data: &[u8], start: usize) -> Result<(RawSegment, usize)> {
    let mut degs: Vec<DEG> = Vec::new();
    let mut current_deg = DEG::new();
    let mut pos = start;
    let len = data.len();
    // After a colon separator, the next text must go into a new DE (not appended to previous).
    let mut need_new_de = true;

    // Note: HNVSD detection and inner-segment flattening is handled in
    // dialog.rs::parse_response(), not at the parser level.

    loop {
        if pos >= len {
            if !current_deg.0.is_empty() {
                degs.push(current_deg);
            }
            break;
        }

        match data[pos] {
            b'?' => {
                // Escape: next character is literal
                pos += 1;
                if pos >= len {
                    return Err(FinTSError::Parse(
                        "Unexpected end after escape character".into(),
                    ));
                }
                let ch = data[pos];
                let buf = [ch];
                let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(&buf);
                if need_new_de {
                    current_deg.0.push(DataElement::Text(cow.into_owned()));
                    need_new_de = false;
                } else {
                    append_text_to_de(&mut current_deg, &cow);
                }
                pos += 1;
            }
            b'@' => {
                // Binary data: @<length>@<bytes>
                pos += 1;
                let num_start = pos;
                while pos < len && data[pos] != b'@' {
                    pos += 1;
                }
                if pos >= len {
                    return Err(FinTSError::Parse(
                        "Unterminated binary length prefix".into(),
                    ));
                }
                let len_str = std::str::from_utf8(&data[num_start..pos])
                    .map_err(|e| FinTSError::Parse(format!("Invalid binary length: {}", e)))?;
                let bin_len: usize = len_str.parse().map_err(|e| {
                    FinTSError::Parse(format!("Invalid binary length number: {}", e))
                })?;
                pos += 1; // skip closing @

                if pos
                    .checked_add(bin_len)
                    .map_or(true, |end| end > data.len())
                {
                    return Err(FinTSError::Parse(format!(
                        "Binary data extends past end of message: need {} bytes at pos {}, only {} available",
                        bin_len, pos, data.len() - pos
                    )));
                }

                let binary_data = data[pos..pos + bin_len].to_vec();
                current_deg.0.push(DataElement::Binary(binary_data));
                need_new_de = false;
                pos += bin_len;
            }
            b':' => {
                // DE separator within a DEG — finalize current DE, start a new one
                if current_deg.0.is_empty() {
                    // No DE was started yet, the element before the colon is empty
                    current_deg.0.push(DataElement::Empty);
                }
                pos += 1;
                need_new_de = true;
                // If next is also a separator, insert an empty DE immediately
                if pos < len && (data[pos] == b':' || data[pos] == b'+' || data[pos] == b'\'') {
                    current_deg.0.push(DataElement::Empty);
                }
            }
            b'+' => {
                // DEG separator — finalize current DEG
                if current_deg.0.is_empty() {
                    current_deg.0.push(DataElement::Empty);
                }
                degs.push(current_deg);
                current_deg = DEG::new();
                need_new_de = true;
                pos += 1;
            }
            b'\'' => {
                // Segment terminator — finalize everything
                if current_deg.0.is_empty() {
                    current_deg.0.push(DataElement::Empty);
                }
                degs.push(current_deg);
                pos += 1;
                return Ok((RawSegment { degs }, pos));
            }
            _ => {
                // Regular character data — accumulate until next separator
                let char_start = pos;
                while pos < len
                    && data[pos] != b'?'
                    && data[pos] != b'@'
                    && data[pos] != b':'
                    && data[pos] != b'+'
                    && data[pos] != b'\''
                {
                    pos += 1;
                }
                let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(&data[char_start..pos]);
                if need_new_de {
                    current_deg.0.push(DataElement::Text(cow.into_owned()));
                    need_new_de = false;
                } else {
                    append_text_to_de(&mut current_deg, &cow);
                }
            }
        }
    }

    Ok((RawSegment { degs }, pos))
}

/// Helper: append text to the current data element being built in a DEG.
fn append_text_to_de(deg: &mut DEG, text: &str) {
    if let Some(DataElement::Text(ref mut s)) = deg.0.last_mut() {
        s.push_str(text);
    } else {
        deg.0.push(DataElement::Text(text.to_string()));
    }
}

/// Parse the inner segments from an HNVSD binary payload.
pub fn parse_inner_segments(data: &[u8]) -> Result<Vec<RawSegment>> {
    parse_message(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_segment() {
        let data = b"HNHBS:5:1+2'";
        let segments = parse_message(data).unwrap();
        assert_eq!(segments.len(), 1);
        let seg = &segments[0];
        assert_eq!(seg.segment_type(), "HNHBS");
        assert_eq!(seg.segment_number(), 5);
        assert_eq!(seg.segment_version(), 1);
        assert_eq!(seg.deg(1).get_str(0), "2");
    }

    #[test]
    fn test_parse_multiple_segments() {
        let data = b"HIRMG:3:2+0010::Nachricht entgegengenommen.'HNHBS:4:1+1'";
        let segments = parse_message(data).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].segment_type(), "HIRMG");
        assert_eq!(segments[1].segment_type(), "HNHBS");
    }

    #[test]
    fn test_parse_empty_des() {
        let data = b"HKTAN:5:7+4+HKIDN+++++++'";
        let segments = parse_message(data).unwrap();
        let seg = &segments[0];
        assert_eq!(seg.segment_type(), "HKTAN");
        assert_eq!(seg.deg(1).get_str(0), "4");
        assert_eq!(seg.deg(2).get_str(0), "HKIDN");
    }

    #[test]
    fn test_parse_deg_with_colons() {
        let data = b"HNSHK:2:4+PIN:1+999'";
        let segments = parse_message(data).unwrap();
        let seg = &segments[0];
        // DEG 1 = "PIN:1"
        assert_eq!(seg.deg(1).get_str(0), "PIN");
        assert_eq!(seg.deg(1).get_str(1), "1");
        // DEG 2 = "999"
        assert_eq!(seg.deg(2).get_str(0), "999");
    }

    #[test]
    fn test_parse_escaped_characters() {
        let data = b"TEST:1:1+Hello?+World?:Test?'End'";
        let segments = parse_message(data).unwrap();
        let seg = &segments[0];
        assert_eq!(seg.deg(1).get_str(0), "Hello+World:Test'End");
    }

    #[test]
    fn test_parse_binary_data() {
        let data = b"TEST:1:1+@5@HELLO+next'";
        let segments = parse_message(data).unwrap();
        let seg = &segments[0];
        assert_eq!(seg.deg(1).get(0).as_bytes().unwrap(), b"HELLO");
        assert_eq!(seg.deg(2).get_str(0), "next");
    }

    #[test]
    fn test_segment_header_with_reference() {
        let data = b"HIRMS:4:2:3+0010::Nachricht entgegengenommen.'";
        let segments = parse_message(data).unwrap();
        let seg = &segments[0];
        assert_eq!(seg.segment_type(), "HIRMS");
        assert_eq!(seg.segment_number(), 4);
        assert_eq!(seg.segment_version(), 2);
        assert_eq!(seg.segment_reference(), Some(3));
    }
}
