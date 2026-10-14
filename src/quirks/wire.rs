//! Lossless byte-level view of the FinTS wire format.
//!
//! Quirks patch messages that the regular parser may not even accept, so they
//! work on raw bytes. These helpers find segment / DEG / DE boundaries while
//! honoring `?` escapes and `@len@` binary data, and never panic: malformed
//! binary markers are treated as plain characters.

use std::ops::Range;

/// Split `data` at unescaped `sep` bytes outside binary data.
///
/// Returns the ranges between separators (separators excluded). With
/// `keep_sep`, each range includes its trailing separator (used for
/// segments, which end in `'`). A trailing remainder without separator is
/// returned as the last range if non-empty.
fn split(data: &[u8], sep: u8, keep_sep: bool) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'?' => i += 2,
            b'@' => i = skip_binary(data, i).unwrap_or(i + 1),
            b if b == sep => {
                ranges.push(start..if keep_sep { i + 1 } else { i });
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < data.len() {
        ranges.push(start..data.len());
    }
    ranges
}

/// If `data[at]` starts a well-formed `@len@bytes` element, return the index
/// just past it.
fn skip_binary(data: &[u8], at: usize) -> Option<usize> {
    let digits_start = at + 1;
    let digits_len = data.get(digits_start..)?.iter().position(|b| !b.is_ascii_digit())?;
    if digits_len == 0 || data.get(digits_start + digits_len) != Some(&b'@') {
        return None;
    }
    let len: usize = std::str::from_utf8(&data[digits_start..digits_start + digits_len]).ok()?.parse().ok()?;
    let end = (digits_start + digits_len + 1).checked_add(len)?;
    (end <= data.len()).then_some(end)
}

/// Byte ranges of all segments, each including its terminating `'`.
/// Leading CR/LF/space between segments is skipped.
pub(crate) fn segments(msg: &[u8]) -> Vec<Range<usize>> {
    split(msg, b'\'', true)
        .into_iter()
        .map(|r| {
            let skip = msg[r.clone()].iter().take_while(|b| matches!(b, b'\r' | b'\n' | b' ')).count();
            r.start + skip..r.end
        })
        .filter(|r| !r.is_empty())
        .collect()
}

/// Byte ranges of the DEGs of one segment (relative to `seg`, terminator excluded).
pub(crate) fn degs(seg: &[u8]) -> Vec<Range<usize>> {
    let body = seg.strip_suffix(b"'").unwrap_or(seg);
    let mut ranges = split(body, b'+', false);
    // "A+" yields only "A" from split; keep the empty trailing DEG explicit.
    if body.last() == Some(&b'+') {
        ranges.push(body.len()..body.len());
    }
    ranges
}

/// Byte ranges of the DEs of one DEG (relative to `deg`).
pub(crate) fn des(deg: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = split(deg, b':', false);
    if deg.last() == Some(&b':') {
        ranges.push(deg.len()..deg.len());
    }
    ranges
}

/// Segment type of a raw segment (first DE), e.g. `HNHBK`.
pub(crate) fn segment_type(seg: &[u8]) -> &[u8] {
    let end = seg.iter().position(|b| matches!(b, b':' | b'+' | b'\'')).unwrap_or(seg.len());
    &seg[..end]
}

/// Payload of a binary DE (`@len@bytes`), if `de` is exactly one.
pub(crate) fn binary_payload(de: &[u8]) -> Option<&[u8]> {
    if de.first() != Some(&b'@') {
        return None;
    }
    let end = skip_binary(de, 0)?;
    if end != de.len() {
        return None;
    }
    let header_len = de[1..].iter().position(|b| *b == b'@')? + 2;
    Some(&de[header_len..])
}

/// Replace `range` in `data` with `with`.
pub(crate) fn splice(data: &[u8], range: Range<usize>, with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + with.len());
    out.extend_from_slice(&data[..range.start]);
    out.extend_from_slice(with);
    out.extend_from_slice(&data[range.end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts<'a>(data: &'a [u8], ranges: &[Range<usize>]) -> Vec<&'a str> {
        ranges.iter().map(|r| std::str::from_utf8(&data[r.clone()]).unwrap()).collect()
    }

    #[test]
    fn splits_segments_respecting_escapes_and_binary() {
        let msg = b"HNHBK:1:3+1'HIRMG:2:2+0010::a?'b'HNVSD:999:1+@5@x'y'z'HNHBS:4:1+1'";
        let segs = segments(msg);
        assert_eq!(
            texts(msg, &segs),
            ["HNHBK:1:3+1'", "HIRMG:2:2+0010::a?'b'", "HNVSD:999:1+@5@x'y'z'", "HNHBS:4:1+1'"]
        );
    }

    #[test]
    fn splits_degs_and_des() {
        let seg = b"HIRMS:3:2:4+0020::ok?+fine+3040::more:TD1'";
        let d = degs(seg);
        assert_eq!(texts(seg, &d), ["HIRMS:3:2:4", "0020::ok?+fine", "3040::more:TD1"]);
        let deg = &seg[d[2].clone()];
        assert_eq!(texts(deg, &des(deg)), ["3040", "", "more", "TD1"]);
        assert_eq!(texts(b"A:", &des(b"A:")), ["A", ""]);
    }

    #[test]
    fn binary_payload_extracts_bytes() {
        assert_eq!(binary_payload(b"@3@a'b"), Some(&b"a'b"[..]));
        assert_eq!(binary_payload(b"@3@ab"), None);
        assert_eq!(binary_payload(b"text"), None);
    }

    #[test]
    fn malformed_binary_markers_do_not_panic() {
        for msg in [&b"A+@"[..], b"A+@99@x'", b"A+@x@'", b"@", b"?", b"A+@18446744073709551615@'"] {
            let _ = segments(msg);
            let _ = degs(msg);
            let _ = binary_payload(msg);
        }
    }
}
