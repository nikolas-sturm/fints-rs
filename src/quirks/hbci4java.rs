// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Ported from hbci4java (https://github.com/hbci4j/hbci4java),
// package org.kapott.hbci.rewrite:
//   RInvalidSegment, RWrongStatusSegOrder, RWrongSequenceNumbers,
//   RMissingMsgRef, RHBCIVersion, RSigIdLeadingZero,
//   RInvalidSuppHBCIVersion, RSecTypeTAN
// Copyright (c) 2001-2008 Stefan Palme and the hbci4java contributors.
//
// This file is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 2.1 of the License, or (at your option)
// any later version. It is distributed WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
// the GNU Lesser General Public License for more details (LICENSES/LGPL-2.1.txt).
//
// Unlike the rest of this crate (MIT), this file is LGPL-2.1-or-later. See NOTICE.

//! hbci4java's default rewriters, ported to the [`Quirk`] trait.
//!
//! Each works on raw bytes via the `wire` helpers and returns the input
//! unchanged (`Cow::Borrowed`) when the message is already correct.
//! Deviations from the Java originals are noted per type; they only make the
//! port stricter about when to touch a message, never broader.

use std::borrow::Cow;

use super::wire;
use super::{Quirk, QuirkContext};

// ── helpers ────────────────────────────────────────────────────────────────

/// Raw segments of a message as byte slices.
fn split_segments(msg: &[u8]) -> Vec<&[u8]> {
    wire::segments(msg).into_iter().map(|r| &msg[r]).collect()
}

/// Join segments; `Borrowed` if the result equals the input.
fn rebuild<'a>(original: &'a [u8], segments: &[Cow<'_, [u8]>]) -> Cow<'a, [u8]> {
    let out: Vec<u8> = segments.iter().flat_map(|s| s.iter().copied()).collect();
    if out == original {
        Cow::Borrowed(original)
    } else {
        Cow::Owned(out)
    }
}

/// Replace DE `de_idx` of DEG `deg_idx` in a raw segment.
fn replace_de(seg: &[u8], deg_idx: usize, de_idx: usize, value: &[u8]) -> Option<Vec<u8>> {
    let deg = wire::degs(seg).get(deg_idx)?.clone();
    let de = wire::des(&seg[deg.clone()]).get(de_idx)?.clone();
    Some(wire::splice(
        seg,
        deg.start + de.start..deg.start + de.end,
        value,
    ))
}

/// Text of DE `de_idx` of DEG `deg_idx` (raw bytes, escapes untouched).
fn de_bytes(seg: &[u8], deg_idx: usize, de_idx: usize) -> Option<&[u8]> {
    let deg = wire::degs(seg).get(deg_idx)?.clone();
    let deg_bytes = &seg[deg];
    let de = wire::des(deg_bytes).get(de_idx)?.clone();
    Some(&deg_bytes[de])
}

/// Segment version from its header, if numeric.
fn segment_version(seg: &[u8]) -> Option<u16> {
    std::str::from_utf8(de_bytes(seg, 0, 2)?).ok()?.parse().ok()
}

// ── RInvalidSegment ────────────────────────────────────────────────────────

/// Removes stray `IIDIA` segments some banks emit.
///
/// Port of `RInvalidSegment`. The original removes the first `IIDIA` found
/// after a segment end; this removes every `IIDIA` segment.
pub struct InvalidSegment;

impl Quirk for InvalidSegment {
    fn name(&self) -> &'static str {
        "InvalidSegment"
    }

    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let segs: Vec<Cow<[u8]>> = split_segments(msg)
            .into_iter()
            .filter(|s| wire::segment_type(s) != b"IIDIA")
            .map(Cow::Borrowed)
            .collect();
        rebuild(msg, &segs)
    }
}

// ── RWrongStatusSegOrder ───────────────────────────────────────────────────

/// Restores the required order header (HNHBK, HNSHK) → HIRMG → HIRMS → data.
///
/// Port of `RWrongStatusSegOrder`, same state machine. Must run before
/// [`WrongSequenceNumbers`], which fixes the numbering afterwards.
pub struct WrongStatusSegOrder;

impl Quirk for WrongStatusSegOrder {
    fn name(&self) -> &'static str {
        "WrongStatusSegOrder"
    }

    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let (mut header, mut glob, mut seg_status, mut data) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let (mut in_header, mut in_glob, mut in_seg, mut in_data) = (true, false, false, false);
        let mut error = false;

        for seg in split_segments(msg) {
            match wire::segment_type(seg) {
                b"HNHBK" | b"HNSHK" => {
                    header.push(seg);
                    error |= !in_header;
                }
                b"HIRMG" => {
                    glob.push(seg);
                    if in_header {
                        in_header = false;
                        in_glob = true;
                    }
                    error |= !in_glob;
                }
                b"HIRMS" => {
                    seg_status.push(seg);
                    if in_glob {
                        in_glob = false;
                        in_seg = true;
                    }
                    error |= !in_seg;
                }
                _ => {
                    data.push(seg);
                    if in_glob || in_seg {
                        in_glob = false;
                        in_seg = false;
                        in_data = true;
                    }
                    error |= !in_data;
                }
            }
        }
        if !error {
            return Cow::Borrowed(msg);
        }
        let ordered: Vec<Cow<[u8]>> = header
            .into_iter()
            .chain(glob)
            .chain(seg_status)
            .chain(data)
            .map(Cow::Borrowed)
            .collect();
        rebuild(msg, &ordered)
    }
}

// ── RWrongSequenceNumbers ──────────────────────────────────────────────────

/// Renumbers segments 1, 2, 3, … in message order (binary data is skipped
/// by the wire scanner, as in the original).
///
/// Port of `RWrongSequenceNumbers`. The original throws on a non-numeric
/// sequence number; this replaces it like any other wrong number.
pub struct WrongSequenceNumbers;

impl Quirk for WrongSequenceNumbers {
    fn name(&self) -> &'static str {
        "WrongSequenceNumbers"
    }

    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let segs: Vec<Cow<[u8]>> = split_segments(msg)
            .into_iter()
            .enumerate()
            .map(|(i, seg)| {
                let expected = (i + 1).to_string();
                match de_bytes(seg, 0, 1) {
                    Some(seq) if seq != expected.as_bytes() => {
                        replace_de(seg, 0, 1, expected.as_bytes())
                            .map(Cow::Owned)
                            .unwrap_or(Cow::Borrowed(seg))
                    }
                    _ => Cow::Borrowed(seg),
                }
            })
            .collect();
        rebuild(msg, &segs)
    }
}

// ── RMissingMsgRef ─────────────────────────────────────────────────────────

/// Adds the missing message reference (`dialogID:msgnum` of our request) to HNHBK.
///
/// Port of `RMissingMsgRef` (an `incomingCrypted` rewriter). The original
/// appends whenever HNHBK has fewer than six DEGs; this only does so when
/// exactly the reference is missing.
pub struct MissingMsgRef;

impl Quirk for MissingMsgRef {
    fn name(&self) -> &'static str {
        "MissingMsgRef"
    }

    fn incoming_raw<'a>(&self, msg: &'a [u8], ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let Some(first) = wire::segments(msg).into_iter().next() else {
            return Cow::Borrowed(msg);
        };
        let seg = &msg[first.clone()];
        if wire::segment_type(seg) != b"HNHBK" || wire::degs(seg).len() != 5 {
            return Cow::Borrowed(msg);
        }
        let reference = format!("+{}:{}", ctx.dialog_id, ctx.message_number);
        let insert_at = first.end - 1; // before the terminating '
        if msg.get(insert_at) != Some(&b'\'') {
            return Cow::Borrowed(msg);
        }
        Cow::Owned(wire::splice(
            msg,
            insert_at..insert_at,
            reference.as_bytes(),
        ))
    }
}

// ── RHBCIVersion ───────────────────────────────────────────────────────────

/// Restores a missing or `0` HBCI version in HNHBK with the one we sent.
///
/// Port of `RHBCIVersion` (an `incomingCrypted` rewriter).
pub struct HbciVersion;

impl Quirk for HbciVersion {
    fn name(&self) -> &'static str {
        "HBCIVersion"
    }

    fn incoming_raw<'a>(&self, msg: &'a [u8], ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let Some(first) = wire::segments(msg).into_iter().next() else {
            return Cow::Borrowed(msg);
        };
        let seg = &msg[first.clone()];
        if wire::segment_type(seg) != b"HNHBK" {
            return Cow::Borrowed(msg);
        }
        let Some(deg) = wire::degs(seg).get(2).cloned() else {
            return Cow::Borrowed(msg);
        };
        let version = &seg[deg.clone()];
        if !(version.is_empty() || version == b"0") {
            return Cow::Borrowed(msg);
        }
        let abs = first.start + deg.start..first.start + deg.end;
        Cow::Owned(wire::splice(msg, abs, ctx.hbci_version.as_bytes()))
    }
}

// ── RSigIdLeadingZero ──────────────────────────────────────────────────────

/// Strips leading zeros from the signature ID (Sicherheitsreferenznummer) in HNSHK.
///
/// Port of `RSigIdLeadingZero`. The original takes the field after the
/// sixth `+`, which is the signature ID in HNSHK v3 (HBCI 2.2); in FinTS 3.0
/// HNSHK v4 a security profile DEG comes first, so the ID is DEG 7 there.
pub struct SigIdLeadingZero;

impl Quirk for SigIdLeadingZero {
    fn name(&self) -> &'static str {
        "SigIdLeadingZero"
    }

    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let mut fixed = false;
        let segs: Vec<Cow<[u8]>> = split_segments(msg)
            .into_iter()
            .map(|seg| {
                if fixed || wire::segment_type(seg) != b"HNSHK" {
                    return Cow::Borrowed(seg);
                }
                fixed = true; // only the first HNSHK, like the original
                let idx = if segment_version(seg).unwrap_or(4) >= 4 {
                    7
                } else {
                    6
                };
                match de_bytes(seg, idx, 0) {
                    Some(id)
                        if id.len() > 1 && id[0] == b'0' && id.iter().all(u8::is_ascii_digit) =>
                    {
                        let trimmed = id
                            .iter()
                            .position(|b| *b != b'0')
                            .map_or(&id[id.len() - 1..], |p| &id[p..]);
                        replace_de(seg, idx, 0, trimmed)
                            .map(Cow::Owned)
                            .unwrap_or(Cow::Borrowed(seg))
                    }
                    _ => Cow::Borrowed(seg),
                }
            })
            .collect();
        rebuild(msg, &segs)
    }
}

// ── RInvalidSuppHBCIVersion ────────────────────────────────────────────────

/// Fixes HBCI versions in the BPD's supported-versions list (HIBPA): banks
/// sometimes send `2` / `3` instead of `210` / `300`.
///
/// Port of `RInvalidSuppHBCIVersion`. The original stops after the first
/// replacement; this fixes every entry.
pub struct InvalidSuppHbciVersion;

impl Quirk for InvalidSuppHbciVersion {
    fn name(&self) -> &'static str {
        "InvalidSuppHBCIVersion"
    }

    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let segs: Vec<Cow<[u8]>> = split_segments(msg)
            .into_iter()
            .map(|seg| {
                if wire::segment_type(seg) != b"HIBPA" {
                    return Cow::Borrowed(seg);
                }
                // HIBPA (BPA3): header, version, KIK, name, numgva, SuppLangs, SuppVersions (DEG 6)
                let Some(deg) = wire::degs(seg).get(6).cloned() else {
                    return Cow::Borrowed(seg);
                };
                let deg_bytes = &seg[deg.clone()];
                let mut out = Vec::with_capacity(deg_bytes.len() + 8);
                for (i, de) in wire::des(deg_bytes).into_iter().enumerate() {
                    if i > 0 {
                        out.push(b':');
                    }
                    out.extend_from_slice(match &deg_bytes[de] {
                        b"2" => b"210",
                        b"3" => b"300",
                        other => other,
                    });
                }
                if out == deg_bytes {
                    Cow::Borrowed(seg)
                } else {
                    Cow::Owned(wire::splice(seg, deg, &out))
                }
            })
            .collect();
        rebuild(msg, &segs)
    }
}

// ── RSecTypeTAN ────────────────────────────────────────────────────────────

/// Removes the invalid security method `TAN` from HISHV (supported security
/// methods). If it was the only one, the whole HISHV segment is dropped
/// ([`WrongSequenceNumbers`] fixes the numbering afterwards in the original;
/// here our parser doesn't depend on it).
///
/// Port of `RSecTypeTAN`.
pub struct SecTypeTan;

impl Quirk for SecTypeTan {
    fn name(&self) -> &'static str {
        "SecTypeTAN"
    }

    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        let mut segs: Vec<Cow<[u8]>> = Vec::new();
        for seg in split_segments(msg) {
            if wire::segment_type(seg) != b"HISHV" {
                segs.push(Cow::Borrowed(seg));
                continue;
            }
            // HISHV: header + mixing allowed (J/N) + SuppSecMethods DEGs (method:version…)
            let degs = wire::degs(seg);
            let kept: Vec<_> = degs
                .iter()
                .enumerate()
                .filter(|(i, d)| *i < 2 || wire::segment_type(&seg[(*d).clone()]) != b"TAN")
                .map(|(_, d)| &seg[d.clone()])
                .collect();
            if kept.len() == degs.len() {
                segs.push(Cow::Borrowed(seg));
            } else if kept.len() > 2 {
                let mut out = kept.join(&b'+');
                out.push(b'\'');
                segs.push(Cow::Owned(out));
            }
            // else: TAN was the only method → drop the segment
        }
        rebuild(msg, &segs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: QuirkContext<'static> = QuirkContext {
        hbci_version: "300",
        dialog_id: "DLG-7",
        message_number: 3,
    };

    fn run(q: &dyn Quirk, msg: &str) -> String {
        String::from_utf8(q.incoming(msg.as_bytes(), &CTX).into_owned()).unwrap()
    }

    fn run_raw(q: &dyn Quirk, msg: &str) -> String {
        String::from_utf8(q.incoming_raw(msg.as_bytes(), &CTX).into_owned()).unwrap()
    }

    fn unchanged(q: &dyn Quirk, msg: &str) {
        assert!(
            matches!(q.incoming(msg.as_bytes(), &CTX), Cow::Borrowed(_)),
            "{} touched: {msg}",
            q.name()
        );
        assert!(
            matches!(q.incoming_raw(msg.as_bytes(), &CTX), Cow::Borrowed(_)),
            "{} touched: {msg}",
            q.name()
        );
    }

    const GOOD: &str = "HNHBK:1:3+000000000120+300+DLG-7+3+DLG-7:3'HNSHK:2:4+PIN:1+999+1234567+1+1+2::SYS+1+1:20260101:120000'\
        HIRMG:3:2+0010::Nachricht entgegengenommen'HIRMS:4:2:3+0020::Auftrag ausgefuehrt'\
        HIKAZ:5:7:3+@11@:20:STARTUMS'HNHBS:6:1+3'";

    #[test]
    fn all_quirks_leave_a_correct_message_alone() {
        for q in crate::quirks::QuirkChain::hbci4java().quirks.iter() {
            unchanged(q.as_ref(), GOOD);
        }
    }

    #[test]
    fn invalid_segment_removes_iidia() {
        // RInvalidSegment: "'IIDIA:" … "'" is deleted.
        let fixed = run(
            &InvalidSegment,
            "HNHBK:1:3+1+300+D+1'HIRMG:2:2+0010::ok'IIDIA:3:1+X+Y'HNHBS:4:1+1'",
        );
        assert_eq!(fixed, "HNHBK:1:3+1+300+D+1'HIRMG:2:2+0010::ok'HNHBS:4:1+1'");
    }

    #[test]
    fn wrong_status_seg_order_moves_status_segments_up() {
        // Data segment before HIRMG/HIRMS → header, HIRMG, HIRMS, data.
        let fixed = run(
            &WrongStatusSegOrder,
            "HNHBK:1:3+1'HISAL:2:7:3+X'HIRMS:3:2:3+0020::ok'HIRMG:4:2+0010::ok'HNHBS:5:1+1'",
        );
        assert_eq!(
            fixed,
            "HNHBK:1:3+1'HIRMG:4:2+0010::ok'HIRMS:3:2:3+0020::ok'HISAL:2:7:3+X'HNHBS:5:1+1'"
        );
    }

    #[test]
    fn wrong_sequence_numbers_renumbers_and_skips_binary() {
        // The binary payload contains "'" and fake segment headers that must not be touched.
        let fixed = run(
            &WrongSequenceNumbers,
            "HNHBK:1:3+1'HIRMG:7:2+0010::ok'HIKAZ::7:3+@12@'XX:99:1+ab''HNHBS:9:1+1'",
        );
        assert_eq!(
            fixed,
            "HNHBK:1:3+1'HIRMG:2:2+0010::ok'HIKAZ:3:7:3+@12@'XX:99:1+ab''HNHBS:4:1+1'"
        );
    }

    #[test]
    fn status_order_then_sequence_numbers_compose() {
        let msg = "HNHBK:1:3+1'HISAL:2:7:3+X'HIRMG:3:2+0010::ok'HNHBS:4:1+1'";
        let step1 = run(&WrongStatusSegOrder, msg);
        assert_eq!(
            run(&WrongSequenceNumbers, &step1),
            "HNHBK:1:3+1'HIRMG:2:2+0010::ok'HISAL:3:7:3+X'HNHBS:4:1+1'"
        );
    }

    #[test]
    fn missing_msg_ref_is_rebuilt_from_request() {
        let fixed = run_raw(
            &MissingMsgRef,
            "HNHBK:1:3+000000000100+300+DLG-7+3'HNHBS:2:1+3'",
        );
        assert_eq!(
            fixed,
            "HNHBK:1:3+000000000100+300+DLG-7+3+DLG-7:3'HNHBS:2:1+3'"
        );
    }

    #[test]
    fn hbci_version_restored_when_empty_or_zero() {
        assert_eq!(
            run_raw(&HbciVersion, "HNHBK:1:3+000000000100+0+DLG-7+3+DLG-7:3'"),
            "HNHBK:1:3+000000000100+300+DLG-7+3+DLG-7:3'"
        );
        assert_eq!(
            run_raw(&HbciVersion, "HNHBK:1:3+000000000100++DLG-7+3+DLG-7:3'"),
            "HNHBK:1:3+000000000100+300+DLG-7+3+DLG-7:3'"
        );
    }

    #[test]
    fn sig_id_leading_zeros_removed() {
        // HNSHK v4: profile, function, control ref, area, role, SecIdnDetails, sig ID (DEG 7)
        assert_eq!(
            run(
                &SigIdLeadingZero,
                "HNSHK:2:4+PIN:1+999+1234567+1+1+2::SYS+0042+1:20260101:120000'"
            ),
            "HNSHK:2:4+PIN:1+999+1234567+1+1+2::SYS+42+1:20260101:120000'"
        );
        // HNSHK v3 (HBCI 2.2): sig ID is DEG 6, as in the Java original.
        assert_eq!(
            run(&SigIdLeadingZero, "HNSHK:2:3+999+1234567+1+1+2::SYS+000+X'"),
            "HNSHK:2:3+999+1234567+1+1+2::SYS+0+X'"
        );
    }

    #[test]
    fn invalid_supp_hbci_version_fixed() {
        assert_eq!(
            run(
                &InvalidSuppHbciVersion,
                "HIBPA:5:3:4+12+280:10020030+Bank+0+1+2:3:300+0'"
            ),
            "HIBPA:5:3:4+12+280:10020030+Bank+0+1+210:300:300+0'"
        );
    }

    #[test]
    fn sec_type_tan_removed_from_hishv() {
        // More than one method: drop only TAN:1.
        assert_eq!(
            run(&SecTypeTan, "HISHV:6:3:4+N+RDH:3+TAN:1+PIN:1'X:7:1'"),
            "HISHV:6:3:4+N+RDH:3+PIN:1'X:7:1'"
        );
        // Only TAN: drop the whole segment.
        assert_eq!(
            run(&SecTypeTan, "A:1:1'HISHV:6:3:4+N+TAN:1'X:7:1'"),
            "A:1:1'X:7:1'"
        );
    }

    #[test]
    fn quirks_never_panic_on_garbage() {
        let chain = crate::quirks::QuirkChain::hbci4java();
        for msg in [
            &b""[..],
            b"'",
            b"HNHBK",
            b"HNHBK:1:3+'",
            b"HNSHK:2:4+0'",
            b"HIBPA:'",
            b"HISHV:1:3+N+TAN'",
            b"@9@",
            b"HNHBK:1:3+@99999@'",
        ] {
            let _ = chain.incoming(msg, &CTX);
        }
    }
}
