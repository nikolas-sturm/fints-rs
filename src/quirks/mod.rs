//! Quirk layer: patch malformed bank messages before parsing.
//!
//! Like hbci4java's rewriters, every message passes through all quirks in
//! order and each quirk is a no-op when the message is already correct.
//!
//! The pipeline in [`QuirkChain::incoming`] mirrors hbci4java's:
//!
//! 1. [`Quirk::incoming_raw`] on the message as received (hbci4java's
//!    `incomingCrypted`), e.g. a broken HNHBK header.
//! 2. Unwrap the PIN/TAN "encryption" envelope: drop HNVSK, replace HNVSD by
//!    its payload. The result is the clear-text message
//!    `HNHBK + inner segments + HNHBS`.
//! 3. [`Quirk::incoming`] on the clear text (hbci4java's `incomingClearText`).
//!
//! Outgoing messages pass [`Quirk::outgoing`] before they are sent.
//!
//! This module (trait, pipeline, `wire` helpers) is MIT like the rest of the
//! crate. The ported hbci4java rewriters live in [`hbci4java`] and are
//! LGPL-2.1-or-later; see `NOTICE`.

use std::borrow::Cow;

pub mod hbci4java;
pub(crate) mod wire;

/// What a quirk may need to know about the request a response belongs to.
#[derive(Debug, Clone, Copy)]
pub struct QuirkContext<'a> {
    /// HBCI version we sent in HNHBK, e.g. "300".
    pub hbci_version: &'a str,
    /// Dialog ID we sent ("0" for the first message of a dialog).
    pub dialog_id: &'a str,
    /// Message number we sent.
    pub message_number: u16,
}

/// A fix for one kind of malformed bank message.
///
/// All methods default to "leave unchanged". Implementations must never
/// panic and should return `Cow::Borrowed` when nothing needs fixing.
pub trait Quirk: Send + Sync {
    /// Short name for logs, e.g. "WrongSequenceNumbers".
    fn name(&self) -> &'static str;

    /// Fix the raw incoming message (outer envelope still present).
    fn incoming_raw<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        Cow::Borrowed(msg)
    }

    /// Fix the clear-text incoming message (`HNHBK + inner segments + HNHBS`).
    fn incoming<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        Cow::Borrowed(msg)
    }

    /// Fix an outgoing message before it is sent.
    fn outgoing<'a>(&self, msg: &'a [u8], _ctx: &QuirkContext<'_>) -> Cow<'a, [u8]> {
        Cow::Borrowed(msg)
    }
}

/// An ordered list of quirks applied to every message of a connection.
pub struct QuirkChain {
    quirks: Vec<Box<dyn Quirk>>,
}

impl std::fmt::Debug for QuirkChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.quirks.iter().map(|q| q.name())).finish()
    }
}

impl Default for QuirkChain {
    /// hbci4java's default rewriter set, in hbci4java's order.
    fn default() -> Self {
        Self::hbci4java()
    }
}

impl QuirkChain {
    /// No quirks: messages pass through unchanged (envelope still unwrapped).
    pub fn none() -> Self {
        Self { quirks: Vec::new() }
    }

    /// hbci4java's default rewriters (`kernel.rewriter`), in the same order:
    /// InvalidSegment, WrongStatusSegOrder, WrongSequenceNumbers,
    /// MissingMsgRef, HBCIVersion, SigIdLeadingZero, InvalidSuppHBCIVersion,
    /// SecTypeTAN. The MT940 rewriters (KUmsDelimiters, KUmsEmptyBDateSets)
    /// are not ported; the `mt940` crate handles those statements so far.
    pub fn hbci4java() -> Self {
        use hbci4java::*;
        Self {
            quirks: vec![
                Box::new(InvalidSegment),
                Box::new(WrongStatusSegOrder),
                Box::new(WrongSequenceNumbers),
                Box::new(MissingMsgRef),
                Box::new(HbciVersion),
                Box::new(SigIdLeadingZero),
                Box::new(InvalidSuppHbciVersion),
                Box::new(SecTypeTan),
            ],
        }
    }

    /// Append a quirk (e.g. a bank-specific fix).
    pub fn with(mut self, quirk: impl Quirk + 'static) -> Self {
        self.quirks.push(Box::new(quirk));
        self
    }

    /// Names of the active quirks, in order.
    pub fn names(&self) -> Vec<&'static str> {
        self.quirks.iter().map(|q| q.name()).collect()
    }

    /// Run the full incoming pipeline: raw quirks → unwrap envelope → clear-text quirks.
    pub fn incoming(&self, raw: &[u8], ctx: &QuirkContext<'_>) -> Vec<u8> {
        let mut msg = raw.to_vec();
        for q in &self.quirks {
            msg = apply(q.as_ref(), "raw", msg, |m| q.incoming_raw(m, ctx));
        }
        let mut msg = unwrap_envelope(&msg);
        for q in &self.quirks {
            msg = apply(q.as_ref(), "incoming", msg, |m| q.incoming(m, ctx));
        }
        msg
    }

    /// Run the outgoing quirks.
    pub fn outgoing(&self, msg: &[u8], ctx: &QuirkContext<'_>) -> Vec<u8> {
        let mut msg = msg.to_vec();
        for q in &self.quirks {
            msg = apply(q.as_ref(), "outgoing", msg, |m| q.outgoing(m, ctx));
        }
        msg
    }
}

fn apply(
    q: &dyn Quirk,
    phase: &str,
    msg: Vec<u8>,
    f: impl for<'m> FnOnce(&'m [u8]) -> Cow<'m, [u8]>,
) -> Vec<u8> {
    match f(&msg) {
        Cow::Borrowed(_) => msg,
        Cow::Owned(fixed) => {
            tracing::warn!("[FinTS] Quirk {} ({}) patched the message", q.name(), phase);
            fixed
        }
    }
}

/// Turn `HNHBK HNVSK HNVSD{inner} HNHBS` into `HNHBK inner HNHBS`.
/// Messages without an envelope (e.g. some error responses) pass unchanged.
pub(crate) fn unwrap_envelope(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len());
    for range in wire::segments(msg) {
        let seg = &msg[range];
        match wire::segment_type(seg) {
            b"HNVSK" => {}
            b"HNVSD" => {
                let degs = wire::degs(seg);
                let payload = degs.get(1).and_then(|d| wire::binary_payload(&seg[d.clone()]));
                match payload {
                    Some(inner) => out.extend_from_slice(inner),
                    None => out.extend_from_slice(seg),
                }
            }
            _ => out.extend_from_slice(seg),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: QuirkContext<'static> = QuirkContext { hbci_version: "300", dialog_id: "DLG", message_number: 2 };

    #[test]
    fn unwrap_envelope_flattens_hnvsd() {
        let inner = b"HNSHK:2:4+PIN:1'HIRMG:3:2+0010::ok'";
        let mut msg = b"HNHBK:1:3+000000000100+300+DLG+2+DLG:2'HNVSK:998:3+PIN:1'HNVSD:999:1+@".to_vec();
        msg.extend_from_slice(inner.len().to_string().as_bytes());
        msg.push(b'@');
        msg.extend_from_slice(inner);
        msg.extend_from_slice(b"'HNHBS:4:1+2'");
        assert_eq!(
            unwrap_envelope(&msg),
            b"HNHBK:1:3+000000000100+300+DLG+2+DLG:2'HNSHK:2:4+PIN:1'HIRMG:3:2+0010::ok'HNHBS:4:1+2'".to_vec()
        );
    }

    #[test]
    fn correct_message_passes_default_chain_unchanged() {
        let msg = b"HNHBK:1:3+000000000100+300+DLG+2+DLG:2'HIRMG:2:2+0010::ok'HIRMS:3:2:3+0020::fine'HISAL:4:7:3+X'HNHBS:5:1+2'";
        assert_eq!(QuirkChain::default().incoming(msg, &CTX), msg.to_vec());
    }

    #[test]
    fn chain_lists_hbci4java_order() {
        assert_eq!(
            QuirkChain::hbci4java().names(),
            [
                "InvalidSegment", "WrongStatusSegOrder", "WrongSequenceNumbers", "MissingMsgRef",
                "HBCIVersion", "SigIdLeadingZero", "InvalidSuppHBCIVersion", "SecTypeTAN",
            ]
        );
    }
}
