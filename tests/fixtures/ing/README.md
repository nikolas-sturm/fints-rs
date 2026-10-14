# ING (BLZ 50010517) regression fixtures

Empty until the first real exchange with ING has been captured. Each fixture is
one request/response pair from a real dialog, masked, kept so that a fix for ING
can never silently regress.

## Capturing

1. Run with wire logging: `RUST_LOG=fints=trace fints-client -v --bank 50010517 sync --days 90`
   (`fints-client decode --b64` turns a base64 message into readable segments).
2. Run hbci4java's `UmsatzAbrufPinTan` against the same account at debug level
   and diff HKIDN, HKVVB, HKTAN and HKKAZ field by field (the guide's oracle step).

## Masking (before committing)

- PIN: already replaced by `***PIN***` in fints-rs logs; check HNSHA anyway.
- IBAN / account number / depot number: replace digits, keep the length and a
  valid-looking shape (e.g. `DE00500105170000000000`).
- Names (HIUPD owner, MT940 :86: counterparty, MT535): replace with `MUSTERMANN`.
- System ID (HISYN, HNSHK/HNVSK): replace with `SYSID-MASKED`.

## Layout

One file per message, named `NN-<what>.fints`, e.g. `01-init-request.fints`,
`02-init-response-3955.fints`, in FinTS wire format (one segment per line is
fine; the parser skips line breaks between segments).
