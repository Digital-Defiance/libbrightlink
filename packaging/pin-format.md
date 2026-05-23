# BLP1 — libBrightLink pin file format

`bl_pin_store_file()` writes one pin per file at
`<dir_path>/<binary_id>.sep-pub`. Each file contains a single TOFU-pinned
P-256 public key in a format that's byte-stable, has room for future
extension, and refuses unrecognised content.

## Layout

```
+------------+-----------+-----------------------------------+--------------+
| 0..3       | 4         | 5..69                             | 70..         |
+------------+-----------+-----------------------------------+--------------+
| "BLP1"     | version   | uncompressed P-256 public key     | reserved     |
| (4 bytes)  | (1 byte)  | (65 bytes, leading 0x04)          | (future use) |
+------------+-----------+-----------------------------------+--------------+
```

- **Magic** — `0x42 0x4C 0x50 0x31` (ASCII `"BLP1"`). A loader that doesn't
  see this magic refuses the file.
- **Version** — `0x01` for v1. Loaders MUST refuse unknown versions.
- **Public key** — 65 bytes in standard X9.63 uncompressed form. The
  leading byte MUST be `0x04`.
- **Reserved** — additional bytes past offset 70 are RESERVED for future
  format extensions (key-id digest, pinned-at BrightDate, last-rotation
  timestamp, HMAC envelope tag). v1 loaders MUST tolerate trailing bytes
  (treat them as opaque) so v1 binaries can read v2 files written by
  newer libraries. Files shorter than 70 bytes are malformed.

## File permissions

- File mode: **0600** (owner read/write only).
- Containing directory mode: **0700**.
- Atomic writes via write-to-`.new` + `fsync` + `rename`.

## Why no encryption

A pin file contains only the bridge's PUBLIC key. The TOFU contract is "I
trust this exact 65 bytes; refuse to talk to a bridge whose SEP key
doesn't match." There is no secret to protect.

The threat we *do* care about is **tampering** — a same-uid attacker
swapping our pin file for one matching a malicious bridge they control.
Encryption doesn't address that; **integrity** does. Future versions of
this format MAY add an HMAC envelope keyed off code-signing identity
(macOS Secure Enclave-derived per-app keys via
`kSecAttrTokenIDSecureEnclave`) or TPM2-sealed material; the reserved
trailing region leaves room for such a tag without a format break.

For v1, mode-0600 inside a 0700 directory is the integrity boundary.
That matches the convention used by the BrightNexus bridge for its own
ACL files (`geo-acl.json` + `geo-acl.sig` per RFC §7.2).

## Compatibility

| File written by | Readable by  |
|-----------------|--------------|
| v1 (this doc)   | v1, v2+ (trailing bytes tolerated) |
| v2 (future)     | v2 only — v1 files lack the v2 fields by definition; v1 readers refuse on version byte mismatch |

A v2 reader handed a v1 file accepts it (forward-compatible).
A v1 reader handed a v2 file refuses on the version byte (no silent
downgrade — the protection that v2 added is exactly what v1 wouldn't be
checking).
