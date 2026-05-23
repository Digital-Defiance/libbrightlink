# Changelog

All notable changes to libBrightLink are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial seed: handle-based client API in `brightlink.h`.
- `LINK_REGISTER` (§4.5) with full DD-ECIES envelope, 238-byte transcript,
  P-256 transcript signature verify, TOFU pinning.
- `LINK_GEO_GET` (§9.4) with WGS84 + BrightSpace dual-coordinate output.
- Pin storage: `bl_pin_store_memory`, `bl_pin_store_file` (BLP1 on-disk
  format with magic + version header), `bl_pin_store_custom` for keyring /
  TPM-sealed backends.
- `brightlink_crypto.h` primitive surface (DD-ECIES, HKDF-SHA256,
  AES-256-GCM, P-256 sign/verify, secp256k1).
- `mock-brightnexus` test binary that speaks the bridge half of the
  protocol against the same crypto primitives.
- Static-only build via Meson; no shared library yet.

## Promotion criteria

The library will be promoted to ABI-stable v1.0.0 (and a versioned shared
library) when:

1. Both reference consumers (Bright iputils and BSH) have shipped against
   libBrightLink for at least one stable release.
2. A third-party consumer outside Digital Defiance has integrated and
   provided integration feedback.
3. The known-answer test vectors cover all crypto primitives at the
   bit-exact level (currently HKDF and transcript layout; need ECIES
   envelope round-trip and P-256 signature determinism).
4. The remaining v1 protocol surface (`LINK_DELIVER` with all §5 payload
   schemas, the four other `LINK_GEO_*` verbs, `LINK_PUSH`) is shipped
   and has at least one consumer per surface.
