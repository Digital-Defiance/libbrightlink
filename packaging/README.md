# Packaging

libBrightLink does not currently ship as a standalone distribution package.
Each consumer (Bright iptils, BSH) embeds it via git submodule and statically
links the result into its own binaries.

## Why static-only for v0.1.x

- The library API is not ABI-stable yet. A versioned `.so` would imply a
  commitment we cannot back up before v1.0.
- The total static cost is ~30 KB per binary — trivial relative to OpenSSL
  itself, which every consumer already links.
- Static linking dodges SONAME drift across distros (`libsecp256k1-1` on
  Ubuntu noble vs `libsecp256k1-6` on later releases is the bright-iputils
  example) by burying the dependency edge inside the consumer's own
  build-time `${shlibs:Depends}` resolution.

## Future packaging

When promotion criteria in `CHANGELOG.md` are met, this directory will
grow:

- `debian/` — `libbrightlink-dev` (static archive + headers), eventually
  `libbrightlinkN` runtime + `libbrightlink-dev` headers.
- `homebrew/` — formula for the macOS tap.
- `libbrightlink.pc.in` — pkg-config template.
- A versioned shared library with a stable symbol map.

## On-disk pin format

See [pin-format.md](pin-format.md) for the on-disk layout used by
`bl_pin_store_file()`.
