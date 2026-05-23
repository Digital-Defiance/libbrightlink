# libBrightLink

The canonical C client for the [BrightLink Protocol][rfc] — a hardware-anchored
ephemeral-credential and geo-context bridge between local CLI tools and the
resident [BrightNexus][nexus] desktop agent.

[rfc]: https://github.com/Digital-Defiance/BrightChain/blob/main/docs/papers/brightlink.md
[nexus]: https://brightnexus.digitaldefiance.org/

## Status

**v0.1.x — preview.** API is documented and tested but not yet ABI-stable.
Source-level compatibility is preserved between minor versions; binary
compatibility is not promised before v1.0.

The v0.1.x surface covers what Bright iptils needs:

- `bl_client_new` / `bl_client_free` — handle-based lifecycle
- `bl_register` — explicit registration (also called lazily)
- `bl_geo_get` — the §9.4 LINK_GEO_GET verb
- `bl_pin_store_memory` and `bl_pin_store_file` (with the `BLP1` on-disk format)
- `bl_pin_store_custom` — plug your own (keyring, TPM-sealed, etc.)
- The full `brightlink_crypto.h` primitive surface (DD-ECIES, HKDF, AES-GCM,
  P-256, secp256k1) for test harnesses and tools that need crypto outside
  a registered session.

The v0.2 surface (driven by the bsh migration) will add `bl_deliver` for the
nine §5 payload schemas, the remaining four `LINK_GEO_*` verbs, and the
`LINK_PUSH` subscribe channel.

## Consumers

| Project | Status | Notes |
|---------|--------|-------|
| Bright iptils | ✅ in-tree submodule | `bping`, `btraceroute`, `bmtr`, `baudit` use `bl_geo_get` |
| BSH (zsh fork) | 🚧 migration in progress | replacing `Src/Modules/brightlink.c` with a thin shim over libBrightLink |

## Build

```sh
meson setup build
ninja -C build
```

Disable the test tree (saves the libBrightLink mock-brightnexus binary) with
`-Dlibbrightlink_tests=false`.

## Use from another Meson project

Add as a submodule under `subprojects/libbrightlink/`:

```sh
git submodule add https://github.com/Digital-Defiance/libbrightlink.git \
    subprojects/libbrightlink
```

Then in your `meson.build`:

```meson
brightlink = subproject('libbrightlink')
brightlink_dep = brightlink.get_variable('libbrightlink_dep')

executable('your-tool',
    'your-tool.c',
    dependencies : [brightlink_dep])
```

In your code:

```c
#include "brightlink/brightlink.h"

bl_client_config_t cfg = {
    .agent_name = "your-tool",
    .pin_store  = bl_pin_store_file("/home/user/.brightchain/pins", "your-tool"),
};
bl_client_t *c = bl_client_new(&cfg);

bl_geo_position_t pos;
if (bl_geo_get(c, BL_GEO_FORMAT_BOTH, &pos) == BL_OK) {
    /* pos.wgs84_lat, pos.brightspace_x_bm, etc. */
}
bl_client_free(c);
```

## Pin storage

Pins are TOFU records of the bridge's P-256 SEP public key. They are public
material — file-mode integrity, not encryption, is the relevant property.
See [packaging/pin-format.md](packaging/pin-format.md) for the on-disk format.

| Store | When to use |
|-------|-------------|
| `bl_pin_store_memory()` | Long-lived processes (interactive shells, daemons). Pin survives across multiple `bl_register` inside the same process; no disk persistence. |
| `bl_pin_store_file(dir, id)` | Short-lived single-shot tools (CLI utilities). Pin persists at `<dir>/<id>.sep-pub` (mode 0600 inside a 0700 directory). |
| `bl_pin_store_custom(vt)` | Anything else — keyring-backed, TPM-sealed, etc. |

## Threat model

libBrightLink defends against:

- **Bridge impersonation.** TOFU pin verification rejects a different SEP key
  than the one observed at first registration.
- **Local-socket adversaries.** The bridge socket is mode 0600 inside a 0700
  directory; only the local user can connect.
- **Replay.** Per-direction monotonic counters and AEAD AAD include
  direction tag, counter, and command type/context.

It does **not** defend against:

- An attacker with code execution as the user. Once an attacker can `read()`
  `/proc/<pid>/mem`, the in-memory `K_session` is theirs.
- A malicious BrightNexus build run before any genuine one (the first-install
  pin is also the attacker's pin). Out-of-band SEP key publication via OS
  package signing is the answer; see RFC §14.

## License

MIT. See [LICENSE](LICENSE).
