/*
 * brightlink.h — public API for libBrightLink, the canonical C client
 * for the BrightLink Protocol.
 *
 * libBrightLink implements the shell side of the BrightLink Protocol
 * (see docs/papers/brightlink.md in the BrightChain monorepo). It speaks
 * EBP/1 + BrightLink to a local BrightNexus bridge over a Unix-domain
 * socket, performs the §4.5 LINK_REGISTER handshake, and exposes the
 * §9 LINK_GEO_* and §4.6 LINK_DELIVER surfaces to consumers.
 *
 * Stability. This is v0.1.x — the API is documented and tested, but not
 * yet ABI-stable. Source-level compatibility is preserved between minor
 * versions; binary compatibility is not promised before v1.0.
 *
 * Linkage. libBrightLink is a static library. Every consumer ships its
 * own copy embedded into the final binary. There is no shared library
 * yet — see CHANGELOG.md for the promotion criteria.
 *
 * Threading. A bl_client_t is NOT thread-safe. Callers that want
 * concurrent BrightLink calls allocate one client per thread. The
 * underlying primitives (libsecp256k1, OpenSSL EVP) are thread-safe
 * but per-client buffers are not.
 *
 * Error handling. Every fallible call returns a bl_status_t. BL_OK is
 * success; anything else is a typed failure. bl_strerror() maps codes to
 * stable English strings safe for inclusion in error messages. To get
 * the bridge's own English error string (when the bridge refused the
 * call rather than the transport failing), call bl_last_bridge_error().
 */

#ifndef BRIGHTLINK_H
#define BRIGHTLINK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────── version ─────────────────────── */

#define BL_VERSION_MAJOR 0
#define BL_VERSION_MINOR 1
#define BL_VERSION_PATCH 0

/* Returns a static "MAJOR.MINOR.PATCH" string. */
const char *bl_version(void);

/* ─────────────────────── status codes ─────────────────────── */

typedef enum {
    BL_OK = 0,
    BL_ERR_INVALID_ARG,         /* caller-side: NULL where required, etc. */
    BL_ERR_OOM,                 /* allocation failure */
    BL_ERR_TRANSPORT,           /* connect/read/write failure */
    BL_ERR_PROTOCOL,            /* bridge sent a malformed response */
    BL_ERR_CRYPTO,              /* AES-GCM, ECIES, HKDF, P-256 verify */
    BL_ERR_PIN_MISMATCH,        /* bridge SEP key changed since pin */
    BL_ERR_BRIDGE_REFUSED,      /* bridge returned {"error":...} */
    BL_ERR_NOT_REGISTERED,      /* deliver/geo before LINK_REGISTER */
    BL_ERR_DENIED,              /* user denied a geo scope */
    BL_ERR_TIMEOUT,             /* read/prompt timed out */
} bl_status_t;

const char *bl_strerror(bl_status_t s);

/* ─────────────────────── pin store (TOFU) ─────────────────────── */

/*
 * Pin storage is the only consumer-shaped knob in libBrightLink. The
 * library never reads or writes pin material directly — it goes through
 * a bl_pin_store_t. Three implementations ship in-box:
 *
 *   bl_pin_store_memory()
 *       In-process only. The pin lives for the lifetime of the
 *       bl_client_t and disappears at bl_client_free(). Right choice for
 *       long-lived processes (interactive shells, daemons).
 *
 *   bl_pin_store_file(dir_path, binary_id)
 *       Persists pins to <dir_path>/<binary_id>.sep-pub (mode 0600 inside
 *       the dir, which is auto-created at mode 0700). Right choice for
 *       short-lived single-shot tools (e.g. bping, btraceroute) that
 *       need pin continuity across invocations.
 *
 *   bl_pin_store_custom(vt)
 *       Plug-your-own. Useful for keyring-backed (libsecret, KWallet,
 *       Keychain) or sealed-by-TPM/SEP backends.
 *
 * Pin material is the bridge's UNCOMPRESSED P-256 public key (65 bytes,
 * leading 0x04). It is NOT a secret — TOFU pinning depends on integrity
 * (file permissions, atomic writes, optional HMAC envelope) rather than
 * confidentiality. See packaging/pin-format.md for the on-disk format.
 */

typedef struct bl_pin_store_s bl_pin_store_t;

/* Custom store callbacks. Return 1 on success, 0 on failure. `load` writes
 * the 65-byte uncompressed P-256 key into pub65_out and returns 1; if no
 * pin exists it returns 0 with no buffer write. `save` persists the given
 * pin. `free_` releases store-private state. */
typedef struct {
    int  (*load)(void *ctx, uint8_t pub65_out[65]);
    int  (*save)(void *ctx, const uint8_t pub65[65]);
    void (*free_)(void *ctx);
    void *ctx;
} bl_pin_store_vtable_t;

bl_pin_store_t *bl_pin_store_memory(void);
bl_pin_store_t *bl_pin_store_file(const char *dir_path, const char *binary_id);
bl_pin_store_t *bl_pin_store_custom(const bl_pin_store_vtable_t *vt);
void            bl_pin_store_free(bl_pin_store_t *s);

/* ─────────────────────── client ─────────────────────── */

typedef struct bl_client_s bl_client_t;

typedef struct {
    /* Bridge socket path. NULL means "use $BRIGHTNEXUS_SOCKET if set,
     * otherwise $HOME/.brightchain/brightnexus/brightnexus.sock". */
    const char *socket_path;

    /* Caller identification recorded in the bridge's audit log. The
     * agent_name typically matches the calling binary's basename
     * (e.g. "bping", "bsh"). agent_version is informational. Both are
     * truncated to 64 chars by the bridge. */
    const char *agent_name;
    const char *agent_version;

    /* Pin storage. Required. Free'd at bl_client_free unless the caller
     * passes BL_PIN_STORE_BORROWED; see notes below. */
    bl_pin_store_t *pin_store;

    /* Requested LINK_REGISTER session TTL. 0 means default (1 hour); the
     * bridge clamps to its configured ceiling regardless. */
    int ttl_seconds;

    /* Optional. When non-NULL, the library writes one-line diagnostics
     * to this stream on transport / crypto / bridge-refused failures.
     * Pass stderr to mirror BRIGHTLINK_DEBUG=1; pass NULL for silent. */
    void *debug_stream;
} bl_client_config_t;

/*
 * By default bl_client_free(c) also frees c->pin_store. If the caller
 * wants to retain the pin store across multiple clients, set
 * pin_store_borrowed = 1 and free the store separately.
 *
 * Future-compat: keeping this behavior in a config flag rather than a
 * separate ctor signature keeps the API stable as we add more options.
 */
typedef struct {
    bl_client_config_t base;
    int                pin_store_borrowed;
} bl_client_config_v2_t;

/* Create a client. The config is copied; caller may free *cfg after. */
bl_client_t *bl_client_new(const bl_client_config_t *cfg);
void         bl_client_free(bl_client_t *c);

/* If the bridge replied with an {"error": "..."} response on the most
 * recent call, returns that English string (e.g. "Stale registration",
 * "geo: scope denied by policy"). Returns NULL otherwise. The string is
 * owned by the client; callers MUST NOT free it. Cleared on the next
 * successful or unsuccessful call. */
const char *bl_last_bridge_error(const bl_client_t *c);

/* ─────────────────────── session ─────────────────────── */

/*
 * Explicit registration. Optional — bl_geo_get / bl_deliver register
 * lazily on first call. Useful when you want to fail fast on bridge
 * unreachability before doing other work, or when you need a session
 * established for a follow-on call inside a tight time budget.
 *
 * On success: the client holds a 32-byte K_session and 16-byte sessionId
 * (for AEAD-wrapped commands like LINK_DELIVER) and a TOFU-pinned bridge
 * SEP key. The session expires server-side after the granted TTL; clients
 * that outlive their session must re-register (the library re-registers
 * on the next call when it observes a "session expired" bridge response).
 */
bl_status_t bl_register(bl_client_t *c);

/* ─────────────────────── geo ─────────────────────── */

/*
 * Geographic position from the bridge (RFC §9.4). Both representations
 * are populated when the bridge returns them; check the have_* flags
 * before reading. accuracy_m and brightdate are populated whenever the
 * bridge returns them, which in current §9.4 is always.
 *
 * brightspace.epoch_bd is the BrightDate the fix was sampled at. Long-
 * lived spatial claims that survive across plate-motion-significant
 * intervals SHOULD re-project against this epoch (see BrightSpace §5).
 */
typedef struct {
    int    have_wgs84;
    double wgs84_lat;            /* degrees */
    double wgs84_lon;            /* degrees */
    double wgs84_alt_m;          /* metres above WGS84 ellipsoid; NaN if absent */

    int    have_brightspace;
    double brightspace_x_bm;
    double brightspace_y_bm;
    double brightspace_z_bm;
    double brightspace_epoch_bd; /* BrightDate at which fix was sampled */

    double accuracy_m;
    double brightdate;           /* BrightDate at which the response was issued */
} bl_geo_position_t;

typedef enum {
    BL_GEO_FORMAT_WGS84       = 1,
    BL_GEO_FORMAT_BRIGHTSPACE = 2,
    BL_GEO_FORMAT_BOTH        = 3,
} bl_geo_format_t;

/*
 * LINK_GEO_GET (RFC §9.4). Gated by the user's geo:precise scope. On
 * success, populates *out. On BL_ERR_DENIED the user denied the scope
 * via the bridge's prompt or has it set to "deny" in the ACL.
 *
 * format is the wire-cost knob: BL_GEO_FORMAT_BOTH returns both blocks
 * (the typical case). Clients that only consume one form save a few
 * hundred bytes of JSON by asking for only that form.
 */
bl_status_t bl_geo_get(bl_client_t *c,
                       bl_geo_format_t format,
                       bl_geo_position_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BRIGHTLINK_H */
