/*
 * brightlink.c — handle-based BrightLink Protocol client.
 *
 * Implements the public API in include/brightlink/brightlink.h. Compared
 * with the bright-iputils-internal predecessor that held a single
 * implicit session in module-global state, this file is rebuilt around
 * an explicit bl_client_t handle so multiple sessions can coexist
 * (different sockets, different agents, different pin stores) and so
 * lifecycle is owned by the caller rather than by zmodload init/finish
 * hooks.
 *
 * Wire-format references (RFC: docs/papers/brightlink.md):
 *
 *   - GET_PUBLIC_KEY / GET_ENCLAVE_PUBLIC_KEY (EBP/1):  fetched lazily.
 *   - LINK_REGISTER:                                    §4.5
 *   - HKDF info string "brightlink-session-key-v1":     §4.5.2
 *   - 238-byte canonical transcript layout:             §4.5.3
 *   - DD-ECIES Basic envelope (suite 0x21):             §4.5.0
 *   - LINK_GEO_GET (no AEAD wrap; socket perms gate):   §9, §9.4
 */

/* Required for strdup, snprintf-with-%n on glibc, struct sockaddr_un.
 * Define BEFORE any system header so feature-test macros take effect. */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "brightlink/brightlink.h"
#include "brightlink/brightlink_crypto.h"
#include "pin_store_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <pwd.h>

/* ─────────────────────── RFC-pinned constants ─────────────────────── */

#define BL_HKDF_INFO              "brightlink-session-key-v1"
#define BL_HKDF_INFO_LEN          (sizeof(BL_HKDF_INFO) - 1)

#define BL_TRANSCRIPT_HEADER      "BrightLink v1 transcript\0"
#define BL_TRANSCRIPT_HEADER_LEN  25
#define BL_TRANSCRIPT_TOTAL_LEN   238

#define BL_PROTOCOL_VERSION       1
#define BL_CLIENT_NONCE_LEN       16
#define BL_SHARE_LEN              32
#define BL_SESSION_ID_LEN         16
#define BL_SESSION_KEY_LEN        32

#define BL_MAX_TTL_SECONDS        (8 * 3600)
#define BL_DEFAULT_TTL_SECONDS    3600

/* ─────────────────────── version ─────────────────────── */

#define _BL_STR(x) #x
#define _BL_XSTR(x) _BL_STR(x)
const char *bl_version(void)
{
    return _BL_XSTR(BL_VERSION_MAJOR) "."
           _BL_XSTR(BL_VERSION_MINOR) "."
           _BL_XSTR(BL_VERSION_PATCH);
}

/* ─────────────────────── status strings ─────────────────────── */

const char *bl_strerror(bl_status_t s)
{
    switch (s) {
    case BL_OK:                  return "ok";
    case BL_ERR_INVALID_ARG:     return "invalid argument";
    case BL_ERR_OOM:             return "out of memory";
    case BL_ERR_TRANSPORT:       return "transport failed";
    case BL_ERR_PROTOCOL:        return "malformed bridge response";
    case BL_ERR_CRYPTO:          return "crypto operation failed";
    case BL_ERR_PIN_MISMATCH:    return "bridge SEP key changed since pin";
    case BL_ERR_BRIDGE_REFUSED:  return "bridge refused the request";
    case BL_ERR_NOT_REGISTERED:  return "session not registered";
    case BL_ERR_DENIED:          return "policy denied scope";
    case BL_ERR_TIMEOUT:         return "operation timed out";
    }
    return "unknown error";
}

/* ─────────────────────── client state ─────────────────────── */

struct bl_client_s {
    /* Configuration (owned copies). */
    char            socket_path[1024];
    char            agent_name[64];
    char            agent_version[64];
    int             ttl_seconds;
    bl_pin_store_t *pin_store;
    int             pin_store_borrowed;
    FILE           *debug_stream;     /* NULL = silent */

    /* Connection. */
    int             fd;               /* -1 when not connected */

    /* Session state (set after successful LINK_REGISTER). */
    int             session_active;
    unsigned char   session_id[BL_SESSION_ID_LEN];
    unsigned char   session_key[BL_SESSION_KEY_LEN];

    /* Pin (loaded from pin_store on first call, written through on
     * first successful registration). */
    int             pin_loaded;
    unsigned char   pin_pub65[BLC_PUB_UNCOMPRESSED];

    /* Last-bridge-error text — owned by client, freed at next call. */
    char           *last_bridge_error;
};

static void bl_dbg(const bl_client_t *c, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void bl_dbg(const bl_client_t *c, const char *fmt, ...)
{
    if (c == NULL || c->debug_stream == NULL) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("brightlink: ", c->debug_stream);
    vfprintf(c->debug_stream, fmt, ap);
    fputc('\n', c->debug_stream);
    va_end(ap);
}

static void bl_clear_bridge_error(bl_client_t *c)
{
    free(c->last_bridge_error);
    c->last_bridge_error = NULL;
}

/* ─────────────────────── lifecycle ─────────────────────── */

static int resolve_default_socket(char *out, size_t cap)
{
    const char *env = getenv("BRIGHTNEXUS_SOCKET");
    if (env != NULL && env[0] != '\0') {
        size_t n = strlen(env);
        if (n >= cap) return 0;
        memcpy(out, env, n + 1);
        return 1;
    }
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        home = (pw != NULL) ? pw->pw_dir : NULL;
    }
    if (home == NULL) return 0;
    int n = snprintf(out, cap,
                     "%s/.brightchain/brightnexus/brightnexus.sock", home);
    return (n > 0 && (size_t)n < cap);
}

bl_client_t *bl_client_new(const bl_client_config_t *cfg)
{
    if (cfg == NULL || cfg->pin_store == NULL) return NULL;

    bl_client_t *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;

    c->fd = -1;
    c->pin_store = cfg->pin_store;
    c->pin_store_borrowed = 0;
    c->debug_stream = (FILE *)cfg->debug_stream;

    if (cfg->socket_path != NULL && cfg->socket_path[0] != '\0') {
        size_t n = strlen(cfg->socket_path);
        if (n >= sizeof(c->socket_path)) goto fail;
        memcpy(c->socket_path, cfg->socket_path, n + 1);
    } else if (!resolve_default_socket(c->socket_path, sizeof(c->socket_path))) {
        goto fail;
    }

    snprintf(c->agent_name, sizeof(c->agent_name), "%s",
             (cfg->agent_name && cfg->agent_name[0]) ? cfg->agent_name : "libbrightlink");
    snprintf(c->agent_version, sizeof(c->agent_version), "%s",
             (cfg->agent_version && cfg->agent_version[0]) ? cfg->agent_version : "");

    c->ttl_seconds = (cfg->ttl_seconds > 0) ? cfg->ttl_seconds : BL_DEFAULT_TTL_SECONDS;
    if (c->ttl_seconds > BL_MAX_TTL_SECONDS) c->ttl_seconds = BL_MAX_TTL_SECONDS;

    return c;

fail:
    free(c);
    return NULL;
}

static void bl_disconnect(bl_client_t *c)
{
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

void bl_client_free(bl_client_t *c)
{
    if (c == NULL) return;
    bl_disconnect(c);
    bl_clear_bridge_error(c);
    OPENSSL_cleanse(c->session_key, sizeof(c->session_key));
    if (!c->pin_store_borrowed && c->pin_store != NULL) {
        bl_pin_store_free(c->pin_store);
    }
    free(c);
}

const char *bl_last_bridge_error(const bl_client_t *c)
{
    return (c != NULL) ? c->last_bridge_error : NULL;
}

/* ─────────────────────── socket I/O ─────────────────────── */

static bl_status_t bl_connect(bl_client_t *c)
{
    if (c->fd >= 0) return BL_OK;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        bl_dbg(c, "socket(): %s", strerror(errno));
        return BL_ERR_TRANSPORT;
    }

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(c->socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        return BL_ERR_INVALID_ARG;
    }
    strcpy(addr.sun_path, c->socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        bl_dbg(c, "connect %s: %s", c->socket_path, strerror(errno));
        close(fd);
        return BL_ERR_TRANSPORT;
    }
    c->fd = fd;
    return BL_OK;
}

static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        total += (size_t)n;
    }
    return (ssize_t)total;
}

/* EBP/1 brace-counter framing: read one top-level JSON object. */
static ssize_t read_until_brace(int fd, char *buf, size_t cap)
{
    size_t pos = 0;
    int depth = 0, in_string = 0, escaped = 0, seen_open = 0;
    while (pos < cap - 1) {
        ssize_t n = read(fd, buf + pos, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        char ch = buf[pos++];
        if (escaped) { escaped = 0; continue; }
        if (in_string) {
            if (ch == '\\') escaped = 1;
            else if (ch == '"') in_string = 0;
            continue;
        }
        if (ch == '"') { in_string = 1; continue; }
        if (ch == '{') { depth++; seen_open = 1; }
        else if (ch == '}') {
            if (--depth == 0 && seen_open) { buf[pos] = '\0'; return (ssize_t)pos; }
        }
    }
    return -1;
}

static bl_status_t bl_send_request(bl_client_t *c, const char *json,
                                   char **resp_out)
{
    *resp_out = NULL;
    bl_status_t st = bl_connect(c);
    if (st != BL_OK) return st;

    if (write_all(c->fd, json, strlen(json)) < 0) {
        bl_dbg(c, "write failed");
        bl_disconnect(c);
        return BL_ERR_TRANSPORT;
    }
    char buf[16 * 1024];
    ssize_t n = read_until_brace(c->fd, buf, sizeof(buf));
    if (n <= 0) {
        bl_dbg(c, "read failed (%zd)", n);
        bl_disconnect(c);
        return BL_ERR_TRANSPORT;
    }
    *resp_out = strdup(buf);
    return (*resp_out != NULL) ? BL_OK : BL_ERR_OOM;
}

/* ─────────────────────── tiny JSON helpers ─────────────────────── */

static const char *json_locate(const char *json, const char *key)
{
    char needle[128];
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n <= 0 || (size_t)n >= sizeof(needle)) return NULL;
    const char *p = strstr(json, needle);
    if (p == NULL) return NULL;
    p += n;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int json_field_str(const char *json, const char *key,
                          char *out, size_t out_cap)
{
    const char *p = json_locate(json, key);
    if (p == NULL || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' && p[1] != '\0') {
            char ch = p[1];
            switch (ch) {
            case '"':  if (i + 1 >= out_cap) return 0; out[i++] = '"';  p += 2; break;
            case '\\': if (i + 1 >= out_cap) return 0; out[i++] = '\\'; p += 2; break;
            case '/':  if (i + 1 >= out_cap) return 0; out[i++] = '/';  p += 2; break;
            case 'n':  if (i + 1 >= out_cap) return 0; out[i++] = '\n'; p += 2; break;
            case 'r':  if (i + 1 >= out_cap) return 0; out[i++] = '\r'; p += 2; break;
            case 't':  if (i + 1 >= out_cap) return 0; out[i++] = '\t'; p += 2; break;
            default:   if (i + 1 >= out_cap) return 0; out[i++] = ch;   p += 2; break;
            }
        } else {
            if (i + 1 >= out_cap) return 0;
            out[i++] = *p++;
        }
    }
    if (*p != '"') return 0;
    out[i] = '\0';
    return 1;
}

static int json_field_int(const char *json, const char *key, long long *out)
{
    const char *p = json_locate(json, key);
    if (p == NULL) return 0;
    char *endp;
    long long v = strtoll(p, &endp, 10);
    if (endp == p) return 0;
    *out = v;
    return 1;
}

static int json_field_double(const char *json, const char *key, double *out)
{
    const char *p = json_locate(json, key);
    if (p == NULL) return 0;
    char *endp;
    double v = strtod(p, &endp);
    if (endp == p) return 0;
    *out = v;
    return 1;
}

static int json_field_b64(const char *json, const char *key,
                          unsigned char *out, size_t out_cap, size_t *out_len)
{
    char tmp[4096];
    if (!json_field_str(json, key, tmp, sizeof(tmp))) return 0;
    return blc_b64decode(tmp, strlen(tmp), out, out_cap, out_len) >= 0 ? 1 : 0;
}

/* If resp carries an "error" field, capture it on the client and return 1. */
static int capture_bridge_error(bl_client_t *c, const char *resp)
{
    if (strstr(resp, "\"error\"") == NULL) return 0;
    char err[512] = {0};
    json_field_str(resp, "error", err, sizeof(err));
    free(c->last_bridge_error);
    c->last_bridge_error = strdup(err[0] ? err : "(no detail)");
    bl_dbg(c, "bridge refused: %s", c->last_bridge_error);
    return 1;
}

/* ─────────────────────── transcript ─────────────────────── */

static int build_transcript(const unsigned char *client_nonce,
                            const unsigned char *client_pub65,
                            const unsigned char *client_share,
                            const unsigned char *session_id,
                            const unsigned char *bridge_share,
                            double issued_at_bd,
                            int64_t bridge_issued_at_unix,
                            uint32_t ttl_seconds,
                            unsigned char *transcript_out)
{
    unsigned char *p = transcript_out;
    memcpy(p, BL_TRANSCRIPT_HEADER, BL_TRANSCRIPT_HEADER_LEN); p += BL_TRANSCRIPT_HEADER_LEN;

    blc_le32(p, BL_CLIENT_NONCE_LEN); p += 4;
    memcpy(p, client_nonce, BL_CLIENT_NONCE_LEN); p += BL_CLIENT_NONCE_LEN;

    blc_le32(p, 65); p += 4;
    memcpy(p, client_pub65, 65); p += 65;

    blc_le32(p, BL_SHARE_LEN); p += 4;
    memcpy(p, client_share, BL_SHARE_LEN); p += BL_SHARE_LEN;

    blc_le32(p, BL_SESSION_ID_LEN); p += 4;
    memcpy(p, session_id, BL_SESSION_ID_LEN); p += BL_SESSION_ID_LEN;

    blc_le32(p, BL_SHARE_LEN); p += 4;
    memcpy(p, bridge_share, BL_SHARE_LEN); p += BL_SHARE_LEN;

    int64_t issued_at_unix = (int64_t)(issued_at_bd * 86400.0 + 0.5);
    blc_le32(p, 8); p += 4;
    blc_be64(p, (uint64_t)issued_at_unix); p += 8;

    blc_le32(p, 8); p += 4;
    blc_be64(p, (uint64_t)bridge_issued_at_unix); p += 8;

    blc_le32(p, 4); p += 4;
    p[0] = (unsigned char)((ttl_seconds >> 24) & 0xff);
    p[1] = (unsigned char)((ttl_seconds >> 16) & 0xff);
    p[2] = (unsigned char)((ttl_seconds >> 8)  & 0xff);
    p[3] = (unsigned char)(ttl_seconds & 0xff);
    p += 4;

    return (size_t)(p - transcript_out) == BL_TRANSCRIPT_TOTAL_LEN ? 1 : 0;
}

/* ─────────────────────── bridge identity fetches ─────────────────────── */

static bl_status_t fetch_pubkey(bl_client_t *c, const char *cmd_json,
                                unsigned char out65[BLC_PUB_UNCOMPRESSED])
{
    char *resp = NULL;
    bl_status_t st = bl_send_request(c, cmd_json, &resp);
    if (st != BL_OK) return st;
    if (capture_bridge_error(c, resp)) {
        free(resp);
        return BL_ERR_BRIDGE_REFUSED;
    }
    size_t n = 0;
    int ok = json_field_b64(resp, "publicKey", out65, BLC_PUB_UNCOMPRESSED, &n);
    free(resp);
    if (!ok || n != BLC_PUB_UNCOMPRESSED || out65[0] != 0x04) return BL_ERR_PROTOCOL;
    return BL_OK;
}

/* ─────────────────────── LINK_REGISTER ─────────────────────── */

bl_status_t bl_register(bl_client_t *c)
{
    if (c == NULL) return BL_ERR_INVALID_ARG;
    if (c->session_active) return BL_OK;

    bl_clear_bridge_error(c);

    /* Load any prior pin so the TOFU check is meaningful on the first
     * registration of this process. */
    if (!c->pin_loaded) {
        if (c->pin_store->vt.load(c->pin_store->vt.ctx, c->pin_pub65)) {
            c->pin_loaded = 1;
        }
    }

    unsigned char bridge_pub[BLC_PUB_UNCOMPRESSED];
    bl_status_t st = fetch_pubkey(c, "{\"cmd\":\"GET_PUBLIC_KEY\"}", bridge_pub);
    if (st != BL_OK) return st;

    unsigned char sep_pub[BLC_PUB_UNCOMPRESSED];
    st = fetch_pubkey(c, "{\"cmd\":\"GET_ENCLAVE_PUBLIC_KEY\"}", sep_pub);
    if (st != BL_OK) return st;

    if (c->pin_loaded) {
        if (memcmp(sep_pub, c->pin_pub65, BLC_PUB_UNCOMPRESSED) != 0) {
            bl_dbg(c, "TOFU mismatch: bridge SEP key changed");
            return BL_ERR_PIN_MISMATCH;
        }
    }

    /* Generate client material. */
    unsigned char client_nonce[BL_CLIENT_NONCE_LEN];
    unsigned char client_share[BL_SHARE_LEN];
    unsigned char eph_priv[32];
    unsigned char eph_pub[BLC_PUB_UNCOMPRESSED];
    if (RAND_bytes(client_nonce, sizeof(client_nonce)) != 1 ||
        RAND_bytes(client_share, sizeof(client_share)) != 1 ||
        !blc_secp_random_priv(eph_priv) ||
        !blc_secp_pub_uncompressed(eph_priv, eph_pub)) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_CRYPTO;
    }

    /* Build the §4.5.1 envelope plaintext. */
    double issued_at_bd = (double)time(NULL) / 86400.0;
    char client_pub_b64[128];
    char client_share_b64[64];
    blc_b64encode(eph_pub, BLC_PUB_UNCOMPRESSED, client_pub_b64, sizeof(client_pub_b64));
    blc_b64encode(client_share, BL_SHARE_LEN, client_share_b64, sizeof(client_share_b64));

    char plaintext_json[1024];
    int n = snprintf(plaintext_json, sizeof(plaintext_json),
        "{\"v\":1,"
        "\"clientPub\":\"%s\","
        "\"clientShare\":\"%s\","
        "\"issuedAtBd\":%.6f,"
        "\"ttlSeconds\":%d,"
        "\"agent\":{\"name\":\"%s\",\"version\":\"%s\","
                   "\"platform\":\"libbrightlink-c\"}}",
        client_pub_b64, client_share_b64, issued_at_bd,
        c->ttl_seconds, c->agent_name, c->agent_version);
    if (n < 0 || (size_t)n >= sizeof(plaintext_json)) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }

    unsigned char *envelope = NULL;
    size_t envelope_len = 0;
    if (!blc_ecies_encrypt(bridge_pub,
                           (const unsigned char *)plaintext_json, (size_t)n,
                           &envelope, &envelope_len)) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_CRYPTO;
    }

    size_t env_b64_cap = 4 * ((envelope_len + 2) / 3) + 1;
    char *env_b64 = malloc(env_b64_cap);
    char nonce_b64[32];
    if (env_b64 == NULL ||
        blc_b64encode(envelope, envelope_len, env_b64, env_b64_cap) < 0 ||
        blc_b64encode(client_nonce, sizeof(client_nonce), nonce_b64, sizeof(nonce_b64)) < 0) {
        free(envelope); free(env_b64);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_CRYPTO;
    }
    free(envelope);

    size_t req_cap = strlen(env_b64) + 256;
    char *request = malloc(req_cap);
    if (request == NULL) { free(env_b64); OPENSSL_cleanse(eph_priv, sizeof(eph_priv)); return BL_ERR_OOM; }
    int rn = snprintf(request, req_cap,
        "{\"cmd\":\"LINK_REGISTER\",\"protocolVersion\":1,"
        "\"clientNonce\":\"%s\",\"envelope\":\"%s\"}",
        nonce_b64, env_b64);
    free(env_b64);
    if (rn < 0 || (size_t)rn >= req_cap) {
        free(request);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }

    char *resp = NULL;
    bl_status_t send_st = bl_send_request(c, request, &resp);
    free(request);
    if (send_st != BL_OK) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return send_st;
    }

    if (capture_bridge_error(c, resp)) {
        free(resp);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_BRIDGE_REFUSED;
    }

    long long bridge_issued_at = 0;
    long long granted_ttl = 0;
    if (!json_field_int(resp, "bridgeIssuedAtUnix", &bridge_issued_at) ||
        !json_field_int(resp, "ttlSeconds", &granted_ttl)) {
        free(resp); OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }
    unsigned char session_id[BL_SESSION_ID_LEN];
    size_t sid_len = 0;
    if (!json_field_b64(resp, "sessionId", session_id, sizeof(session_id), &sid_len)
        || sid_len != BL_SESSION_ID_LEN) {
        free(resp); OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }

    /* Decrypt responseEnvelope. */
    size_t resp_env_b64_cap = strlen(resp) + 1;
    char *resp_env_b64 = malloc(resp_env_b64_cap);
    if (resp_env_b64 == NULL) { free(resp); OPENSSL_cleanse(eph_priv, sizeof(eph_priv)); return BL_ERR_OOM; }
    if (!json_field_str(resp, "responseEnvelope", resp_env_b64, resp_env_b64_cap)) {
        free(resp); free(resp_env_b64); OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }
    unsigned char *resp_envelope = malloc(resp_env_b64_cap);
    if (resp_envelope == NULL) {
        free(resp); free(resp_env_b64); OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_OOM;
    }
    size_t resp_env_len = 0;
    if (blc_b64decode(resp_env_b64, strlen(resp_env_b64),
                      resp_envelope, resp_env_b64_cap, &resp_env_len) < 0) {
        free(resp); free(resp_env_b64); free(resp_envelope);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }
    free(resp_env_b64);

    unsigned char *bridge_share = NULL;
    size_t bridge_share_len = 0;
    if (!blc_ecies_decrypt(eph_priv, resp_envelope, resp_env_len,
                           &bridge_share, &bridge_share_len)
        || bridge_share_len != BL_SHARE_LEN) {
        free(resp); free(resp_envelope); free(bridge_share);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_CRYPTO;
    }
    free(resp_envelope);

    /* Derive K_session (RFC §4.5.2). */
    unsigned char ikm[2 * BL_SHARE_LEN];
    memcpy(ikm, client_share, BL_SHARE_LEN);
    memcpy(ikm + BL_SHARE_LEN, bridge_share, BL_SHARE_LEN);
    unsigned char salt[BL_CLIENT_NONCE_LEN + BL_SESSION_ID_LEN];
    memcpy(salt, client_nonce, BL_CLIENT_NONCE_LEN);
    memcpy(salt + BL_CLIENT_NONCE_LEN, session_id, BL_SESSION_ID_LEN);

    unsigned char k_session[BL_SESSION_KEY_LEN];
    if (!blc_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt),
                         (const unsigned char *)BL_HKDF_INFO, BL_HKDF_INFO_LEN,
                         k_session, sizeof(k_session))) {
        free(resp);
        OPENSSL_cleanse(bridge_share, BL_SHARE_LEN); free(bridge_share);
        OPENSSL_cleanse(ikm, sizeof(ikm));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_CRYPTO;
    }
    OPENSSL_cleanse(ikm, sizeof(ikm));

    /* Verify SEP-signed transcript. */
    unsigned char transcript[BL_TRANSCRIPT_TOTAL_LEN];
    if (!build_transcript(client_nonce, eph_pub, client_share,
                          session_id, bridge_share,
                          issued_at_bd, (int64_t)bridge_issued_at,
                          (uint32_t)granted_ttl, transcript)) {
        free(resp);
        OPENSSL_cleanse(bridge_share, BL_SHARE_LEN); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }
    char sig_b64[1024];
    if (!json_field_str(resp, "transcriptSig", sig_b64, sizeof(sig_b64))) {
        free(resp);
        OPENSSL_cleanse(bridge_share, BL_SHARE_LEN); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }
    unsigned char sig_der[256];
    size_t sig_der_len = 0;
    if (blc_b64decode(sig_b64, strlen(sig_b64), sig_der, sizeof(sig_der), &sig_der_len) < 0) {
        free(resp);
        OPENSSL_cleanse(bridge_share, BL_SHARE_LEN); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_PROTOCOL;
    }
    if (!blc_verify_p256(sep_pub, transcript, sizeof(transcript),
                         sig_der, sig_der_len)) {
        free(resp);
        OPENSSL_cleanse(bridge_share, BL_SHARE_LEN); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return BL_ERR_CRYPTO;
    }
    free(resp);

    /* Pin the SEP key on first successful registration (write-through to
     * the configured store). Failure to persist the pin is non-fatal —
     * the in-memory pin works for this session, the user just gets
     * re-pinned next time if the file write failed. */
    if (!c->pin_loaded) {
        memcpy(c->pin_pub65, sep_pub, BLC_PUB_UNCOMPRESSED);
        c->pin_loaded = 1;
        if (!c->pin_store->vt.save(c->pin_store->vt.ctx, sep_pub)) {
            bl_dbg(c, "could not persist TOFU pin (non-fatal)");
        }
    }

    /* Commit session. */
    memcpy(c->session_id, session_id, BL_SESSION_ID_LEN);
    memcpy(c->session_key, k_session, BL_SESSION_KEY_LEN);
    c->session_active = 1;

    OPENSSL_cleanse(bridge_share, BL_SHARE_LEN); free(bridge_share);
    OPENSSL_cleanse(client_share, sizeof(client_share));
    OPENSSL_cleanse(client_nonce, sizeof(client_nonce));
    OPENSSL_cleanse(k_session, sizeof(k_session));
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
    return BL_OK;
}

/* ─────────────────────── LINK_GEO_GET ─────────────────────── */

static const char *format_string(bl_geo_format_t f)
{
    switch (f) {
    case BL_GEO_FORMAT_WGS84:       return "wgs84";
    case BL_GEO_FORMAT_BRIGHTSPACE: return "brightspace";
    case BL_GEO_FORMAT_BOTH:        return "both";
    }
    return "both";
}

bl_status_t bl_geo_get(bl_client_t *c, bl_geo_format_t format,
                       bl_geo_position_t *out)
{
    if (c == NULL || out == NULL) return BL_ERR_INVALID_ARG;
    bl_clear_bridge_error(c);

    if (!c->session_active) {
        bl_status_t st = bl_register(c);
        if (st != BL_OK) return st;
    }

    char request[128];
    int n = snprintf(request, sizeof(request),
                     "{\"cmd\":\"LINK_GEO_GET\",\"format\":\"%s\"}",
                     format_string(format));
    if (n < 0 || (size_t)n >= sizeof(request)) return BL_ERR_PROTOCOL;

    char *resp = NULL;
    bl_status_t st = bl_send_request(c, request, &resp);
    if (st != BL_OK) return st;

    if (capture_bridge_error(c, resp)) {
        free(resp);
        /* Distinguish user-denied from other refusals so callers can
         * react appropriately (e.g. UI vs. fall-through). */
        const char *msg = c->last_bridge_error ? c->last_bridge_error : "";
        if (strstr(msg, "denied") || strstr(msg, "denied by policy")
            || strstr(msg, "user denied")) {
            return BL_ERR_DENIED;
        }
        return BL_ERR_BRIDGE_REFUSED;
    }

    if (strstr(resp, "\"ok\":true") == NULL) {
        free(resp);
        return BL_ERR_PROTOCOL;
    }

    memset(out, 0, sizeof(*out));
    out->wgs84_alt_m = NAN;

    /* WGS84 block. */
    if (json_field_double(resp, "lat", &out->wgs84_lat) &&
        json_field_double(resp, "lon", &out->wgs84_lon)) {
        out->have_wgs84 = 1;
        json_field_double(resp, "alt_m", &out->wgs84_alt_m);
    }

    /* BrightSpace block — distinct field names so simple substring
     * search is safe. */
    if (json_field_double(resp, "x_bm", &out->brightspace_x_bm) &&
        json_field_double(resp, "y_bm", &out->brightspace_y_bm) &&
        json_field_double(resp, "z_bm", &out->brightspace_z_bm)) {
        out->have_brightspace = 1;
        json_field_double(resp, "epoch_bd", &out->brightspace_epoch_bd);
    }

    json_field_double(resp, "accuracy_m", &out->accuracy_m);
    json_field_double(resp, "brightdate", &out->brightdate);

    free(resp);

    if (!out->have_wgs84 && !out->have_brightspace) {
        /* Bridge claimed ok:true but emitted neither block — that's a
         * protocol violation, not a normal "no fix" condition (the
         * latter is signalled with ok:false + "geo: engine unavailable"). */
        return BL_ERR_PROTOCOL;
    }
    return BL_OK;
}
