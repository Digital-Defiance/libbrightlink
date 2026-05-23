/*
 * mock-brightnexus.c — minimal BrightLink bridge for iputils tests.
 *
 * Implements the bridge half of the four EBP/1+BrightLink commands the
 * iputils tools use:
 *
 *   GET_PUBLIC_KEY            — return the bridge's secp256k1 ECIES key.
 *   GET_ENCLAVE_PUBLIC_KEY    — return the bridge's P-256 SEP key.
 *   LINK_REGISTER             — DD-ECIES envelope decode, transcript
 *                               assembly, P-256 transcript signature.
 *   LINK_GEO_GET              — fixed-fixture position + brightspace ECEF.
 *
 * The mock is single-threaded, accepts one connection at a time, and runs
 * until SIGTERM. Both keypairs are freshly generated at startup and live
 * only in process memory — that's enough to exercise the client's
 * LINK_REGISTER → LINK_GEO_GET path including the TOFU pin write.
 *
 * Wire-format and crypto choices are deliberately minimal:
 *   - Fixed geo fixture (San Francisco) returned by every LINK_GEO_GET.
 *     The test only needs to verify the [brightlink:ecef] tag flows; the
 *     specific coordinates don't matter as long as they're well-formed.
 *   - Granted TTL clamped to whatever the client asked for, capped at 1h.
 *   - No ACL gating, no peer attestation, no rate limiting. The mock
 *     covers the protocol, not the policy surface — see bsh's
 *     test-harness/mock-brightnexus for the full policy mock.
 *
 * Usage:
 *   mock-brightnexus <socket-path>
 *
 *   The mock binds <socket-path> with mode 0600, prints "ready" + newline
 *   to stdout (synchronisation point for callers), and serves connections
 *   until SIGTERM or SIGINT.
 */

#include "brightlink/brightlink_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#define TRANSCRIPT_HEADER     "BrightLink v1 transcript\0"
#define TRANSCRIPT_HEADER_LEN 25
#define TRANSCRIPT_TOTAL_LEN  238

#define HKDF_INFO          "brightlink-session-key-v1"
#define HKDF_INFO_LEN      (sizeof(HKDF_INFO) - 1)

#define MAX_TTL_SECONDS    3600
#define SHARE_LEN          32
#define SESSION_ID_LEN     16
#define CLIENT_NONCE_LEN   16

/* ------------------------------------------------------------------ */
/*  Lifecycle: SIGTERM stops the accept loop                            */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_stop = 0;
static char g_socket_path[1024] = "";

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void cleanup_socket(void)
{
    if (g_socket_path[0] != '\0') unlink(g_socket_path);
}

/* ------------------------------------------------------------------ */
/*  Bridge identity                                                     */
/* ------------------------------------------------------------------ */

static unsigned char g_secp_priv[32];
static unsigned char g_secp_pub65[BLC_PUB_UNCOMPRESSED];
static unsigned char g_p256_priv[32];
static unsigned char g_p256_pub65[BLC_PUB_UNCOMPRESSED];

static int generate_identity(void)
{
    if (!blc_secp_random_priv(g_secp_priv)) return 0;
    if (!blc_secp_pub_uncompressed(g_secp_priv, g_secp_pub65)) return 0;
    if (!blc_p256_keygen(g_p256_priv, g_p256_pub65)) return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Tiny JSON helpers (locate, extract string)                          */
/* ------------------------------------------------------------------ */

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

/* Extract a string field. The mock only sees the client's REGISTER
 * envelope b64 and clientNonce — neither needs JSON unescaping, both are
 * pure ASCII base64 chars. */
static int json_field_str(const char *json, const char *key, char *out, size_t out_cap)
{
    const char *p = json_locate(json, key);
    if (p == NULL || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p != '\0' && *p != '"' && i + 1 < out_cap) out[i++] = *p++;
    if (*p != '"') return 0;
    out[i] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/*  238-byte transcript construction                                    */
/* ------------------------------------------------------------------ */

static void build_transcript(const unsigned char *client_nonce,
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
    memcpy(p, TRANSCRIPT_HEADER, TRANSCRIPT_HEADER_LEN); p += TRANSCRIPT_HEADER_LEN;

    blc_le32(p, CLIENT_NONCE_LEN); p += 4;
    memcpy(p, client_nonce, CLIENT_NONCE_LEN); p += CLIENT_NONCE_LEN;

    blc_le32(p, 65); p += 4;
    memcpy(p, client_pub65, 65); p += 65;

    blc_le32(p, SHARE_LEN); p += 4;
    memcpy(p, client_share, SHARE_LEN); p += SHARE_LEN;

    blc_le32(p, SESSION_ID_LEN); p += 4;
    memcpy(p, session_id, SESSION_ID_LEN); p += SESSION_ID_LEN;

    blc_le32(p, SHARE_LEN); p += 4;
    memcpy(p, bridge_share, SHARE_LEN); p += SHARE_LEN;

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
}

/* ------------------------------------------------------------------ */
/*  Wire framing — write a JSON line, read a top-level JSON object.     */
/* ------------------------------------------------------------------ */

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
        char c = buf[pos++];
        if (escaped) { escaped = 0; continue; }
        if (in_string) {
            if (c == '\\') escaped = 1;
            else if (c == '"') in_string = 0;
            continue;
        }
        if (c == '"') { in_string = 1; continue; }
        if (c == '{') { depth++; seen_open = 1; }
        else if (c == '}') {
            if (--depth == 0 && seen_open) { buf[pos] = '\0'; return (ssize_t)pos; }
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Command handlers                                                     */
/* ------------------------------------------------------------------ */

static int handle_get_public_key(int fd)
{
    char pub_b64[128];
    blc_b64encode(g_secp_pub65, BLC_PUB_UNCOMPRESSED, pub_b64, sizeof(pub_b64));
    char resp[256];
    int n = snprintf(resp, sizeof(resp), "{\"ok\":true,\"publicKey\":\"%s\"}", pub_b64);
    return write_all(fd, resp, (size_t)n) > 0 ? 1 : 0;
}

static int handle_get_enclave_public_key(int fd)
{
    char pub_b64[128];
    blc_b64encode(g_p256_pub65, BLC_PUB_UNCOMPRESSED, pub_b64, sizeof(pub_b64));
    char resp[256];
    int n = snprintf(resp, sizeof(resp), "{\"ok\":true,\"publicKey\":\"%s\"}", pub_b64);
    return write_all(fd, resp, (size_t)n) > 0 ? 1 : 0;
}

/* LINK_REGISTER. Decrypt the §4.5.1 envelope plaintext to recover the
 * client's contributions, build the transcript, sign with our P-256 key,
 * and ECIES-encrypt our bridgeShare back to the client. */
static int handle_link_register(int fd, const char *req)
{
    /* Pull clientNonce and envelope from the request. */
    char nonce_b64[64];
    if (!json_field_str(req, "clientNonce", nonce_b64, sizeof(nonce_b64))) return 0;
    unsigned char client_nonce[CLIENT_NONCE_LEN];
    size_t nlen = 0;
    if (blc_b64decode(nonce_b64, strlen(nonce_b64), client_nonce, sizeof(client_nonce), &nlen) < 0
        || nlen != CLIENT_NONCE_LEN) return 0;

    /* The envelope can be sized arbitrarily — heap-allocate a buffer big
     * enough for the inflated b64 form (we accept up to 4 KiB inner
     * plaintext, which is well above the §4.5.1 schema's typical size). */
    char env_b64[8192];
    if (!json_field_str(req, "envelope", env_b64, sizeof(env_b64))) return 0;
    size_t env_b64_len = strlen(env_b64);
    unsigned char *envelope = malloc(env_b64_len);
    if (envelope == NULL) return 0;
    size_t env_len = 0;
    if (blc_b64decode(env_b64, env_b64_len, envelope, env_b64_len, &env_len) < 0) {
        free(envelope); return 0;
    }

    unsigned char *plaintext = NULL;
    size_t pt_len = 0;
    if (!blc_ecies_decrypt(g_secp_priv, envelope, env_len, &plaintext, &pt_len)) {
        free(envelope);
        return 0;
    }
    free(envelope);

    /* The plaintext is JSON. Pull clientPub (b64), clientShare (b64),
     * issuedAtBd (number), ttlSeconds (number). */
    char *pt_str = malloc(pt_len + 1);
    if (pt_str == NULL) { free(plaintext); return 0; }
    memcpy(pt_str, plaintext, pt_len);
    pt_str[pt_len] = '\0';
    free(plaintext);

    char client_pub_b64[256];
    char client_share_b64[64];
    if (!json_field_str(pt_str, "clientPub", client_pub_b64, sizeof(client_pub_b64)) ||
        !json_field_str(pt_str, "clientShare", client_share_b64, sizeof(client_share_b64))) {
        free(pt_str);
        return 0;
    }

    /* issuedAtBd / ttlSeconds — strtod / strtoll directly on the located
     * value pointer, no further parsing needed. */
    const char *p_iss = json_locate(pt_str, "issuedAtBd");
    const char *p_ttl = json_locate(pt_str, "ttlSeconds");
    if (p_iss == NULL || p_ttl == NULL) { free(pt_str); return 0; }
    double issued_at_bd = strtod(p_iss, NULL);
    long long requested_ttl = strtoll(p_ttl, NULL, 10);
    if (requested_ttl < 1) requested_ttl = 1;
    if (requested_ttl > MAX_TTL_SECONDS) requested_ttl = MAX_TTL_SECONDS;
    free(pt_str);

    unsigned char client_pub65[BLC_PUB_UNCOMPRESSED];
    size_t cp_len = 0;
    if (blc_b64decode(client_pub_b64, strlen(client_pub_b64),
                      client_pub65, sizeof(client_pub65), &cp_len) < 0
        || cp_len != BLC_PUB_UNCOMPRESSED) return 0;

    unsigned char client_share[SHARE_LEN];
    size_t cs_len = 0;
    if (blc_b64decode(client_share_b64, strlen(client_share_b64),
                      client_share, sizeof(client_share), &cs_len) < 0
        || cs_len != SHARE_LEN) return 0;

    /* Bridge contributions. */
    unsigned char session_id[SESSION_ID_LEN];
    unsigned char bridge_share[SHARE_LEN];
    if (RAND_bytes(session_id, sizeof(session_id)) != 1) return 0;
    if (RAND_bytes(bridge_share, sizeof(bridge_share)) != 1) return 0;

    int64_t bridge_issued_at_unix = (int64_t)time(NULL);

    /* Build and sign the §4.5.3 transcript. */
    unsigned char transcript[TRANSCRIPT_TOTAL_LEN];
    build_transcript(client_nonce, client_pub65, client_share,
                     session_id, bridge_share,
                     issued_at_bd, bridge_issued_at_unix,
                     (uint32_t)requested_ttl,
                     transcript);

    unsigned char sig_der[256];
    size_t sig_len = 0;
    if (!blc_sign_p256(g_p256_priv, transcript, sizeof(transcript),
                       sig_der, sizeof(sig_der), &sig_len)) {
        return 0;
    }

    /* ECIES-encrypt bridgeShare back to the client's clientPub. */
    unsigned char *resp_envelope = NULL;
    size_t resp_env_len = 0;
    if (!blc_ecies_encrypt(client_pub65, bridge_share, SHARE_LEN,
                           &resp_envelope, &resp_env_len)) {
        return 0;
    }

    /* Build the response JSON. */
    char sid_b64[32], sig_b64[1024], env_resp_b64[2048];
    blc_b64encode(session_id, SESSION_ID_LEN, sid_b64, sizeof(sid_b64));
    blc_b64encode(sig_der, sig_len, sig_b64, sizeof(sig_b64));
    blc_b64encode(resp_envelope, resp_env_len, env_resp_b64, sizeof(env_resp_b64));
    free(resp_envelope);

    char resp[4096];
    int n = snprintf(resp, sizeof(resp),
        "{\"ok\":true,"
        "\"sessionId\":\"%s\","
        "\"bridgeIssuedAtUnix\":%lld,"
        "\"ttlSeconds\":%lld,"
        "\"responseEnvelope\":\"%s\","
        "\"transcriptSig\":\"%s\"}",
        sid_b64, (long long)bridge_issued_at_unix,
        (long long)requested_ttl,
        env_resp_b64, sig_b64);
    if (n < 0 || (size_t)n >= sizeof(resp)) return 0;

    return write_all(fd, resp, (size_t)n) > 0 ? 1 : 0;
}

static int handle_link_geo_get(int fd)
{
    /* San Francisco fixture, with a BrightSpace block so the iputils
     * client comes out with the [brightlink:ecef] tag. The exact values
     * mirror the reference fixture in bsh's test-harness for parity. */
    static const char fixture[] =
        "{\"ok\":true,"
        "\"position\":{"
            "\"wgs84\":{\"lat\":37.7749,\"lon\":-122.4194,\"alt_m\":100.0},"
            "\"brightspace\":{"
                "\"x_bm\":-0.009044,"
                "\"y_bm\":-0.014210,"
                "\"z_bm\":0.012970,"
                "\"epoch_bd\":9638.521}},"
        "\"accuracy_m\":15.0,"
        "\"brightdate\":9638.521}";
    return write_all(fd, fixture, sizeof(fixture) - 1) > 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  Connection dispatch                                                  */
/* ------------------------------------------------------------------ */

static void serve_connection(int fd)
{
    /* Multiple commands per connection — the iputils client issues
     * GET_PUBLIC_KEY, GET_ENCLAVE_PUBLIC_KEY, LINK_REGISTER, LINK_GEO_GET
     * in sequence on a single TCP-style flow. */
    char buf[16 * 1024];
    while (!g_stop) {
        ssize_t n = read_until_brace(fd, buf, sizeof(buf));
        if (n <= 0) return;

        if (strstr(buf, "GET_PUBLIC_KEY") && !strstr(buf, "ENCLAVE")) {
            if (!handle_get_public_key(fd)) return;
        } else if (strstr(buf, "GET_ENCLAVE_PUBLIC_KEY")) {
            if (!handle_get_enclave_public_key(fd)) return;
        } else if (strstr(buf, "LINK_REGISTER")) {
            if (!handle_link_register(fd, buf)) return;
        } else if (strstr(buf, "LINK_GEO_GET")) {
            if (!handle_link_geo_get(fd)) return;
        } else {
            /* Unknown — return the EBP/1 generic. */
            const char err[] =
                "{\"ok\":false,\"error\":\"Unknown command\"}";
            if (write_all(fd, err, sizeof(err) - 1) <= 0) return;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <socket-path>\n", argv[0]);
        return 2;
    }
    const char *sock_path = argv[1];
    if (strlen(sock_path) >= sizeof(g_socket_path)) {
        fprintf(stderr, "mock-brightnexus: socket path too long\n");
        return 2;
    }
    snprintf(g_socket_path, sizeof(g_socket_path), "%s", sock_path);

    /* Bind socket. We stage the same first-bind safety the bridge uses
     * (refuse to overwrite an existing file at the path), but for tests
     * the parent harness deliberately starts from a clean tmpdir so a
     * leftover file means a previous test crashed. We unlink and warn. */
    if (unlink(sock_path) == 0) {
        fprintf(stderr, "mock-brightnexus: removed stale socket %s\n", sock_path);
    } else if (errno != ENOENT) {
        fprintf(stderr, "mock-brightnexus: unlink(%s): %s\n", sock_path, strerror(errno));
        return 1;
    }

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        fprintf(stderr, "mock-brightnexus: socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock_path);

    /* Restrict mode to the user before binding so the file shows up with
     * 0600 from the start. */
    mode_t old_umask = umask(0177);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        umask(old_umask);
        fprintf(stderr, "mock-brightnexus: bind(%s): %s\n", sock_path, strerror(errno));
        close(sfd);
        return 1;
    }
    umask(old_umask);

    if (listen(sfd, 16) < 0) {
        fprintf(stderr, "mock-brightnexus: listen: %s\n", strerror(errno));
        close(sfd);
        cleanup_socket();
        return 1;
    }

    /* Wire up signal handlers + atexit cleanup. */
    atexit(cleanup_socket);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    /* Ignore SIGPIPE so a client closing mid-write doesn't kill the mock. */
    signal(SIGPIPE, SIG_IGN);

    if (!generate_identity()) {
        fprintf(stderr, "mock-brightnexus: identity generation failed\n");
        close(sfd);
        return 1;
    }

    /* Synchronisation point for the test harness: it blocks on reading
     * "ready\n" from our stdout before connecting any clients. */
    printf("ready\n");
    fflush(stdout);

    while (!g_stop) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        serve_connection(cfd);
        close(cfd);
    }

    close(sfd);
    return 0;
}
