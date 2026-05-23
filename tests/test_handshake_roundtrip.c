/*
 * test_handshake_roundtrip.c — end-to-end integration test for libBrightLink.
 *
 * Forks mock-brightnexus, performs a full LINK_REGISTER + LINK_GEO_GET
 * cycle, verifies the response carries the expected San Francisco fixture
 * (37.7749, -122.4194 with the matching BrightSpace block), and checks
 * that the file-backed pin store wrote a BLP1-formatted pin.
 *
 * No assumptions about a running BrightNexus instance — this test owns
 * the entire bridge lifecycle.
 */

/* mkdtemp/kill require POSIX.1-2008 feature exposure on glibc. */
#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "brightlink/brightlink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <math.h>
#include <time.h>

/* Path to the mock binary. The meson test runner sets MESON_BUILD_ROOT
 * to the build tree; we resolve relative to that. Falls back to a path
 * relative to the cwd for ad-hoc runs. */
static const char *resolve_mock_path(char *buf, size_t cap)
{
    const char *build = getenv("MESON_BUILD_ROOT");
    if (build != NULL && build[0] != '\0') {
        snprintf(buf, cap, "%s/tests/mock-brightnexus/mock-brightnexus", build);
        if (access(buf, X_OK) == 0) return buf;
    }
    /* Direct invocation from within build/ */
    snprintf(buf, cap, "tests/mock-brightnexus/mock-brightnexus");
    if (access(buf, X_OK) == 0) return buf;
    snprintf(buf, cap, "./mock-brightnexus");
    if (access(buf, X_OK) == 0) return buf;
    return NULL;
}

static int wait_for_ready(int rfd)
{
    /* Read up to "ready\n" or 256 bytes, whichever comes first. */
    char buf[256];
    size_t pos = 0;
    while (pos < sizeof(buf) - 1) {
        ssize_t n = read(rfd, buf + pos, 1);
        if (n <= 0) return 0;
        if (buf[pos] == '\n') {
            buf[pos] = '\0';
            return strncmp(buf, "ready", 5) == 0;
        }
        pos++;
    }
    return 0;
}

#define FAIL(msg) do { fprintf(stderr, "FAIL: " msg "\n"); return 1; } while (0)
#define EXPECT_OK(call) do { \
    bl_status_t _s = (call); \
    if (_s != BL_OK) { \
        fprintf(stderr, "FAIL: " #call " returned %s (%d)\n", bl_strerror(_s), _s); \
        return 1; \
    } \
} while (0)

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    /* Locate mock binary. */
    char mock_path[1024];
    if (resolve_mock_path(mock_path, sizeof(mock_path)) == NULL)
        FAIL("could not locate mock-brightnexus binary");

    /* Build a tmpdir for socket + pin store. */
    char tmpl[64];
    snprintf(tmpl, sizeof(tmpl), "/tmp/libbrightlink-test.XXXXXX");
    char *tmpdir = mkdtemp(tmpl);
    if (tmpdir == NULL) FAIL("mkdtemp");
    char sock_path[1024];
    snprintf(sock_path, sizeof(sock_path), "%s/brightnexus.sock", tmpdir);
    char pin_dir[1024];
    snprintf(pin_dir, sizeof(pin_dir), "%s/pins", tmpdir);

    /* Pipe for "ready" sync. */
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) FAIL("pipe");

    /* Fork mock. */
    pid_t pid = fork();
    if (pid < 0) FAIL("fork");
    if (pid == 0) {
        close(sync_pipe[0]);
        if (dup2(sync_pipe[1], STDOUT_FILENO) < 0) _exit(2);
        close(sync_pipe[1]);
        execl(mock_path, "mock-brightnexus", sock_path, (char *)NULL);
        _exit(2);
    }
    close(sync_pipe[1]);

    /* Wait for ready. */
    if (!wait_for_ready(sync_pipe[0])) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        FAIL("mock did not emit ready line");
    }
    close(sync_pipe[0]);

    int rc = 0;

    /* Build client and exercise. */
    {
        bl_pin_store_t *store = bl_pin_store_file(pin_dir, "test_handshake");
        if (store == NULL) {
            fprintf(stderr, "FAIL: bl_pin_store_file returned NULL\n");
            rc = 1; goto cleanup;
        }

        bl_client_config_t cfg = {
            .socket_path  = sock_path,
            .agent_name   = "libbrightlink-test",
            .pin_store    = store,
            .ttl_seconds  = 600,
            .debug_stream = stderr,
        };
        bl_client_t *c = bl_client_new(&cfg);
        if (c == NULL) {
            bl_pin_store_free(store);
            fprintf(stderr, "FAIL: bl_client_new returned NULL\n");
            rc = 1; goto cleanup;
        }

        /* Explicit register so we can assert it succeeds independently
         * of bl_geo_get's lazy-register behaviour. */
        bl_status_t st = bl_register(c);
        if (st != BL_OK) {
            fprintf(stderr, "FAIL: bl_register: %s (%d) — bridge said: %s\n",
                    bl_strerror(st), st,
                    bl_last_bridge_error(c) ? bl_last_bridge_error(c) : "(no detail)");
            bl_client_free(c);
            rc = 1; goto cleanup;
        }

        /* Geo. */
        bl_geo_position_t pos;
        st = bl_geo_get(c, BL_GEO_FORMAT_BOTH, &pos);
        if (st != BL_OK) {
            fprintf(stderr, "FAIL: bl_geo_get: %s (%d)\n", bl_strerror(st), st);
            bl_client_free(c);
            rc = 1; goto cleanup;
        }

        /* Verify the fixture (San Francisco). */
        if (!pos.have_wgs84) {
            fprintf(stderr, "FAIL: response missing wgs84 block\n");
            rc = 1;
        }
        if (!pos.have_brightspace) {
            fprintf(stderr, "FAIL: response missing brightspace block\n");
            rc = 1;
        }
        if (fabs(pos.wgs84_lat - 37.7749) > 1e-4) {
            fprintf(stderr, "FAIL: wgs84_lat = %.6f, expected ~37.7749\n", pos.wgs84_lat);
            rc = 1;
        }
        if (fabs(pos.wgs84_lon - (-122.4194)) > 1e-4) {
            fprintf(stderr, "FAIL: wgs84_lon = %.6f, expected ~-122.4194\n", pos.wgs84_lon);
            rc = 1;
        }
        if (fabs(pos.brightspace_x_bm - (-0.009044)) > 1e-5) {
            fprintf(stderr, "FAIL: brightspace_x_bm = %.6f, expected ~-0.009044\n", pos.brightspace_x_bm);
            rc = 1;
        }

        /* Verify pin file was written with the BLP1 magic. */
        char pin_path[1100];
        snprintf(pin_path, sizeof(pin_path), "%s/test_handshake.sep-pub", pin_dir);
        int pf = open(pin_path, O_RDONLY);
        if (pf < 0) {
            fprintf(stderr, "FAIL: pin file %s missing\n", pin_path);
            rc = 1;
        } else {
            unsigned char hdr[5];
            ssize_t n = read(pf, hdr, sizeof(hdr));
            close(pf);
            if (n != 5 || memcmp(hdr, "BLP1", 4) != 0 || hdr[4] != 1) {
                fprintf(stderr, "FAIL: pin file lacks BLP1 magic + version\n");
                rc = 1;
            }
            /* Verify mode 0600. */
            struct stat st_pin;
            if (stat(pin_path, &st_pin) == 0 && (st_pin.st_mode & 0777) != 0600) {
                fprintf(stderr, "FAIL: pin file mode %04o, expected 0600\n",
                        (unsigned)(st_pin.st_mode & 0777));
                rc = 1;
            }
        }

        bl_client_free(c);
    }

    if (rc == 0) printf("ok %s\n", argv[0]);

cleanup:
    /* Stop mock. */
    kill(pid, SIGTERM);
    int wait_rc;
    waitpid(pid, &wait_rc, 0);

    /* Clean tmpdir best-effort. */
    char rm_cmd[1100];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", tmpdir);
    (void)system(rm_cmd);

    return rc;
}
