/*
 * test_pin_store_file.c — verify the public file-backed pin store contract.
 *
 * The internal vtable shape (load/save callbacks) is implementation
 * detail; the public guarantees are:
 *
 *   1. bl_pin_store_file(dir_path, binary_id) returns NULL when
 *      binary_id contains separators, traversal markers, or NUL — that
 *      is, when path safety would otherwise be violated.
 *   2. The returned store is freeable via bl_pin_store_free without
 *      leaking or crashing.
 *
 * The on-disk format (BLP1 magic + version + 65-byte pubkey + mode 0600
 * inside a 0700 dir) and the round-trip across save/load are exercised
 * by test_handshake_roundtrip.c, which goes through bl_register.
 *
 * Doing it this way keeps the public/private boundary intact: this test
 * never touches struct internals.
 */

/* mkdtemp is XSI/POSIX.1-2008; glibc only exposes it under
 * _DEFAULT_SOURCE / _XOPEN_SOURCE >= 500. Define before any include. */
#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 700

#include "brightlink/brightlink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int fail(const char *msg)
{
    fprintf(stderr, "FAIL: %s\n", msg);
    return 1;
}

int main(void)
{
    char tmpl[64];
    snprintf(tmpl, sizeof(tmpl), "/tmp/libbrightlink-pin.XXXXXX");
    char *tmpdir = mkdtemp(tmpl);
    if (tmpdir == NULL) return fail("mkdtemp");

    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "%s/pins", tmpdir);

    /* Valid binary_id → non-NULL store. */
    {
        bl_pin_store_t *s = bl_pin_store_file(dir_path, "test");
        if (s == NULL) return fail("valid binary_id returned NULL");
        bl_pin_store_free(s);

        /* Verify the directory was created at mode 0700. */
        struct stat st;
        if (stat(dir_path, &st) != 0) return fail("dir_path not created");
        if (!S_ISDIR(st.st_mode)) return fail("dir_path is not a directory");
        if ((st.st_mode & 0777) != 0700) {
            fprintf(stderr, "FAIL: dir mode %04o, expected 0700\n",
                    (unsigned)(st.st_mode & 0777));
            return 1;
        }
    }

    /* Path-traversal guards: each of these should refuse with NULL. */
    struct { const char *id; const char *why; } bad[] = {
        { "../escape",  "parent traversal" },
        { "with/slash", "embedded slash"   },
        { ".hidden",    "leading dot"      },
        { "",           "empty"            },
        { NULL,         "NULL"             },
        { "trailing/",  "trailing slash"   },
        { "spa ce",     "space"            },     /* not in our allowed set */
        { "back\\slash", "backslash"       },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bl_pin_store_t *s = bl_pin_store_file(dir_path, bad[i].id);
        if (s != NULL) {
            fprintf(stderr, "FAIL: bl_pin_store_file accepted %s id (%s)\n",
                    bad[i].why, bad[i].id ? bad[i].id : "(NULL)");
            bl_pin_store_free(s);
            return 1;
        }
    }

    /* NULL dir_path is also rejected. */
    if (bl_pin_store_file(NULL, "test") != NULL)
        return fail("NULL dir_path accepted");

    /* Cleanup. */
    char rm[1100];
    snprintf(rm, sizeof(rm), "rm -rf %s", tmpdir);
    (void)system(rm);

    printf("ok pin-store-file\n");
    return 0;
}
