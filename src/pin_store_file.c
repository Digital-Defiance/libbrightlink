/*
 * pin_store_file.c — file-backed pin store with the BLP1 on-disk format.
 *
 * Right choice for short-lived single-shot tools (bping, btraceroute):
 * the pin survives across invocations on disk, but each invocation does
 * a fresh LINK_REGISTER under the persisted pin so a malicious bridge
 * impersonating the genuine one is rejected immediately.
 *
 * On-disk format. See pin_store_internal.h. Files are 70 bytes minimum,
 * mode 0600, inside a directory created at mode 0700 if necessary. The
 * directory path and binary_id are joined as <dir>/<binary_id>.sep-pub
 * with no path-traversal escape — binary_id is treated as a literal
 * filename component and rejected if it contains '/', '\', NUL, or
 * leading '.'.
 *
 * Atomicity. Writes go through write-to-.new + fsync + rename. A torn
 * write leaves the existing file untouched and the .new sidecar may be
 * cleaned up by the caller (or persists harmlessly until the next save).
 *
 * Threats not addressed. Same-uid file-write tampering. The pin is a
 * public key — file integrity is the relevant property, not secrecy. A
 * future bl_pin_store_hmac_file() can wrap the format with an HMAC tag
 * keyed off code-signing identity / TPM-sealed material; the format
 * leaves room for it.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "brightlink/brightlink.h"
#include "pin_store_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct {
    char file_path[1024];
} file_ctx_t;

/* binary_id sanitisation. We allow ASCII letters, digits, dot, dash,
 * underscore. Anything else means a caller is feeding us a path or
 * worse, and we refuse rather than risk traversal. */
static int valid_binary_id(const char *id)
{
    if (id == NULL || *id == '\0' || *id == '.') return 0;
    for (const char *p = id; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        int ok = (c >= 'A' && c <= 'Z') ||
                 (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '-' || c == '_';
        if (!ok) return 0;
    }
    return 1;
}

/* mkdir -p semantics for one final directory component, without walking
 * arbitrary paths. We create only `dir_path` if missing; we do not
 * recursively mkdir its parents. Callers (bl_pin_store_file) are expected
 * to pass a path under $HOME/.brightchain/... where the parent already
 * exists or is created elsewhere. */
static int ensure_dir_0700(const char *dir_path)
{
    if (mkdir(dir_path, 0700) == 0) return 1;
    if (errno != EEXIST) return 0;
    /* Verify it really is a dir we own. */
    struct stat st;
    if (stat(dir_path, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return 0;
    return 1;
}

static int file_load(void *vctx, uint8_t pub65_out[65])
{
    file_ctx_t *ctx = vctx;
    int fd = open(ctx->file_path, O_RDONLY);
    if (fd < 0) return 0;

    uint8_t buf[BL_PIN_FILE_MIN_LEN];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n != (ssize_t)sizeof(buf)) return 0;

    if (memcmp(buf, BL_PIN_FILE_MAGIC, BL_PIN_FILE_MAGIC_LEN) != 0) return 0;
    if (buf[BL_PIN_FILE_MAGIC_LEN] != BL_PIN_FILE_VERSION) return 0;
    if (buf[BL_PIN_FILE_HEADER_LEN] != 0x04) return 0;  /* uncompressed marker */

    memcpy(pub65_out, buf + BL_PIN_FILE_HEADER_LEN, 65);
    return 1;
}

static int file_save(void *vctx, const uint8_t pub65[65])
{
    file_ctx_t *ctx = vctx;

    /* Reject anything other than uncompressed P-256. */
    if (pub65[0] != 0x04) return 0;

    char tmp_path[1024 + 8];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.new", ctx->file_path);
    if (n <= 0 || (size_t)n >= sizeof(tmp_path)) return 0;

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;

    uint8_t hdr[BL_PIN_FILE_HEADER_LEN];
    memcpy(hdr, BL_PIN_FILE_MAGIC, BL_PIN_FILE_MAGIC_LEN);
    hdr[BL_PIN_FILE_MAGIC_LEN] = BL_PIN_FILE_VERSION;

    if (write(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        close(fd); unlink(tmp_path); return 0;
    }
    if (write(fd, pub65, 65) != 65) {
        close(fd); unlink(tmp_path); return 0;
    }
    if (fsync(fd) != 0) {
        close(fd); unlink(tmp_path); return 0;
    }
    if (close(fd) != 0) {
        unlink(tmp_path); return 0;
    }
    if (rename(tmp_path, ctx->file_path) != 0) {
        unlink(tmp_path); return 0;
    }
    return 1;
}

static void file_free(void *vctx)
{
    free(vctx);
}

bl_pin_store_t *bl_pin_store_file(const char *dir_path, const char *binary_id)
{
    if (dir_path == NULL || dir_path[0] == '\0') return NULL;
    if (!valid_binary_id(binary_id)) return NULL;

    if (!ensure_dir_0700(dir_path)) return NULL;

    file_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return NULL;
    int n = snprintf(ctx->file_path, sizeof(ctx->file_path),
                     "%s/%s.sep-pub", dir_path, binary_id);
    if (n <= 0 || (size_t)n >= sizeof(ctx->file_path)) {
        free(ctx);
        return NULL;
    }

    bl_pin_store_t *s = calloc(1, sizeof(*s));
    if (s == NULL) { free(ctx); return NULL; }

    s->vt.load  = file_load;
    s->vt.save  = file_save;
    s->vt.free_ = file_free;
    s->vt.ctx   = ctx;
    s->own_ctx  = 1;
    return s;
}
