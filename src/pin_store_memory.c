/*
 * pin_store_memory.c — in-process pin store.
 *
 * Pins live for the lifetime of the bl_pin_store_t. Right choice for
 * long-lived processes (interactive shells, daemons): the SEP key
 * survives across multiple LINK_REGISTER calls inside the same process,
 * but doesn't survive process exit. Tools that want continuity across
 * invocations should use bl_pin_store_file() instead.
 */

#include "brightlink/brightlink.h"
#include "pin_store_internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    int     pinned;
    uint8_t pub65[65];
} mem_ctx_t;

static int mem_load(void *vctx, uint8_t pub65_out[65])
{
    mem_ctx_t *ctx = vctx;
    if (!ctx->pinned) return 0;
    memcpy(pub65_out, ctx->pub65, 65);
    return 1;
}

static int mem_save(void *vctx, const uint8_t pub65[65])
{
    mem_ctx_t *ctx = vctx;
    memcpy(ctx->pub65, pub65, 65);
    ctx->pinned = 1;
    return 1;
}

static void mem_free(void *vctx)
{
    free(vctx);
}

bl_pin_store_t *bl_pin_store_memory(void)
{
    mem_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return NULL;

    bl_pin_store_t *s = calloc(1, sizeof(*s));
    if (s == NULL) { free(ctx); return NULL; }

    s->vt.load  = mem_load;
    s->vt.save  = mem_save;
    s->vt.free_ = mem_free;
    s->vt.ctx   = ctx;
    s->own_ctx  = 1;
    return s;
}
