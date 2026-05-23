/*
 * pin_store.c — bl_pin_store_t lifecycle and the custom-vtable adapter.
 *
 * The memory and file backends live in pin_store_memory.c and
 * pin_store_file.c respectively; both populate the same struct shape so
 * the rest of the library never branches on which backend it has.
 */

#include "brightlink/brightlink.h"
#include "pin_store_internal.h"

#include <stdlib.h>
#include <string.h>

bl_pin_store_t *bl_pin_store_custom(const bl_pin_store_vtable_t *vt)
{
    if (vt == NULL || vt->load == NULL || vt->save == NULL) return NULL;
    bl_pin_store_t *s = calloc(1, sizeof(*s));
    if (s == NULL) return NULL;
    s->vt = *vt;
    s->own_ctx = 0;   /* caller owns vt->ctx for custom stores */
    return s;
}

void bl_pin_store_free(bl_pin_store_t *s)
{
    if (s == NULL) return;
    if (s->vt.free_ != NULL) s->vt.free_(s->vt.ctx);
    free(s);
}
