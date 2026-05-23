/*
 * pin_store_internal.h — implementation-private layout for bl_pin_store_t.
 *
 * NOT a public header. The library's public surface is brightlink.h;
 * pin store internals only need to be visible across the small set of
 * pin_store_*.c files.
 */

#ifndef BL_PIN_STORE_INTERNAL_H
#define BL_PIN_STORE_INTERNAL_H

#include <stdint.h>
#include "brightlink/brightlink.h"

struct bl_pin_store_s {
    bl_pin_store_vtable_t vt;
    int                   own_ctx;   /* 1 if vt.ctx must be free()'d on store free */
};

/* On-disk pin file layout (file mode 0600 inside dir mode 0700):
 *
 *   offset 0..3   "BLP1" magic (4 bytes ASCII)
 *   offset 4      format version (uint8, currently 1)
 *   offset 5..69  uncompressed P-256 public key (65 bytes, leading 0x04)
 *   offset 70+    reserved for future fields (key-id, pinned-at, etc.)
 *
 * Total minimum file size: 70 bytes. Loaders MUST tolerate trailing
 * bytes (longer files are valid; they carry future-format additions).
 * Loaders MUST reject files with the wrong magic or version.
 *
 * Pins are PUBLIC keys, not secrets. The on-disk format protects
 * INTEGRITY (file mode + atomic writes), not confidentiality. See
 * packaging/pin-format.md for the rationale.
 */
#define BL_PIN_FILE_MAGIC      "BLP1"
#define BL_PIN_FILE_MAGIC_LEN  4
#define BL_PIN_FILE_VERSION    1
#define BL_PIN_FILE_HEADER_LEN 5    /* magic + version */
#define BL_PIN_FILE_MIN_LEN    (BL_PIN_FILE_HEADER_LEN + 65)

#endif /* BL_PIN_STORE_INTERNAL_H */
