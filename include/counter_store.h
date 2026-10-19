#ifndef SECURE_ECU_COUNTER_STORE_H
#define SECURE_ECU_COUNTER_STORE_H

#include <stddef.h>
#include <stdint.h>

#define CSTORE_PATH_MAX 4096U

typedef enum {
    CSTORE_OK = 0,
    CSTORE_NOT_FOUND,   /* no file yet: caller may start at 0 */
    CSTORE_CORRUPT,     /* file exists but is not a valid counter record */
    CSTORE_IO_ERROR,    /* read/write/rename failed */
    CSTORE_BAD_ARG
} cstore_status_t;

/* Resolves the counter file path: $SECURE_ECU_COUNTER_FILE if set,
 * otherwise $HOME/.secure_ecu_counter. Returns 0 on success, -1 if no
 * path can be determined or it does not fit in out. */
int cstore_resolve_path(char *out, size_t len);

cstore_status_t cstore_load(const char *path, uint32_t *counter);

/* Atomic: writes <path>.tmp, fsyncs, then renames over <path>. */
cstore_status_t cstore_save(const char *path, uint32_t counter);

const char *cstore_status_str(cstore_status_t status);

#endif /* SECURE_ECU_COUNTER_STORE_H */
