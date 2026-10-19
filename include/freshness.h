#ifndef SECURE_ECU_FRESHNESS_H
#define SECURE_ECU_FRESHNESS_H

#include <stdint.h>

/* Maximum forward jump accepted in one step. 0 disables the limit. */
#define FRESHNESS_MAX_JUMP 1000U

typedef enum {
    FRESHNESS_OK = 0,
    FRESHNESS_REPLAY,          /* counter == last accepted */
    FRESHNESS_STALE,           /* counter <  last accepted */
    FRESHNESS_JUMP_TOO_LARGE,  /* counter too far ahead */
    FRESHNESS_EXHAUSTED,       /* last accepted == UINT32_MAX */
    FRESHNESS_BAD_ARG
} freshness_status_t;

typedef struct {
    uint32_t last_accepted;
    uint32_t max_jump;
} freshness_t;

void freshness_init(freshness_t *fm, uint32_t initial, uint32_t max_jump);

/* Call ONLY after the MAC has been verified. Updates state only on
 * FRESHNESS_OK; every rejection leaves the stored counter unchanged. */
freshness_status_t freshness_accept(freshness_t *fm, uint32_t received);

const char *freshness_status_str(freshness_status_t status);

#endif /* SECURE_ECU_FRESHNESS_H */
