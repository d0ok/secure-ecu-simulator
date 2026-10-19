#include "freshness.h"

#include <stddef.h>

void freshness_init(freshness_t *fm, uint32_t initial, uint32_t max_jump)
{
    if (fm != NULL) {
        fm->last_accepted = initial;
        fm->max_jump = max_jump;
    }
}

freshness_status_t freshness_accept(freshness_t *fm, uint32_t received)
{
    if (fm == NULL) {
        return FRESHNESS_BAD_ARG;
    }
    if (fm->last_accepted == UINT32_MAX) {
        return FRESHNESS_EXHAUSTED;
    }
    if (received == fm->last_accepted) {
        return FRESHNESS_REPLAY;
    }
    if (received < fm->last_accepted) {
        return FRESHNESS_STALE;
    }
    if (fm->max_jump != 0U && (received - fm->last_accepted) > fm->max_jump) {
        return FRESHNESS_JUMP_TOO_LARGE;
    }

    fm->last_accepted = received;
    return FRESHNESS_OK;
}

const char *freshness_status_str(freshness_status_t status)
{
    switch (status) {
    case FRESHNESS_OK:             return "fresh";
    case FRESHNESS_REPLAY:         return "replayed counter";
    case FRESHNESS_STALE:          return "stale counter";
    case FRESHNESS_JUMP_TOO_LARGE: return "counter jump too large";
    case FRESHNESS_EXHAUSTED:      return "counter exhausted";
    case FRESHNESS_BAD_ARG:        return "invalid argument";
    }
    return "unknown";
}
