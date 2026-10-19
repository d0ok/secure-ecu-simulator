#include <stdio.h>

#include "freshness.h"

static int g_run, g_failed;
#define CHECK(name, cond) do { g_run++; \
    if (cond) { printf("[PASS] %s\n", name); } \
    else { g_failed++; printf("[FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

int main(void)
{
    freshness_t f;

    freshness_init(&f, 0U, 1000U);
    CHECK("accept first counter 1", freshness_accept(&f, 1U) == FRESHNESS_OK);
    CHECK("reject duplicate counter", freshness_accept(&f, 1U) == FRESHNESS_REPLAY);
    CHECK("accept increasing counter 2", freshness_accept(&f, 2U) == FRESHNESS_OK);
    CHECK("reject older counter", freshness_accept(&f, 1U) == FRESHNESS_STALE);
    CHECK("reject counter 0 after start", freshness_accept(&f, 0U) == FRESHNESS_STALE);

    CHECK("accept jump of exactly max_jump", freshness_accept(&f, 1002U) == FRESHNESS_OK);
    CHECK("reject jump above max_jump", freshness_accept(&f, 2003U) == FRESHNESS_JUMP_TOO_LARGE);
    CHECK("rejected jump did not change state", f.last_accepted == 1002U);
    CHECK("accept normal counter after rejected jump", freshness_accept(&f, 1003U) == FRESHNESS_OK);

    freshness_init(&f, 0U, 0U);
    CHECK("max_jump 0 means unlimited", freshness_accept(&f, 4000000000U) == FRESHNESS_OK);

    freshness_init(&f, UINT32_MAX - 1U, 0U);
    CHECK("accept UINT32_MAX", freshness_accept(&f, UINT32_MAX) == FRESHNESS_OK);
    CHECK("reject after exhaustion", freshness_accept(&f, UINT32_MAX) == FRESHNESS_EXHAUSTED);
    CHECK("reject wraparound to 0", freshness_accept(&f, 0U) == FRESHNESS_EXHAUSTED);

    CHECK("NULL state rejected", freshness_accept(NULL, 1U) == FRESHNESS_BAD_ARG);

    if (g_failed != 0) {
        printf("%d of %d freshness tests FAILED.\n", g_failed, g_run);
        return 1;
    }
    printf("All %d freshness tests passed.\n", g_run);
    return 0;
}
