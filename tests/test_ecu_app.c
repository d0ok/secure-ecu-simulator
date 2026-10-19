#include <stdio.h>
#include <string.h>

#include "ecu_app.h"

static int g_run, g_failed;
#define CHECK(name, cond) do { g_run++; \
    if (cond) { printf("[PASS] %s\n", name); } \
    else { g_failed++; printf("[FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

int main(void)
{
    ecu_app_t app;
    char out[64];
    const uint8_t params[3] = {0x10, 0x20, 0x30};

    ecu_app_init(&app);
    CHECK("status on fresh ECU",
          ecu_app_execute(&app, ECU_CMD_STATUS, params, out, sizeof(out)) == ECU_OK
          && strcmp(out, "state=UNLOCKED executed=0") == 0);
    CHECK("lock command",
          ecu_app_execute(&app, ECU_CMD_LOCK, params, out, sizeof(out)) == ECU_OK
          && app.locked == 1 && strcmp(out, "doors locked") == 0);
    CHECK("status after lock",
          ecu_app_execute(&app, ECU_CMD_STATUS, params, out, sizeof(out)) == ECU_OK
          && strcmp(out, "state=LOCKED executed=2") == 0);
    CHECK("unlock command",
          ecu_app_execute(&app, ECU_CMD_UNLOCK, params, out, sizeof(out)) == ECU_OK
          && app.locked == 0);
    CHECK("ping command",
          ecu_app_execute(&app, ECU_CMD_PING, params, out, sizeof(out)) == ECU_OK
          && strcmp(out, "pong") == 0);

    {
        uint32_t before = app.commands_executed;
        int locked_before = app.locked;
        CHECK("unsupported command rejected",
              ecu_app_execute(&app, 0x7F, params, out, sizeof(out)) == ECU_ERR_UNSUPPORTED
              && strcmp(out, "unsupported command 0x7F") == 0);
        CHECK("unsupported command changes nothing",
              app.commands_executed == before && app.locked == locked_before);
    }

    CHECK("small output buffer is truncated safely",
          ecu_app_execute(&app, ECU_CMD_PING, params, out, 3) == ECU_OK
          && strlen(out) == 2);
    CHECK("NULL app rejected",
          ecu_app_execute(NULL, ECU_CMD_PING, params, out, sizeof(out)) == ECU_ERR_ARG);
    CHECK("zero-length output rejected",
          ecu_app_execute(&app, ECU_CMD_PING, params, out, 0) == ECU_ERR_ARG);

    if (g_failed != 0) {
        printf("%d of %d ECU application tests FAILED.\n", g_failed, g_run);
        return 1;
    }
    printf("All %d ECU application tests passed.\n", g_run);
    return 0;
}
