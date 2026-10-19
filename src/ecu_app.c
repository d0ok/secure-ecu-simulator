#include "ecu_app.h"

#include <stdio.h>

void ecu_app_init(ecu_app_t *app)
{
    if (app != NULL) {
        app->locked = 0;
        app->commands_executed = 0U;
    }
}

ecu_status_t ecu_app_execute(ecu_app_t *app, uint8_t command,
                             const uint8_t *params, char *out, size_t out_len)
{
    (void)params;

    if (app == NULL || out == NULL || out_len == 0U) {
        return ECU_ERR_ARG;
    }

    switch (command) {
    case ECU_CMD_LOCK:
        app->locked = 1;
        (void)snprintf(out, out_len, "doors locked");
        break;
    case ECU_CMD_UNLOCK:
        app->locked = 0;
        (void)snprintf(out, out_len, "doors unlocked");
        break;
    case ECU_CMD_STATUS:
        /* Reports the count before this command is added. */
        (void)snprintf(out, out_len, "state=%s executed=%u",
                       app->locked ? "LOCKED" : "UNLOCKED",
                       (unsigned int)app->commands_executed);
        break;
    case ECU_CMD_PING:
        (void)snprintf(out, out_len, "pong");
        break;
    default:
        (void)snprintf(out, out_len, "unsupported command 0x%02X",
                       (unsigned int)command);
        return ECU_ERR_UNSUPPORTED;
    }

    app->commands_executed++;
    return ECU_OK;
}
