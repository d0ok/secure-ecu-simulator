#ifndef SECURE_ECU_APP_H
#define SECURE_ECU_APP_H

#include <stddef.h>
#include <stdint.h>

#define ECU_CMD_LOCK    0x01U
#define ECU_CMD_UNLOCK  0x02U
#define ECU_CMD_STATUS  0x03U
#define ECU_CMD_PING    0xA1U

typedef enum {
    ECU_OK = 0,
    ECU_ERR_UNSUPPORTED,
    ECU_ERR_ARG
} ecu_status_t;

typedef struct {
    int      locked;
    uint32_t commands_executed;   /* successful commands so far */
} ecu_app_t;

void ecu_app_init(ecu_app_t *app);

/* Call only for frames that passed authentication and freshness.
 * Writes a short human-readable result into out. params is reserved for
 * future commands (3 bytes) and is ignored by the current command set. */
ecu_status_t ecu_app_execute(ecu_app_t *app, uint8_t command,
                             const uint8_t *params, char *out, size_t out_len);

#endif /* SECURE_ECU_APP_H */
