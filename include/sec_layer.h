#ifndef SECURE_ECU_SEC_LAYER_H
#define SECURE_ECU_SEC_LAYER_H

#include <stdint.h>

#include "can_if.h"
#include "freshness.h"
#include "secoc.h"

typedef enum {
    SEC_OK = 0,
    SEC_ERR_ARG,
    SEC_ERR_NOT_FD,      /* classic CAN frame */
    SEC_ERR_LENGTH,      /* payload is not 24 bytes */
    SEC_ERR_FLAGS,       /* extended, remote or error frame */
    SEC_ERR_ID,          /* unexpected CAN identifier */
    SEC_ERR_MAC,         /* HMAC validation failed */
    SEC_ERR_FRESHNESS    /* see freshness_status in the result */
} sec_status_t;

typedef struct {
    uint8_t      key[SECOC_KEY_LEN];
    freshness_t  freshness;
} sec_ctx_t;

typedef struct {
    sec_status_t       status;
    freshness_status_t freshness_status;
    uint8_t            command;                  /* valid only if SEC_OK */
    uint8_t            params[SECOC_PARAMS_LEN]; /* valid only if SEC_OK */
    uint32_t           freshness;                /* set once the MAC passed */
    uint32_t           last_accepted;
} sec_result_t;

void sec_init(sec_ctx_t *ctx, const uint8_t key[SECOC_KEY_LEN], uint32_t max_jump);
void sec_close(sec_ctx_t *ctx);

/* Order: frame checks, HMAC, freshness. The counter changes only on SEC_OK. */
sec_status_t sec_process(sec_ctx_t *ctx, const can_msg_t *msg, sec_result_t *res);

const char *sec_result_str(const sec_result_t *res);

#endif /* SECURE_ECU_SEC_LAYER_H */
