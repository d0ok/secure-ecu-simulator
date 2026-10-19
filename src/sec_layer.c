#include "sec_layer.h"

#include <string.h>
#include <openssl/crypto.h>

void sec_init(sec_ctx_t *ctx, const uint8_t key[SECOC_KEY_LEN], uint32_t max_jump)
{
    if (ctx == NULL || key == NULL) {
        return;
    }
    memcpy(ctx->key, key, SECOC_KEY_LEN);
    freshness_init(&ctx->freshness, 0U, max_jump);
}

void sec_close(sec_ctx_t *ctx)
{
    if (ctx != NULL) {
        OPENSSL_cleanse(ctx, sizeof(*ctx));
    }
}

static sec_status_t fail(sec_result_t *res, sec_status_t status)
{
    res->status = status;
    return status;
}

sec_status_t sec_process(sec_ctx_t *ctx, const can_msg_t *msg, sec_result_t *res)
{
    if (ctx == NULL || msg == NULL || res == NULL) {
        return SEC_ERR_ARG;
    }

    memset(res, 0, sizeof(*res));
    res->last_accepted = ctx->freshness.last_accepted;

    if (!msg->is_fd) {
        return fail(res, SEC_ERR_NOT_FD);
    }
    if (msg->len != SECOC_PAYLOAD_LEN) {
        return fail(res, SEC_ERR_LENGTH);
    }
    if (msg->is_extended || msg->is_rtr || msg->is_error) {
        return fail(res, SEC_ERR_FLAGS);
    }
    if (msg->id != SECOC_CAN_ID) {
        return fail(res, SEC_ERR_ID);
    }
    if (!secoc_verify_payload(ctx->key, msg->id, msg->data, msg->len)) {
        return fail(res, SEC_ERR_MAC);
    }

    res->freshness = secoc_payload_freshness(msg->data);
    res->freshness_status = freshness_accept(&ctx->freshness, res->freshness);
    res->last_accepted = ctx->freshness.last_accepted;
    if (res->freshness_status != FRESHNESS_OK) {
        return fail(res, SEC_ERR_FRESHNESS);
    }

    res->command = msg->data[SECOC_COMMAND_OFFSET];
    memcpy(res->params, &msg->data[SECOC_PARAMS_OFFSET], SECOC_PARAMS_LEN);
    return fail(res, SEC_OK);
}

const char *sec_result_str(const sec_result_t *res)
{
    if (res == NULL) {
        return "invalid argument";
    }
    switch (res->status) {
    case SEC_OK:            return "accepted";
    case SEC_ERR_ARG:       return "invalid argument";
    case SEC_ERR_NOT_FD:    return "classic CAN is not accepted by this secured-message profile";
    case SEC_ERR_LENGTH:    return "incorrect secured payload length";
    case SEC_ERR_FLAGS:     return "extended, remote, or error frames are not permitted";
    case SEC_ERR_ID:        return "unexpected CAN identifier";
    case SEC_ERR_MAC:       return "HMAC validation failed";
    case SEC_ERR_FRESHNESS: return freshness_status_str(res->freshness_status);
    }
    return "unknown";
}
