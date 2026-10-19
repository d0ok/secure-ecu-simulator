#include <stdio.h>
#include <string.h>

#include "sec_layer.h"

#define KEY_HEX "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static int g_run, g_failed;
#define CHECK(name, cond) do { g_run++; \
    if (cond) { printf("[PASS] %s\n", name); } \
    else { g_failed++; printf("[FAIL] %s (line %d)\n", name, __LINE__); } \
} while (0)

static void make_msg(can_msg_t *m, const uint8_t *key, uint32_t sign_id,
                     uint8_t cmd, uint32_t fresh)
{
    const uint8_t params[SECOC_PARAMS_LEN] = {0x10U, 0x20U, 0x30U};

    memset(m, 0, sizeof(*m));
    (void)secoc_build_payload(key, sign_id, cmd, params, fresh, m->data);
    m->id = SECOC_CAN_ID;
    m->len = SECOC_PAYLOAD_LEN;
    m->is_fd = 1;
}

int main(void)
{
    uint8_t key[SECOC_KEY_LEN];
    sec_ctx_t sec;
    sec_result_t r;
    can_msg_t m;

    CHECK("test key parses", secoc_parse_key_hex(KEY_HEX, key) == 1);
    sec_init(&sec, key, 1000U);

    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 1U);
    CHECK("valid frame accepted", sec_process(&sec, &m, &r) == SEC_OK);
    CHECK("command, params and counter decoded",
          r.command == 0x01U && r.params[0] == 0x10U && r.params[2] == 0x30U
          && r.freshness == 1U);
    CHECK("same frame rejected as replay",
          sec_process(&sec, &m, &r) == SEC_ERR_FRESHNESS
          && r.freshness_status == FRESHNESS_REPLAY);

    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 2U);
    m.data[SECOC_TAG_OFFSET] ^= 0x01U;
    CHECK("forged tag rejected", sec_process(&sec, &m, &r) == SEC_ERR_MAC);
    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 2U);
    CHECK("forged frame did not consume the counter",
          sec_process(&sec, &m, &r) == SEC_OK);

    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 1U);
    CHECK("stale counter rejected",
          sec_process(&sec, &m, &r) == SEC_ERR_FRESHNESS
          && r.freshness_status == FRESHNESS_STALE);
    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 5000U);
    CHECK("large jump rejected",
          sec_process(&sec, &m, &r) == SEC_ERR_FRESHNESS
          && r.freshness_status == FRESHNESS_JUMP_TOO_LARGE);

    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 3U);
    m.is_fd = 0;
    CHECK("classic CAN rejected", sec_process(&sec, &m, &r) == SEC_ERR_NOT_FD);

    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 3U);
    m.len = 16U;
    CHECK("wrong length rejected", sec_process(&sec, &m, &r) == SEC_ERR_LENGTH);

    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 3U);
    m.is_extended = 1;
    CHECK("extended frame rejected", sec_process(&sec, &m, &r) == SEC_ERR_FLAGS);
    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 3U);
    m.is_rtr = 1;
    CHECK("remote frame rejected", sec_process(&sec, &m, &r) == SEC_ERR_FLAGS);
    make_msg(&m, key, SECOC_CAN_ID, 0x01U, 3U);
    m.is_error = 1;
    CHECK("error frame rejected", sec_process(&sec, &m, &r) == SEC_ERR_FLAGS);

    make_msg(&m, key, 0x124U, 0x01U, 3U);
    m.id = 0x124U;
    CHECK("wrong CAN ID rejected", sec_process(&sec, &m, &r) == SEC_ERR_ID);
    make_msg(&m, key, 0x124U, 0x01U, 3U);
    CHECK("tag signed for another ID rejected",
          sec_process(&sec, &m, &r) == SEC_ERR_MAC);

    CHECK("no rejection changed the stored counter",
          sec.freshness.last_accepted == 2U);
    make_msg(&m, key, SECOC_CAN_ID, 0x03U, 3U);
    CHECK("next valid counter still accepted", sec_process(&sec, &m, &r) == SEC_OK);

    CHECK("NULL context rejected", sec_process(NULL, &m, &r) == SEC_ERR_ARG);
    CHECK("result text available", strlen(sec_result_str(&r)) > 0U);

    sec_close(&sec);
    if (g_failed != 0) {
        printf("%d of %d security layer tests FAILED.\n", g_failed, g_run);
        return 1;
    }
    printf("All %d security layer tests passed.\n", g_run);
    return 0;
}
