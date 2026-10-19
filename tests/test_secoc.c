#include "secoc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check(const char *name, int condition)
{
    if (!condition) {
        fprintf(stderr, "[FAIL] %s\n", name);
        exit(EXIT_FAILURE);
    }
    printf("[PASS] %s\n", name);
}

int main(void)
{
    static const char demo_key_hex[] =
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff";
    static const char invalid_key_hex[] =
        "00112233445566778899aabbccddeefg"
        "00112233445566778899aabbccddeeff";
    uint8_t key[SECOC_KEY_LEN] = {0};
    uint8_t invalid_key[SECOC_KEY_LEN] = {0};
    const uint8_t params[SECOC_PARAMS_LEN] = {0x10U, 0x20U, 0x30U};
    uint8_t payload[SECOC_PAYLOAD_LEN] = {0};
    uint8_t tampered[SECOC_PAYLOAD_LEN] = {0};

    check("parse 32-byte hexadecimal key",
          secoc_parse_key_hex(demo_key_hex, key));
    check("reject malformed hexadecimal key",
          !secoc_parse_key_hex(invalid_key_hex, invalid_key));
    check("build authenticated 24-byte payload",
          secoc_build_payload(key, SECOC_CAN_ID, 0xA1U, params, 1U, payload));
    check("accept an authentic payload",
          secoc_verify_payload(key, SECOC_CAN_ID, payload, sizeof(payload)));
    check("decode the big-endian freshness value",
          secoc_payload_freshness(payload) == 1U);

    memcpy(tampered, payload, sizeof(tampered));
    tampered[SECOC_COMMAND_OFFSET] ^= 0x01U;
    check("reject a modified command",
          !secoc_verify_payload(key, SECOC_CAN_ID, tampered, sizeof(tampered)));

    memcpy(tampered, payload, sizeof(tampered));
    tampered[SECOC_PARAMS_OFFSET + 1U] ^= 0x01U;
    check("reject modified command parameters",
          !secoc_verify_payload(key, SECOC_CAN_ID, tampered, sizeof(tampered)));

    memcpy(tampered, payload, sizeof(tampered));
    tampered[SECOC_FRESHNESS_OFFSET + 3U] ^= 0x01U;
    check("reject a modified freshness counter",
          !secoc_verify_payload(key, SECOC_CAN_ID, tampered, sizeof(tampered)));

    memcpy(tampered, payload, sizeof(tampered));
    tampered[SECOC_TAG_OFFSET] ^= 0x01U;
    check("reject a modified authentication tag",
          !secoc_verify_payload(key, SECOC_CAN_ID, tampered, sizeof(tampered)));

    check("reject the message under a different CAN ID",
          !secoc_verify_payload(key, SECOC_CAN_ID + 1U,
                                payload, sizeof(payload)));
    check("reject an incorrect payload length",
          !secoc_verify_payload(key, SECOC_CAN_ID, payload,
                                sizeof(payload) - 1U));

    puts("All SecOC authentication tests passed.");
    return EXIT_SUCCESS;
}

