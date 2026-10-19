#include "secoc.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define SECOC_DOMAIN "SECURE-ECU-SecOC-v1"
#define SECOC_MAC_INPUT_LEN \
    ((sizeof(SECOC_DOMAIN) - 1U) + 4U + 2U + SECOC_TAG_OFFSET)

static int hex_nibble(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return (int)(ch - 'a') + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return (int)(ch - 'A') + 10;
    }
    return -1;
}

int secoc_parse_key_hex(const char *key_hex, uint8_t key[SECOC_KEY_LEN])
{
    if (key == NULL) {
        return 0;
    }

    if (key_hex == NULL || strlen(key_hex) != SECOC_KEY_HEX_LEN) {
        OPENSSL_cleanse(key, SECOC_KEY_LEN);
        return 0;
    }

    for (size_t i = 0; i < SECOC_KEY_LEN; ++i) {
        int high = hex_nibble(key_hex[i * 2U]);
        int low = hex_nibble(key_hex[(i * 2U) + 1U]);

        if (high < 0 || low < 0) {
            OPENSSL_cleanse(key, SECOC_KEY_LEN);
            return 0;
        }

        key[i] = (uint8_t)(((unsigned int)high << 4U) | (unsigned int)low);
    }

    return 1;
}

static int calculate_tag(const uint8_t key[SECOC_KEY_LEN],
                         uint32_t can_id,
                         const uint8_t payload[SECOC_PAYLOAD_LEN],
                         uint8_t tag[SECOC_TAG_LEN])
{
    uint8_t mac_input[SECOC_MAC_INPUT_LEN];
    uint8_t full_mac[EVP_MAX_MD_SIZE];
    size_t offset = 0U;
    size_t full_mac_len = 0U;
    int ok = 0;
    char digest_name[] = "SHA256";
    OSSL_PARAM params[2];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;

    if (key == NULL || payload == NULL || tag == NULL) {
        return 0;
    }

    memcpy(mac_input + offset, SECOC_DOMAIN, sizeof(SECOC_DOMAIN) - 1U);
    offset += sizeof(SECOC_DOMAIN) - 1U;

    /* Canonical, network-byte-order encoding of CAN ID and SecOC Data ID. */
    mac_input[offset++] = (uint8_t)((can_id >> 24U) & 0xffU);
    mac_input[offset++] = (uint8_t)((can_id >> 16U) & 0xffU);
    mac_input[offset++] = (uint8_t)((can_id >> 8U) & 0xffU);
    mac_input[offset++] = (uint8_t)(can_id & 0xffU);
    mac_input[offset++] = (uint8_t)((SECOC_DATA_ID >> 8U) & 0xffU);
    mac_input[offset++] = (uint8_t)(SECOC_DATA_ID & 0xffU);

    /* Command, parameters, and freshness counter are all authenticated. */
    memcpy(mac_input + offset, payload, SECOC_TAG_OFFSET);
    offset += SECOC_TAG_OFFSET;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        goto cleanup;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, digest_name, 0U);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, SECOC_KEY_LEN, params) != 1) {
        goto cleanup;
    }
    if (EVP_MAC_update(ctx, mac_input, offset) != 1) {
        goto cleanup;
    }
    if (EVP_MAC_final(ctx, full_mac, &full_mac_len, sizeof(full_mac)) != 1) {
        goto cleanup;
    }
    if (full_mac_len != SECOC_FULL_MAC_LEN) {
        goto cleanup;
    }

    /* Our educational profile transmits the first 16 bytes of HMAC-SHA-256. */
    memcpy(tag, full_mac, SECOC_TAG_LEN);
    ok = 1;

cleanup:
    OPENSSL_cleanse(mac_input, sizeof(mac_input));
    OPENSSL_cleanse(full_mac, sizeof(full_mac));
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

int secoc_build_payload(const uint8_t key[SECOC_KEY_LEN],
                        uint32_t can_id,
                        uint8_t command,
                        const uint8_t params[SECOC_PARAMS_LEN],
                        uint32_t freshness,
                        uint8_t payload[SECOC_PAYLOAD_LEN])
{
    uint8_t tag[SECOC_TAG_LEN] = {0};

    if (key == NULL || params == NULL || payload == NULL) {
        return 0;
    }

    memset(payload, 0, SECOC_PAYLOAD_LEN);
    payload[SECOC_COMMAND_OFFSET] = command;
    memcpy(payload + SECOC_PARAMS_OFFSET, params, SECOC_PARAMS_LEN);

    payload[SECOC_FRESHNESS_OFFSET] = (uint8_t)((freshness >> 24U) & 0xffU);
    payload[SECOC_FRESHNESS_OFFSET + 1U] = (uint8_t)((freshness >> 16U) & 0xffU);
    payload[SECOC_FRESHNESS_OFFSET + 2U] = (uint8_t)((freshness >> 8U) & 0xffU);
    payload[SECOC_FRESHNESS_OFFSET + 3U] = (uint8_t)(freshness & 0xffU);

    if (!calculate_tag(key, can_id, payload, tag)) {
        OPENSSL_cleanse(payload, SECOC_PAYLOAD_LEN);
        OPENSSL_cleanse(tag, sizeof(tag));
        return 0;
    }

    memcpy(payload + SECOC_TAG_OFFSET, tag, SECOC_TAG_LEN);
    OPENSSL_cleanse(tag, sizeof(tag));
    return 1;
}

int secoc_verify_payload(const uint8_t key[SECOC_KEY_LEN],
                         uint32_t can_id,
                         const uint8_t *payload,
                         size_t payload_len)
{
    uint8_t expected_tag[SECOC_TAG_LEN] = {0};
    int verified = 0;

    if (key == NULL || payload == NULL || payload_len != SECOC_PAYLOAD_LEN) {
        return 0;
    }

    if (!calculate_tag(key, can_id, payload, expected_tag)) {
        OPENSSL_cleanse(expected_tag, sizeof(expected_tag));
        return 0;
    }

    /* Constant-time comparison helps avoid leaking tag-matching information. */
    verified = (CRYPTO_memcmp(expected_tag,
                              payload + SECOC_TAG_OFFSET,
                              SECOC_TAG_LEN) == 0);
    OPENSSL_cleanse(expected_tag, sizeof(expected_tag));
    return verified;
}

uint32_t secoc_payload_freshness(const uint8_t payload[SECOC_PAYLOAD_LEN])
{
    if (payload == NULL) {
        return 0U;
    }

    return ((uint32_t)payload[SECOC_FRESHNESS_OFFSET] << 24U) |
           ((uint32_t)payload[SECOC_FRESHNESS_OFFSET + 1U] << 16U) |
           ((uint32_t)payload[SECOC_FRESHNESS_OFFSET + 2U] << 8U) |
           (uint32_t)payload[SECOC_FRESHNESS_OFFSET + 3U];
}

