#ifndef SECURE_ECU_SECOC_H
#define SECURE_ECU_SECOC_H

#include <stddef.h>
#include <stdint.h>

/* Educational simulator protocol; not a complete AUTOSAR SecOC implementation. */
#define SECOC_CAN_ID          0x123U
#define SECOC_DATA_ID         0x1234U
#define SECOC_KEY_LEN         32U
#define SECOC_KEY_HEX_LEN     (SECOC_KEY_LEN * 2U)
#define SECOC_COMMAND_LEN     1U
#define SECOC_PARAMS_LEN      3U
#define SECOC_FRESHNESS_LEN   4U
#define SECOC_TAG_LEN         16U
#define SECOC_TAG_OFFSET      8U
#define SECOC_PAYLOAD_LEN     24U
#define SECOC_FULL_MAC_LEN    32U

#define SECOC_COMMAND_OFFSET  0U
#define SECOC_PARAMS_OFFSET   1U
#define SECOC_FRESHNESS_OFFSET 4U

/* key_hex must contain exactly 64 hexadecimal characters (32 bytes). */
int secoc_parse_key_hex(const char *key_hex, uint8_t key[SECOC_KEY_LEN]);

/* CAN ID is the numeric identifier only; do not pass SocketCAN flag bits. */
int secoc_build_payload(const uint8_t key[SECOC_KEY_LEN],
                        uint32_t can_id,
                        uint8_t command,
                        const uint8_t params[SECOC_PARAMS_LEN],
                        uint32_t freshness,
                        uint8_t payload[SECOC_PAYLOAD_LEN]);

/* Returns 1 only when length and truncated HMAC are valid; otherwise 0.
 * Freshness ordering/replay protection is intentionally a later milestone.
 */
int secoc_verify_payload(const uint8_t key[SECOC_KEY_LEN],
                         uint32_t can_id,
                         const uint8_t *payload,
                         size_t payload_len);

uint32_t secoc_payload_freshness(const uint8_t payload[SECOC_PAYLOAD_LEN]);

#endif /* SECURE_ECU_SECOC_H */
