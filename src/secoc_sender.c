#define _POSIX_C_SOURCE 200809L

#include "secoc.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/crypto.h>

static int parse_counter(const char *text, uint32_t *counter)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || counter == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return 0;
    }

    *counter = (uint32_t)value;
    return 1;
}

int main(int argc, char **argv)
{
    const char *ifname;
    const char *mode;
    const char *key_hex = getenv("SECURE_ECU_KEY_HEX");
    uint8_t key[SECOC_KEY_LEN] = {0};
    const uint8_t params[SECOC_PARAMS_LEN] = {0x10U, 0x20U, 0x30U};
    uint8_t payload[SECOC_PAYLOAD_LEN] = {0};
    uint32_t freshness;
    int sock = -1;
    int enable_fd = 1;
    int exit_status = EXIT_FAILURE;
    struct sockaddr_can addr;
    struct canfd_frame frame;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <valid|forged> <freshness-counter>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    ifname = argv[1];
    mode = argv[2];
    if (strcmp(mode, "valid") != 0 && strcmp(mode, "forged") != 0) {
        fprintf(stderr, "Mode must be 'valid' or 'forged'.\n");
        return EXIT_FAILURE;
    }
    if (!parse_counter(argv[3], &freshness)) {
        fprintf(stderr, "Freshness counter must be an unsigned 32-bit decimal integer.\n");
        return EXIT_FAILURE;
    }
    if (!secoc_parse_key_hex(key_hex, key)) {
        fprintf(stderr,
                "SECURE_ECU_KEY_HEX is missing or invalid; set it to exactly %u hex characters.\n",
                (unsigned int)SECOC_KEY_HEX_LEN);
        goto cleanup;
    }

    if (!secoc_build_payload(key, SECOC_CAN_ID, 0xA1U, params,
                             freshness, payload)) {
        fprintf(stderr, "Unable to create secured payload.\n");
        goto cleanup;
    }

    if (strcmp(mode, "forged") == 0) {
        /* Simulate tampering after a legitimate message was signed. */
        payload[SECOC_TAG_OFFSET] ^= 0x01U;
    }

    sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock == -1) {
        perror("socket(PF_CAN)");
        goto cleanup;
    }
    if (setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                   &enable_fd, sizeof(enable_fd)) == -1) {
        perror("setsockopt(CAN_RAW_FD_FRAMES)");
        goto cleanup;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0U) {
        fprintf(stderr, "CAN interface '%s' was not found.\n", ifname);
        goto cleanup;
    }

    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = (int)ifindex;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind(AF_CAN)");
        goto cleanup;
    }

    memset(&frame, 0, sizeof(frame));
    frame.can_id = SECOC_CAN_ID;
    frame.len = SECOC_PAYLOAD_LEN;
    frame.flags = 0U;
    memcpy(frame.data, payload, sizeof(payload));

    ssize_t sent = write(sock, &frame, CANFD_MTU);
    if (sent == -1) {
        perror("write(CAN FD frame)");
        goto cleanup;
    }
    if (sent != CANFD_MTU) {
        fprintf(stderr, "Short CAN FD write: %zd of %zu bytes.\n",
                sent, (size_t)CANFD_MTU);
        goto cleanup;
    }

    printf("Sent %s test frame: ID=0x%03X CMD=0xA1 FRESHNESS=%u\n",
           mode, SECOC_CAN_ID, freshness);
    if (strcmp(mode, "forged") == 0) {
        puts("The first authentication-tag byte was deliberately altered.");
    }
    exit_status = EXIT_SUCCESS;

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(payload, sizeof(payload));
    if (sock != -1) {
        (void)close(sock);
    }
    return exit_status;
}
