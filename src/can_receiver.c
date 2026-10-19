#define _POSIX_C_SOURCE 200809L

#include "secoc.h"

#include <errno.h>
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

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

static void reject_frame(canid_t raw_can_id, unsigned int len, const char *reason)
{
    printf("[REJECT] raw_id=0x%08X LEN=%u: %s\n",
           (unsigned int)raw_can_id, len, reason);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const char *ifname = "vcan0";
    const char *key_hex = getenv("SECURE_ECU_KEY_HEX");
    uint8_t key[SECOC_KEY_LEN] = {0};
    int sock = -1;
    int enable_fd = 1;
    int exit_status = EXIT_FAILURE;
    struct sockaddr_can addr;
    struct sigaction sa;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        ifname = argv[1];
    }

    if (!secoc_parse_key_hex(key_hex, key)) {
        fprintf(stderr,
                "SECURE_ECU_KEY_HEX is missing or invalid. Set it to exactly "
                "%u hex characters (the demo key is in README_STEP3.md).\n",
                (unsigned int)SECOC_KEY_HEX_LEN);
        goto cleanup;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        goto cleanup;
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

    printf("Secure ECU receiver listening on %s (CAN ID 0x%03X).\n",
           ifname, SECOC_CAN_ID);
    printf("Expected payload: %u-byte CAN FD; HMAC-SHA-256 tag: %u bytes.\n",
           (unsigned int)SECOC_PAYLOAD_LEN, (unsigned int)SECOC_TAG_LEN);
    printf("MAC verification is enabled; freshness replay checks come next.\n");
    fflush(stdout);
    exit_status = EXIT_SUCCESS;

    while (keep_running) {
        struct canfd_frame frame;
        ssize_t nbytes;
        uint32_t can_id;

        memset(&frame, 0, sizeof(frame));
        nbytes = read(sock, &frame, CANFD_MTU);
        if (nbytes == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("read(CAN socket)");
            exit_status = EXIT_FAILURE;
            break;
        }

        if (nbytes == CAN_MTU) {
            reject_frame(frame.can_id, frame.len,
                         "classic CAN is not accepted by this secured-message profile");
            continue;
        }
        if (nbytes != CANFD_MTU) {
            reject_frame(frame.can_id, frame.len, "unexpected SocketCAN frame size");
            continue;
        }
        if (frame.len > CANFD_MAX_DLEN) {
            reject_frame(frame.can_id, frame.len, "invalid CAN FD length");
            continue;
        }
        if (frame.len != SECOC_PAYLOAD_LEN) {
            reject_frame(frame.can_id, frame.len, "incorrect secured payload length");
            continue;
        }
        if ((frame.can_id & (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0U) {
            reject_frame(frame.can_id, frame.len,
                         "extended, remote, or error frames are not permitted");
            continue;
        }

        can_id = (uint32_t)(frame.can_id & CAN_SFF_MASK);
        if (can_id != SECOC_CAN_ID) {
            reject_frame(frame.can_id, frame.len, "unexpected CAN identifier");
            continue;
        }

        if (!secoc_verify_payload(key, can_id, frame.data, frame.len)) {
            reject_frame(frame.can_id, frame.len, "HMAC validation failed");
            continue;
        }

        printf("[AUTH OK] ID=0x%03X CMD=0x%02X PARAMS=%02X %02X %02X FRESHNESS=%u\n",
               (unsigned int)can_id,
               (unsigned int)frame.data[SECOC_COMMAND_OFFSET],
               (unsigned int)frame.data[SECOC_PARAMS_OFFSET],
               (unsigned int)frame.data[SECOC_PARAMS_OFFSET + 1U],
               (unsigned int)frame.data[SECOC_PARAMS_OFFSET + 2U],
               (unsigned int)secoc_payload_freshness(frame.data));
        fflush(stdout);

        /* Do not execute the command yet. Replay/freshness policy is the next step. */
    }

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    if (sock != -1) {
        (void)close(sock);
    }
    puts("Secure ECU receiver stopped.");
    return exit_status;
}
