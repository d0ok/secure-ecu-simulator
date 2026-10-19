#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "can_if.h"
#include "counter_store.h"
#include "ecu_app.h"
#include "freshness.h"
#include "sec_layer.h"
#include "secoc.h"

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

int main(int argc, char **argv)
{
    const char *ifname = "vcan0";
    const char *key_hex = getenv("SECURE_ECU_KEY_HEX");
    uint8_t key[SECOC_KEY_LEN] = {0};
    char ctr_path[CSTORE_PATH_MAX];
    uint32_t restored = 0U;
    cstore_status_t cs;
    int exit_status = EXIT_FAILURE;
    struct sigaction sa;
    can_if_t can;
    sec_ctx_t sec;
    ecu_app_t app;

    can.fd = -1;
    memset(&sec, 0, sizeof(sec));

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
                "%u hex characters.\n", (unsigned int)SECOC_KEY_HEX_LEN);
        goto cleanup;
    }
    sec_init(&sec, key, FRESHNESS_MAX_JUMP);
    ecu_app_init(&app);

    if (cstore_resolve_path(ctr_path, sizeof(ctr_path)) != 0) {
        fprintf(stderr, "Cannot determine the counter file. "
                        "Set SECURE_ECU_COUNTER_FILE or HOME.\n");
        goto cleanup;
    }
    cs = cstore_load(ctr_path, &restored);
    if (cs == CSTORE_OK) {
        sec.freshness.last_accepted = restored;
        printf("Restored last accepted counter %u from %s\n",
               (unsigned int)restored, ctr_path);
    } else if (cs == CSTORE_NOT_FOUND) {
        printf("No counter file at %s; starting at 0\n", ctr_path);
    } else {
        fprintf(stderr, "Counter file %s: %s. Refusing to start so that old "
                        "frames cannot be replayed.\n", ctr_path, cstore_status_str(cs));
        goto cleanup;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        goto cleanup;
    }

    if (can_if_open(&can, ifname) == -1) {
        fprintf(stderr, "Cannot open CAN interface '%s': %s\n", ifname, strerror(errno));
        goto cleanup;
    }

    printf("Secure ECU receiver listening on %s (CAN ID 0x%03X).\n",
           ifname, SECOC_CAN_ID);
    printf("Layers: SocketCAN -> frame checks -> HMAC -> freshness -> ECU application.\n");
    fflush(stdout);
    exit_status = EXIT_SUCCESS;

    while (keep_running) {
        can_msg_t msg;
        sec_result_t res;
        char reply[64];
        ecu_status_t es;
        int rc = can_if_receive(&can, &msg);

        if (rc == CAN_IF_INTERRUPTED) {
            continue;
        }
        if (rc == CAN_IF_ERROR) {
            perror("read(CAN socket)");
            exit_status = EXIT_FAILURE;
            break;
        }
        if (rc == CAN_IF_MALFORMED) {
            printf("[REJECT] malformed SocketCAN frame\n");
            fflush(stdout);
            continue;
        }

        if (sec_process(&sec, &msg, &res) != SEC_OK) {
            if (res.status == SEC_ERR_FRESHNESS) {
                printf("[REJECT] ID=0x%03X FRESHNESS=%u (last accepted %u): %s\n",
                       (unsigned int)msg.id, (unsigned int)res.freshness,
                       (unsigned int)res.last_accepted, sec_result_str(&res));
            } else {
                printf("[REJECT] ID=0x%03X LEN=%u: %s\n",
                       (unsigned int)msg.id, (unsigned int)msg.len,
                       sec_result_str(&res));
            }
            fflush(stdout);
            continue;
        }

        /* Persist BEFORE executing, so a crash after the command cannot
         * let the same frame be replayed after a restart. Fail closed. */
        cs = cstore_save(ctr_path, res.freshness);
        if (cs != CSTORE_OK) {
            printf("[REJECT] ID=0x%03X FRESHNESS=%u: cannot persist counter (%s); "
                   "command not executed\n",
                   (unsigned int)msg.id, (unsigned int)res.freshness,
                   cstore_status_str(cs));
            fflush(stdout);
            continue;
        }

        printf("[ACCEPT] ID=0x%03X CMD=0x%02X PARAMS=%02X %02X %02X FRESHNESS=%u\n",
               (unsigned int)msg.id, (unsigned int)res.command,
               (unsigned int)res.params[0], (unsigned int)res.params[1],
               (unsigned int)res.params[2], (unsigned int)res.freshness);

        es = ecu_app_execute(&app, res.command, res.params, reply, sizeof(reply));
        printf("[ECU] %s%s\n", (es == ECU_OK) ? "" : "error: ", reply);
        fflush(stdout);
    }

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    sec_close(&sec);
    can_if_close(&can);
    puts("Secure ECU receiver stopped.");
    return exit_status;
}
