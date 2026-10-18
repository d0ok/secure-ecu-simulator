
#define _POSIX_C_SOURCE 200809L

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

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

static void print_frame(const struct canfd_frame *frame, int is_fd)
{
    if (frame->can_id & CAN_EFF_FLAG) {
        printf("[%s] ID=0x%08X",
               is_fd ? "CAN FD" : "CLASSIC CAN",
               (unsigned int)(frame->can_id & CAN_EFF_MASK));
    } else {
        printf("[%s] ID=0x%03X",
               is_fd ? "CAN FD" : "CLASSIC CAN",
               (unsigned int)(frame->can_id & CAN_SFF_MASK));
    }

    printf(" LEN=%u DATA=", (unsigned int)frame->len);

    for (unsigned int i = 0; i < frame->len; i++) {
        printf("%02X", frame->data[i]);
        if (i + 1U < frame->len) {
            putchar(' ');
        }
    }

    if (is_fd) {
        printf(" FD_FLAGS=0x%02X", (unsigned int)frame->flags);
    }

    putchar('\n');
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const char *ifname = "vcan0";
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

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    /* 1. Create a raw CAN socket. */
    sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock == -1) {
        perror("socket(PF_CAN)");
        goto cleanup;
    }

    /* 2. Enable reception of CAN FD frames. */
    if (setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                   &enable_fd, sizeof(enable_fd)) == -1) {
        perror("setsockopt(CAN_RAW_FD_FRAMES)");
        goto cleanup;
    }

    /* 3. Resolve the Linux CAN interface index. */
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0U) {
        perror("if_nametoindex");
        goto cleanup;
    }

    /* 4. Bind the socket to the selected interface. */
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = (int)ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind(AF_CAN)");
        goto cleanup;
    }

    printf("Listening on %s. Press Ctrl+C to stop.\n", ifname);
    printf("CAN FD and classic CAN reception enabled.\n");
    fflush(stdout);

    exit_status = EXIT_SUCCESS;

    /* 5. Receive and display frames. */
    while (keep_running) {
        struct canfd_frame frame;
        ssize_t nbytes = read(sock, &frame, CANFD_MTU);
        int is_fd;

        if (nbytes == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("read(CAN socket)");
            exit_status = EXIT_FAILURE;
            break;
        }

        if (nbytes == CANFD_MTU) {
            is_fd = 1;

            if (frame.len > CANFD_MAX_DLEN) {
                fprintf(stderr, "Invalid CAN FD payload length\n");
                continue;
            }
        } else if (nbytes == CAN_MTU) {
            is_fd = 0;

            if (frame.len > CAN_MAX_DLEN) {
                fprintf(stderr, "Invalid classic CAN payload length\n");
                continue;
            }
        } else {
            fprintf(stderr, "Unexpected CAN frame size: %zd\n", nbytes);
            continue;
        }

        print_frame(&frame, is_fd);
    }

cleanup:
    if (sock != -1) {
        (void)close(sock);
    }

    puts("SocketCAN receiver stopped.");
    return exit_status;
}
