#define _POSIX_C_SOURCE 200809L

#include "can_if.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>

int can_if_open(can_if_t *ctx, const char *ifname)
{
    struct sockaddr_can addr;
    int enable_fd = 1;
    unsigned int ifindex;
    int saved;

    if (ctx == NULL || ifname == NULL) {
        errno = EINVAL;
        return -1;
    }

    ctx->fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (ctx->fd == -1) {
        return -1;
    }
    if (setsockopt(ctx->fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
                   &enable_fd, sizeof(enable_fd)) == -1) {
        goto fail;
    }
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0U) {
        errno = ENODEV;
        goto fail;
    }
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = (int)ifindex;
    if (bind(ctx->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        goto fail;
    }
    return 0;

fail:
    saved = errno;
    (void)close(ctx->fd);
    ctx->fd = -1;
    errno = saved;
    return -1;
}

int can_if_receive(can_if_t *ctx, can_msg_t *msg)
{
    struct canfd_frame frame;
    ssize_t n;
    size_t got;

    if (ctx == NULL || msg == NULL || ctx->fd < 0) {
        errno = EINVAL;
        return CAN_IF_ERROR;
    }

    memset(&frame, 0, sizeof(frame));
    n = read(ctx->fd, &frame, sizeof(frame));
    if (n == -1) {
        return (errno == EINTR) ? CAN_IF_INTERRUPTED : CAN_IF_ERROR;
    }

    got = (size_t)n;
    if (got != CAN_MTU && got != CANFD_MTU) {
        return CAN_IF_MALFORMED;
    }
    if (frame.len > CAN_IF_MAX_DATA || (got == CAN_MTU && frame.len > CAN_MAX_DLEN)) {
        return CAN_IF_MALFORMED;
    }

    memset(msg, 0, sizeof(*msg));
    msg->is_fd       = (got == CANFD_MTU);
    msg->is_extended = (frame.can_id & CAN_EFF_FLAG) != 0U;
    msg->is_rtr      = (frame.can_id & CAN_RTR_FLAG) != 0U;
    msg->is_error    = (frame.can_id & CAN_ERR_FLAG) != 0U;
    msg->id          = msg->is_extended ? (uint32_t)(frame.can_id & CAN_EFF_MASK)
                                        : (uint32_t)(frame.can_id & CAN_SFF_MASK);
    msg->len         = frame.len;
    memcpy(msg->data, frame.data, frame.len);
    return CAN_IF_FRAME;
}

void can_if_close(can_if_t *ctx)
{
    if (ctx != NULL && ctx->fd >= 0) {
        (void)close(ctx->fd);
        ctx->fd = -1;
    }
}
