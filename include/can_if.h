#ifndef SECURE_ECU_CAN_IF_H
#define SECURE_ECU_CAN_IF_H

#include <stdint.h>

#define CAN_IF_MAX_DATA 64U

#define CAN_IF_ERROR       (-1)  /* read failed; errno is set */
#define CAN_IF_INTERRUPTED   0   /* signal arrived; no frame */
#define CAN_IF_FRAME         1   /* msg is filled */
#define CAN_IF_MALFORMED     2   /* unexpected size or length */

typedef struct {
    int fd;
} can_if_t;

typedef struct {
    uint32_t id;               /* identifier with flag bits stripped */
    uint8_t  len;
    uint8_t  data[CAN_IF_MAX_DATA];
    int      is_fd;
    int      is_extended;
    int      is_rtr;
    int      is_error;
} can_msg_t;

int  can_if_open(can_if_t *ctx, const char *ifname);
int  can_if_receive(can_if_t *ctx, can_msg_t *msg);
void can_if_close(can_if_t *ctx);

#endif /* SECURE_ECU_CAN_IF_H */
