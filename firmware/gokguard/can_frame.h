/* can_frame.h -- classic CAN frame as seen by the gateway core (no CAN FD: FDCAN is configured classic-only). */
#ifndef CG_CAN_FRAME_H
#define CG_CAN_FRAME_H

#include <stdint.h>

typedef struct {
    uint32_t id;        /* 11-bit (ext = 0) or 29-bit (ext = 1) identifier */
    uint8_t  ext;       /* 1 = extended (29-bit) frame */
    uint8_t  dlc;       /* 0..8; > 8 is treated as invalid (fail-closed) */
    uint8_t  data[8];   /* unused bytes are 0 */
} cg_frame_t;

#endif
