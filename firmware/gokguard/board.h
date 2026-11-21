/* board.h -- GOK-GW1 hardware abstraction (HAL) interface.
 * Implemented by hal_stm32g0b1.c (target) and hal_host.c (unit tests). The core (policy, guard) only talks to
 * the hardware through these functions. */
#ifndef CG_BOARD_H
#define CG_BOARD_H

#include <stdint.h>
#include "can_frame.h"

typedef enum {
    CG_PORT_A = 0,    /* untrusted domain: OBD-II / infotainment (FDCAN1) */
    CG_PORT_B = 1,    /* protected domain: powertrain / brake (FDCAN2) */
    CG_PORT_EVT = 2   /* event line to GOK-TN1 / GOK CAN-IDS Lab (UART, JSON lines) */
} cg_port_t;

typedef enum { CG_LED_PWR = 0, CG_LED_PASS, CG_LED_BLOCK, CG_LED_DIAG } cg_led_t;

void board_init(void);

/* Non-blocking: 1 and *f filled when a frame was waiting in the RX FIFO of that port, else 0. */
int can_read(cg_port_t port, cg_frame_t *f);
/* Queue a frame for transmit. 1 = queued, 0 = TX FIFO full (frame lost; CAN has no flow control). */
int can_write(cg_port_t port, const cg_frame_t *f);
/* Event line (CG_PORT_EVT): len bytes, JSON lines. */
void evt_write(const uint8_t *data, uint16_t len);

/* 1 = workshop switch closed (diagnostics allowed), raw level (the guard debounces). */
int gpio_read_workshop_key(void);
/* 1 = enclosure tamper switch active (box opened), raw level. */
int gpio_read_tamper(void);

void led_set(cg_led_t led, int on);

uint32_t millis(void);   /* monotonic ms, wraps at 2^32 (differences only) */
uint32_t micros(void);   /* monotonic us, wraps at 2^32 (differences only) */

void wdt_kick(void);     /* toggle TPS3823 WDI; call once per main-loop pass */

#endif
