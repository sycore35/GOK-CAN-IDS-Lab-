/* hal_host.h -- test control surface of the host HAL (not part of the firmware API). */
#ifndef CG_HAL_HOST_H
#define CG_HAL_HOST_H

#include <stdint.h>
#include "board.h"

void host_reset(void);
void host_advance_us(uint32_t us);
void host_advance_ms(uint32_t ms);
void host_set_workshop(int on);
void host_set_tamper(int on);
void host_set_tx_full(cg_port_t port, int full);   /* make can_write() fail (TX FIFO full) */

void host_rx_push(cg_port_t port, const cg_frame_t *f);      /* a frame arrives on a port */
uint16_t host_tx_count(cg_port_t port);                       /* frames transmitted on a port */
const cg_frame_t *host_tx_frame(cg_port_t port, uint16_t i);
void host_tx_clear(cg_port_t port);
uint16_t host_evt_len(void);
const uint8_t *host_evt_data(void);
void host_evt_clear(void);
int host_led(cg_led_t led);
uint32_t host_wdt_kicks(void);

#endif
