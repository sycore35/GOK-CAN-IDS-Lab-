/* Host HAL: simulated time, GPIO, CAN FIFOs and event-line capture for unit tests. */
#include "board.h"
#include "hal_host.h"
#include <string.h>

#define RXQ 64u
#define TXQ 512u
#define EVT_CAP 4096u

static uint32_t now_us;
static int workshop, tamper, tx_full[2];
static int leds[4];
static uint32_t kicks;
static cg_frame_t rxq[2][RXQ];
static uint16_t rx_head[2], rx_tail[2];
static cg_frame_t txq[2][TXQ];
static uint16_t txn[2];
static uint8_t evt[EVT_CAP];
static uint16_t evt_n;

void host_reset(void) {
    now_us = 1000000u; workshop = 0; tamper = 0; kicks = 0;
    memset(leds, 0, sizeof leds); memset(tx_full, 0, sizeof tx_full);
    memset(rx_head, 0, sizeof rx_head); memset(rx_tail, 0, sizeof rx_tail);
    memset(txn, 0, sizeof txn); evt_n = 0;
}
void host_advance_us(uint32_t us) { now_us += us; }
void host_advance_ms(uint32_t ms) { now_us += ms * 1000u; }
void host_set_workshop(int on) { workshop = on; }
void host_set_tamper(int on) { tamper = on; }
void host_set_tx_full(cg_port_t p, int full) { tx_full[p] = full; }

void host_rx_push(cg_port_t p, const cg_frame_t *f) {
    uint16_t next = (uint16_t)((rx_head[p] + 1u) % RXQ);
    if (next == rx_tail[p]) return;   /* RX FIFO overrun: newest frame lost (like the FDCAN FIFO in blocking mode) */
    rxq[p][rx_head[p]] = *f;
    rx_head[p] = next;
}
uint16_t host_tx_count(cg_port_t p) { return txn[p]; }
const cg_frame_t *host_tx_frame(cg_port_t p, uint16_t i) { return &txq[p][i]; }
void host_tx_clear(cg_port_t p) { txn[p] = 0; }
uint16_t host_evt_len(void) { return evt_n; }
const uint8_t *host_evt_data(void) { return evt; }
void host_evt_clear(void) { evt_n = 0; }
int host_led(cg_led_t l) { return leds[l]; }
uint32_t host_wdt_kicks(void) { return kicks; }

void board_init(void) { host_reset(); }
int can_read(cg_port_t p, cg_frame_t *f) {
    if (p > CG_PORT_B || rx_head[p] == rx_tail[p]) return 0;
    *f = rxq[p][rx_tail[p]];
    rx_tail[p] = (uint16_t)((rx_tail[p] + 1u) % RXQ);
    return 1;
}
int can_write(cg_port_t p, const cg_frame_t *f) {
    if (p > CG_PORT_B || tx_full[p] || txn[p] >= TXQ) return 0;
    txq[p][txn[p]++] = *f;
    return 1;
}
void evt_write(const uint8_t *data, uint16_t len) {
    if ((uint32_t)evt_n + len > EVT_CAP) return;
    memcpy(evt + evt_n, data, len);
    evt_n = (uint16_t)(evt_n + len);
}
int gpio_read_workshop_key(void) { return workshop; }
int gpio_read_tamper(void) { return tamper; }
void led_set(cg_led_t led, int on) { leds[led] = on; }
uint32_t millis(void) { return now_us / 1000u; }
uint32_t micros(void) { return now_us; }
void wdt_kick(void) { kicks++; }
