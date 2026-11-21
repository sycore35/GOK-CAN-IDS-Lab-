/* guard.h -- GOK-GW1 gateway state machine: port A (untrusted) <-> policy <-> port B (protected). */
#ifndef CG_GUARD_H
#define CG_GUARD_H

#include <stdint.h>
#include "board.h"
#include "policy.h"

#define CG_EVENT_QUEUE 16u           /* power of two; 15 usable */
#define CG_EVENT_JSON_MAX 192u
#define CG_EVENT_COALESCE_MS 100u    /* at most one BLOCK event per rule per 100 ms (a flood must not drown the log) */
#define CG_POLL_BURST 32u            /* frames handled per port per guard_poll() */

typedef enum { CG_EV_BLOCK = 0, CG_EV_LOCKDOWN = 1 } cg_event_kind_t;

typedef struct {
    uint32_t t_ms, seq, id;
    uint8_t kind, rule, dir, ext, dlc;
    uint8_t data[8];
} cg_event_t;

typedef struct { uint8_t debounce_ms; } guard_config_t;

typedef struct {
    uint32_t passed, blocked, b_to_a, tx_lost, events_lost, events_suppressed;
    uint32_t by_rule[CG_N_RULES];
} cg_stats_t;

typedef struct {
    guard_config_t cfg;
    policy_state_t pol;
    cg_stats_t stats;
    uint8_t workshop_raw, workshop_on;
    uint32_t workshop_since_ms;
    uint8_t lockdown;                 /* tamper latch or failed self-check: A -> B fully closed (GW-09) */
    uint8_t selfcheck_ok, se_ok;
    uint32_t led_off_pass_ms, led_off_block_ms;
    cg_event_t ev[CG_EVENT_QUEUE];
    uint16_t ev_head, ev_tail;
    uint32_t ev_seq;
    uint32_t last_ev_ms[CG_N_RULES];
    uint8_t last_ev_set[CG_N_RULES];
} guard_t;

void guard_config_default(guard_config_t *cfg);
void guard_init(guard_t *g, const guard_config_t *cfg);

/* Pure decision + bookkeeping (stats, events); no I/O. Used by guard_poll() and by the parity tests. */
cg_verdict_t guard_process(guard_t *g, const cg_frame_t *f, cg_dir_t dir, uint32_t t_us);

/* Main-loop step: inputs, drains both CAN ports (decide + forward), LEDs, watchdog. */
void guard_poll(guard_t *g);

/* Emits at most ONE pending event (JSON line + HMAC) to the event line. */
void guard_flush_events(guard_t *g);

/* Clears the tamper latch. Refused (returns 0) while the tamper switch is active or the self-check failed.
 * On the real device this must additionally require an ATECC608A-signed unlock command. */
int guard_clear_lockdown(guard_t *g);

int guard_event_pop(guard_t *g, cg_event_t *out);

/* {"t":12.345,"ev":"BLOCK","rule":"GW-04","dir":"A>B","id":"0x244","dlc":8,"data":"e803..","seq":7,"mac":"<16 hex>"}
 * Returns length (without NUL, which is appended when room), 0 if cap is too small. mac = first 8 bytes of
 * HMAC-SHA256 over the text that precedes `,"mac"` ("none" when the secure element is unavailable). */
uint16_t guard_event_to_json(const cg_event_t *e, char *out, uint16_t cap);

#endif
