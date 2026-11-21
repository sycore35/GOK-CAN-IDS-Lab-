#include "guard.h"
#include "secure_element.h"

#define LED_PULSE_MS 80u

static void push_event(guard_t *g, uint8_t kind, uint8_t rule, const cg_frame_t *f, uint32_t t_ms);

void guard_config_default(guard_config_t *cfg) { cfg->debounce_ms = 20u; }

void guard_init(guard_t *g, const guard_config_t *cfg) {
    uint32_t now = millis();
    uint8_t *p = (uint8_t *)g;
    uint32_t i;
    for (i = 0; i < sizeof *g; i++) p[i] = 0;   /* no memset dependency on target */
    g->cfg = *cfg;
    policy_init(&g->pol);
    g->workshop_since_ms = now;   /* fail-safe: the key counts as OPEN until it was stable for debounce_ms */
    g->selfcheck_ok = (uint8_t)(policy_selfcheck() ? 1 : 0);
    g->lockdown = (uint8_t)(g->selfcheck_ok ? 0 : 1);   /* corrupt policy table => closed, never open */
    g->se_ok = (uint8_t)(se_init() == 0);
    led_set(CG_LED_PWR, 1);
    if (!g->selfcheck_ok) push_event(g, CG_EV_LOCKDOWN, GW_09, 0, now);
}

/* ---------------------------------------------------------------- events */

static void push_event(guard_t *g, uint8_t kind, uint8_t rule, const cg_frame_t *f, uint32_t t_ms) {
    cg_event_t *e;
    uint16_t next = (uint16_t)((g->ev_head + 1u) & (CG_EVENT_QUEUE - 1u));
    uint8_t i;
    if (kind == CG_EV_BLOCK && rule < CG_N_RULES) {   /* coalesce floods: one event per rule per window */
        if (g->last_ev_set[rule] && (uint32_t)(t_ms - g->last_ev_ms[rule]) < CG_EVENT_COALESCE_MS) {
            g->stats.events_suppressed++;
            return;
        }
        g->last_ev_set[rule] = 1;
        g->last_ev_ms[rule] = t_ms;
    }
    if (next == g->ev_tail) {   /* full: drop the OLDEST so the newest evidence survives */
        g->ev_tail = (uint16_t)((g->ev_tail + 1u) & (CG_EVENT_QUEUE - 1u));
        g->stats.events_lost++;
    }
    e = &g->ev[g->ev_head];
    e->t_ms = t_ms; e->seq = g->ev_seq++; e->kind = kind; e->rule = rule; e->dir = CG_A_TO_B;
    e->id = f ? f->id : 0u; e->ext = f ? f->ext : 0u; e->dlc = f ? (uint8_t)(f->dlc > 8u ? 8u : f->dlc) : 0u;
    for (i = 0; i < 8u; i++) e->data[i] = f ? f->data[i] : 0u;
    g->ev_head = next;
}

int guard_event_pop(guard_t *g, cg_event_t *out) {
    if (g->ev_head == g->ev_tail) return 0;
    *out = g->ev[g->ev_tail];
    g->ev_tail = (uint16_t)((g->ev_tail + 1u) & (CG_EVENT_QUEUE - 1u));
    return 1;
}

static uint16_t put_str(char *o, uint16_t n, uint16_t cap, const char *s) {
    while (*s && n < cap) o[n++] = *s++;
    return n;
}

static uint16_t put_u32(char *o, uint16_t n, uint16_t cap, uint32_t v) {
    char tmp[10];
    uint8_t k = 0;
    do { tmp[k++] = (char)('0' + v % 10u); v /= 10u; } while (v && k < sizeof tmp);
    while (k && n < cap) o[n++] = tmp[--k];
    return n;
}

static uint16_t put_hex(char *o, uint16_t n, uint16_t cap, uint32_t v, uint8_t digits) {
    static const char hex[] = "0123456789ABCDEF";
    int8_t i;
    for (i = (int8_t)(digits - 1u); i >= 0 && n < cap; i--) o[n++] = hex[(v >> (4 * i)) & 0xFu];
    return n;
}

uint16_t guard_event_to_json(const cg_event_t *e, char *out, uint16_t cap) {
    static const char *const kinds[] = { "BLOCK", "LOCKDOWN" };
    static const char lc[] = "0123456789abcdef";
    uint8_t mac[32];
    uint16_t n = 0, i;
    if (cap < 16u) return 0;
    n = put_str(out, n, cap, "{\"t\":");        n = put_u32(out, n, cap, e->t_ms / 1000u);
    n = put_str(out, n, cap, ".");
    if (e->t_ms % 1000u < 100u) n = put_str(out, n, cap, "0");
    if (e->t_ms % 1000u < 10u) n = put_str(out, n, cap, "0");
    n = put_u32(out, n, cap, e->t_ms % 1000u);
    n = put_str(out, n, cap, ",\"ev\":\"");     n = put_str(out, n, cap, kinds[e->kind <= 1u ? e->kind : 0u]);
    n = put_str(out, n, cap, "\",\"rule\":\""); n = put_str(out, n, cap, policy_rule_name(e->rule));
    n = put_str(out, n, cap, "\",\"dir\":\"A>B\",\"id\":\"0x");
    n = put_hex(out, n, cap, e->id, e->ext ? 8u : 3u);
    n = put_str(out, n, cap, "\",\"dlc\":");    n = put_u32(out, n, cap, e->dlc);
    n = put_str(out, n, cap, ",\"data\":\"");
    for (i = 0; i < e->dlc && n + 2u < cap; i++) { out[n++] = lc[e->data[i] >> 4]; out[n++] = lc[e->data[i] & 0x0Fu]; }
    n = put_str(out, n, cap, "\",\"seq\":");    n = put_u32(out, n, cap, e->seq);
    if ((uint32_t)n + 30u > cap) return 0;
    if (se_hmac_sha256((const uint8_t *)out, n, mac) != 0) {
        n = put_str(out, n, cap, ",\"mac\":\"none\"}");
    } else {
        n = put_str(out, n, cap, ",\"mac\":\"");
        for (i = 0; i < 8u; i++) { out[n++] = lc[mac[i] >> 4]; out[n++] = lc[mac[i] & 0x0Fu]; }
        n = put_str(out, n, cap, "\"}");
    }
    if (n < cap) out[n] = '\0';
    return n;
}

void guard_flush_events(guard_t *g) {
    cg_event_t e;
    char line[CG_EVENT_JSON_MAX];
    uint16_t n;
    /* The ATECC608A HMAC can take tens of ms: one event per call, from the main loop, never in a decision. */
    if (!guard_event_pop(g, &e)) return;
    n = guard_event_to_json(&e, line, (uint16_t)(sizeof line - 1u));
    if (n) { line[n++] = '\n'; evt_write((const uint8_t *)line, n); }
}

/* -------------------------------------------------------------- decisions */

cg_verdict_t guard_process(guard_t *g, const cg_frame_t *f, cg_dir_t dir, uint32_t t_us) {
    policy_ctx_t ctx;
    cg_verdict_t v;
    ctx.workshop_key = g->workshop_on;
    ctx.locked = (uint8_t)(g->lockdown || !g->selfcheck_ok);
    v = policy_evaluate(&g->pol, &ctx, f, dir, t_us);
    if (dir == CG_B_TO_A) {
        g->stats.b_to_a++;
    } else if (v.decision == CG_FORWARD) {
        g->stats.passed++;
    } else {
        g->stats.blocked++;
        g->stats.by_rule[v.rule < CG_N_RULES ? v.rule : 0u]++;
        push_event(g, CG_EV_BLOCK, v.rule, f, t_us / 1000u);
        led_set(CG_LED_BLOCK, 1);
        g->led_off_block_ms = millis() + LED_PULSE_MS;
    }
    return v;
}

/* --------------------------------------------------------------- polling */

static void sample_inputs(guard_t *g, uint32_t now) {
    uint8_t raw = gpio_read_workshop_key() ? 1u : 0u;
    if (raw != g->workshop_raw) { g->workshop_raw = raw; g->workshop_since_ms = now; }
    else if ((uint32_t)(now - g->workshop_since_ms) >= g->cfg.debounce_ms) g->workshop_on = raw;
    led_set(CG_LED_DIAG, g->workshop_on);

    if (gpio_read_tamper() && !g->lockdown) {   /* latch immediately, no debounce: fail-safe */
        g->lockdown = 1;
        push_event(g, CG_EV_LOCKDOWN, GW_09, 0, now);
        g->stats.blocked++;
        g->stats.by_rule[GW_09]++;
    }
}

static void pump(guard_t *g, cg_port_t from, cg_port_t to, cg_dir_t dir) {
    cg_frame_t f;
    uint32_t n = 0;
    while (n++ < CG_POLL_BURST && can_read(from, &f)) {
        cg_verdict_t v = guard_process(g, &f, dir, micros());
        if (v.decision == CG_FORWARD) {
            if (!can_write(to, &f)) g->stats.tx_lost++;
            else if (dir == CG_A_TO_B) { led_set(CG_LED_PASS, 1); g->led_off_pass_ms = millis() + LED_PULSE_MS; }
        }
    }
}

void guard_poll(guard_t *g) {
    uint32_t now_ms = millis();
    wdt_kick();
    sample_inputs(g, now_ms);
    pump(g, CG_PORT_A, CG_PORT_B, CG_A_TO_B);
    pump(g, CG_PORT_B, CG_PORT_A, CG_B_TO_A);
    if (g->led_off_pass_ms && (int32_t)(now_ms - g->led_off_pass_ms) >= 0) { led_set(CG_LED_PASS, 0); g->led_off_pass_ms = 0; }
    if (g->led_off_block_ms && (int32_t)(now_ms - g->led_off_block_ms) >= 0) { led_set(CG_LED_BLOCK, g->lockdown); g->led_off_block_ms = 0; }
    if (g->lockdown) led_set(CG_LED_BLOCK, 1);
}

int guard_clear_lockdown(guard_t *g) {
    if (gpio_read_tamper() || !g->selfcheck_ok) return 0;
    g->lockdown = 0;
    led_set(CG_LED_BLOCK, 0);
    return 1;
}
