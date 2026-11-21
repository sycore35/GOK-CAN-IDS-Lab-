/* GOK-Guard host tests: single binary, tiny harness (no framework). */
#include <stdio.h>
#include <string.h>
#include "../board.h"
#include "../hal_host.h"
#include "../guard.h"
#include "../policy.h"
#include "../secure_element.h"
#include "vectors_generated.h"

void se_host_hmac_with_key(const uint8_t *key, uint16_t klen, const uint8_t *data, uint16_t len, uint8_t out[32]);

static int g_checks, g_fail, g_tests;
static const char *g_name = "";
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("  FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, g_name, #c); } } while (0)
#define RUN(fn) do { g_name = #fn; g_tests++; fn(); } while (0)

static guard_t G;

/* ---------------------------------------------------------------- helpers */

static cg_frame_t mkf(uint32_t id, uint8_t dlc, const uint8_t *d) {
    cg_frame_t f;
    uint8_t i;
    memset(&f, 0, sizeof f);
    f.id = id; f.dlc = dlc;
    for (i = 0; i < dlc && i < 8u; i++) f.data[i] = d[i];
    return f;
}

static cg_frame_t brake(uint16_t bar_raw, uint8_t gear, uint8_t counter, int bad_crc) {
    uint8_t d[8];
    d[0] = (uint8_t)(bar_raw & 0xFF); d[1] = (uint8_t)(bar_raw >> 8); d[2] = gear; d[3] = d[4] = d[5] = 0;
    d[6] = (uint8_t)(counter & 0x0F);
    d[7] = policy_crc8(d, 7);
    if (bad_crc) d[7] ^= 0x55u;
    return mkf(0x200, 8, d);
}

/* fresh guard with a given (debounced) workshop key / tamper state */
static void setup(int key, int tamper) {
    guard_config_t cfg;
    host_reset();
    guard_config_default(&cfg);
    guard_init(&G, &cfg);
    host_set_workshop(key);
    host_set_tamper(tamper);
    guard_poll(&G);           /* edge seen: debounce timer starts */
    host_advance_ms(30);
    guard_poll(&G);           /* debounce window elapsed: key counts */
    host_tx_clear(CG_PORT_A); host_tx_clear(CG_PORT_B); host_evt_clear();
}

static cg_verdict_t ev_at(const cg_frame_t *f, cg_dir_t dir, uint32_t t_us) { return guard_process(&G, f, dir, t_us); }
#define EXPECT(fr, tm, want_dec, want_rule) do { cg_verdict_t v_ = ev_at(&(fr), CG_A_TO_B, (tm)); CHECK(v_.decision == (want_dec)); CHECK(v_.rule == (want_rule)); } while (0)

/* ---------------------------------------------------------------- primitives */

static void test_crc_vectors(void) {
    static const uint8_t cs[9] = { '1','2','3','4','5','6','7','8','9' };
    static const uint8_t b7[7] = { 0xE8, 3, 2, 0, 0, 0, 1 };
    static const uint8_t z7[7] = { 0 };
    CHECK(policy_crc8(cs, 9) == 0x4Bu);      /* SAE J1850 CRC-8 check value */
    CHECK(policy_crc8(cs, 0) == 0x00u);
    CHECK(policy_crc8(b7, 7) == 0xCBu);      /* identical to src/dbc_decoder.py:calc_crc8_sae_j1850 */
    CHECK(policy_crc8(z7, 7) == 0x0Au);
}

static void test_hmac_vector(void) {   /* RFC 4231 test case 2 */
    static const uint8_t exp[32] = {
        0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
        0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43 };
    uint8_t out[32];
    const char *msg = "what do ya want for nothing?";
    se_host_hmac_with_key((const uint8_t *)"Jefe", 4, (const uint8_t *)msg, (uint16_t)strlen(msg), out);
    CHECK(memcmp(out, exp, 32) == 0);
}

static void test_selfcheck(void) { CHECK(policy_selfcheck() == 1); }

/* ---------------------------------------------------------------- one test per rule (independent of the vectors) */

static void test_forward_legit(void) {
    uint8_t body[4] = { 1, 0, 0, 0 };
    uint8_t clus[4] = { 0x10, 0x0E, 0, 0 };   /* 3600 raw = 36 km/h */
    cg_frame_t a = mkf(0x320, 4, body), b = mkf(0x3C0, 4, clus);
    setup(0, 0);
    EXPECT(a, 1000000u, CG_FORWARD, CG_RULE_NONE);
    EXPECT(b, 1050000u, CG_FORWARD, CG_RULE_NONE);
    CHECK(G.stats.passed == 2 && G.stats.blocked == 0);
}

static void test_gw01(void) {
    uint8_t d[8] = { 0 };
    cg_frame_t unknown = mkf(0x555, 2, d), speed = mkf(0x244, 8, d), ext = mkf(0x320, 4, d), uds_resp = mkf(0x7E8, 4, d);
    setup(0, 0);
    ext.ext = 1;
    EXPECT(unknown, 1000000u, CG_DROP, GW_01);
    EXPECT(speed, 1000100u, CG_DROP, GW_01);       /* in the DBC but B-origin only */
    EXPECT(ext, 1000200u, CG_DROP, GW_01);         /* 29-bit id never matches an 11-bit DBC id */
    EXPECT(uds_resp, 1000300u, CG_DROP, GW_01);    /* a diagnostic RESPONSE id from A */
}

static void test_gw02(void) {
    uint8_t d[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    cg_frame_t longer = mkf(0x320, 8, d), shorter = mkf(0x3C0, 2, d), invalid = mkf(0x320, 4, d);
    setup(0, 0);
    invalid.dlc = 9;
    EXPECT(longer, 1000000u, CG_DROP, GW_02);
    EXPECT(shorter, 1000100u, CG_DROP, GW_02);
    EXPECT(invalid, 1000200u, CG_DROP, GW_02);     /* > 8 never valid */
}

static void test_gw03_bucket(void) {
    uint8_t d[4] = { 1, 0, 0, 0 };
    cg_frame_t f = mkf(0x320, 4, d);
    int i, pass = 0;
    setup(0, 0);
    for (i = 0; i < 8; i++) if (ev_at(&f, CG_A_TO_B, 1000000u + (uint32_t)i * 1000u).decision == CG_FORWARD) pass++;
    CHECK(pass == 4);                              /* burst depth */
    EXPECT(f, 1008000u, CG_DROP, GW_03);
    EXPECT(f, 1000000u + 7000u + 50000u, CG_FORWARD, CG_RULE_NONE);   /* 50 ms at 20 fps = 1 token */
    EXPECT(f, 1000000u + 7000u + 50001u, CG_DROP, GW_03);
}

static void test_clock_wrap(void) {
    uint8_t d[4] = { 1, 0, 0, 0 };
    cg_frame_t f = mkf(0x320, 4, d);
    int i, pass = 0;
    setup(0, 0);
    for (i = 0; i < 6; i++) if (ev_at(&f, CG_A_TO_B, 0xFFFFFFF0u + (uint32_t)i).decision == CG_FORWARD) pass++;
    CHECK(pass == 4);
    EXPECT(f, 4u, CG_DROP, GW_03);                 /* the 32-bit microsecond counter wrapped: only ~20 us passed */
}

static void test_gw04(void) {
    uint8_t hi[4] = { 0x31, 0x75, 0, 0 }, ok[4] = { 0x30, 0x75, 0, 0 };   /* 30001 / 30000 raw */
    cg_frame_t over = mkf(0x3C0, 4, hi), edge = mkf(0x3C0, 4, ok);
    setup(0, 0);
    EXPECT(over, 1000000u, CG_DROP, GW_04);
    EXPECT(edge, 1100000u, CG_FORWARD, CG_RULE_NONE);
}

static void test_gw05(void) {
    cg_frame_t bad = brake(1000, 2, 1, 1), g1 = brake(1000, 2, 1, 0), g2 = brake(1000, 2, 2, 0), skip = brake(1000, 2, 5, 0);
    setup(0, 0);
    EXPECT(bad, 1000000u, CG_DROP, GW_05);         /* CRC wrong */
    EXPECT(g1, 1020000u, CG_DROP, GW_10);          /* CRC ok, first counter accepted, then critical id */
    EXPECT(g2, 1040000u, CG_DROP, GW_10);          /* counter +1 ok */
    EXPECT(skip, 1060000u, CG_DROP, GW_05);        /* counter jumped */
    EXPECT(skip, 1080000u, CG_DROP, GW_05);        /* same counter twice (replay) */
    EXPECT(g1, 1100000u, CG_DROP, GW_05);          /* stale counter */
}

static void test_gw06_gw07(void) {
    static const uint8_t s10[3] = { 0x02, 0x10, 0x03 }, s27[3] = { 0x02, 0x27, 0x01 };
    static const uint8_t ff34[8] = { 0x10, 0x0F, 0x34, 0, 0x44, 0, 0x10, 0 }, cf[8] = { 0x21, 1, 2, 3, 4, 5, 6, 7 };
    static const uint8_t s11[3] = { 0x02, 0x11, 0x01 }, s22[4] = { 0x03, 0x22, 0xF1, 0x90 };
    cg_frame_t a = mkf(0x7E0, 3, s10), b = mkf(0x7E0, 3, s27), c = mkf(0x7E0, 8, ff34), d = mkf(0x7E0, 8, cf);
    cg_frame_t e = mkf(0x7DF, 3, s11), f = mkf(0x6F1, 3, s10), g = mkf(0x7E7, 4, s22);
    setup(0, 0);
    EXPECT(a, 1000000u, CG_DROP, GW_06);           /* harmless session request, still a UDS id without the key */
    EXPECT(b, 1000100u, CG_DROP, GW_07);           /* SecurityAccess */
    EXPECT(c, 1000200u, CG_DROP, GW_07);           /* RequestDownload in a first frame */
    EXPECT(d, 1000300u, CG_DROP, GW_06);           /* consecutive frame carries no service */
    EXPECT(e, 1000400u, CG_DROP, GW_07);           /* ECUReset on the functional address */
    EXPECT(f, 1000500u, CG_DROP, GW_06);           /* foreign diagnostic id 0x6F1 */
    EXPECT(g, 1000600u, CG_DROP, GW_06);           /* ReadDataById is not dangerous but still needs the key */
    setup(1, 0);
    CHECK(G.workshop_on == 1);
    EXPECT(a, 1000000u, CG_FORWARD, CG_RULE_NONE);
    EXPECT(c, 1000100u, CG_FORWARD, CG_RULE_NONE);
    EXPECT(e, 1000200u, CG_FORWARD, CG_RULE_NONE);
}

static void test_gw08_flood(void) {
    uint8_t d[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0x11 };
    cg_frame_t f = mkf(0x000, 8, d);
    uint32_t i, g8 = 0, g1 = 0;
    setup(0, 0);
    for (i = 0; i < 2000u; i++) {                   /* 4000 fps for half a second */
        cg_verdict_t v = ev_at(&f, CG_A_TO_B, 1000000u + i * 250u);
        CHECK(v.decision == CG_DROP);
        if (v.rule == GW_08) g8++; else if (v.rule == GW_01) g1++;
    }
    CHECK(g1 > 0u);   /* the burst is dropped as GW-01 (id 0 not in DBC) */
    CHECK(g8 > 1800u);                              /* then GW-08 takes over */
    CHECK(G.stats.events_suppressed > 1000u);       /* ...and the event log does not drown */
}

static void test_gw09_tamper(void) {
    uint8_t d[4] = { 1, 0, 0, 0 };
    cg_frame_t f = mkf(0x320, 4, d), spd = mkf(0x244, 8, d);
    cg_frame_t out = mkf(0x244, 8, d);
    setup(1, 1);
    CHECK(G.lockdown == 1);
    EXPECT(f, 1000000u, CG_DROP, GW_09);
    host_rx_push(CG_PORT_A, &f);
    host_rx_push(CG_PORT_B, &out);
    guard_poll(&G);
    CHECK(host_tx_count(CG_PORT_B) == 0);           /* nothing A -> B while locked, even with the workshop key */
    CHECK(host_tx_count(CG_PORT_A) == 1);           /* B -> A still flows */
    (void)spd;
    CHECK(guard_clear_lockdown(&G) == 0);           /* refused while the switch is still active */
    host_set_tamper(0);
    CHECK(guard_clear_lockdown(&G) == 1);
    EXPECT(f, 2000000u, CG_FORWARD, CG_RULE_NONE);
}

static void test_gw10(void) {
    static const uint8_t st[8] = { 0x88, 0x13, 0, 0, 0, 0, 0, 0 };          /* steering 5000 raw (+ SecOC FV/MAC) */
    static const uint8_t en[8] = { 0xA0, 0x0F, 130, 20, 0, 0, 0, 0 };       /* rpm 4000 raw */
    cg_frame_t s = mkf(0x0C4, 8, st), e = mkf(0x180, 8, en);
    setup(0, 0);
    EXPECT(s, 1000000u, CG_DROP, GW_10);
    EXPECT(e, 1000100u, CG_DROP, GW_10);
    setup(1, 0);                                    /* the workshop key does not open safety critical ids */
    EXPECT(s, 1000000u, CG_DROP, GW_10);
}

static void test_fail_closed(void) {
    uint8_t d[4] = { 1, 0, 0, 0 };
    cg_frame_t f = mkf(0x320, 4, d);
    cg_verdict_t v;
    setup(0, 0);
    v = guard_process(&G, &f, (cg_dir_t)7, 1000000u);
    CHECK(v.decision == CG_DROP && v.rule == GW_01);   /* corrupt direction value -> closed */
    G.selfcheck_ok = 0;                                 /* a failed policy self-check locks A -> B */
    EXPECT(f, 1100000u, CG_DROP, GW_09);
    CHECK(guard_clear_lockdown(&G) == 0);
}

static void test_b_to_a(void) {
    uint8_t d[8] = { 0 };
    cg_frame_t f = mkf(0x244, 8, d);
    cg_verdict_t v;
    setup(0, 0);
    v = guard_process(&G, &f, CG_B_TO_A, 1000000u);
    CHECK(v.decision == CG_FORWARD && v.rule == CG_RULE_NONE);
    CHECK(G.stats.b_to_a == 1 && G.stats.passed == 0);
}

/* ---------------------------------------------------------------- guard loop, inputs, events */

static void test_poll_forwarding(void) {
    uint8_t ok[4] = { 1, 0, 0, 0 }, bad[8] = { 0 };
    cg_frame_t good = mkf(0x320, 4, ok), evil = mkf(0x0C4, 8, bad), back = mkf(0x180, 8, bad);
    setup(0, 0);
    host_rx_push(CG_PORT_A, &good);
    host_rx_push(CG_PORT_A, &evil);
    host_rx_push(CG_PORT_B, &back);
    guard_poll(&G);
    CHECK(host_tx_count(CG_PORT_B) == 1 && host_tx_frame(CG_PORT_B, 0)->id == 0x320u);
    CHECK(host_tx_count(CG_PORT_A) == 1 && host_tx_frame(CG_PORT_A, 0)->id == 0x180u);
    CHECK(G.stats.passed == 1 && G.stats.blocked == 1 && G.stats.by_rule[GW_10] == 1);
    CHECK(host_led(CG_LED_PASS) == 1 && host_led(CG_LED_BLOCK) == 1);
    host_advance_ms(100);
    guard_poll(&G);
    CHECK(host_led(CG_LED_PASS) == 0 && host_led(CG_LED_BLOCK) == 0);
    host_set_tx_full(CG_PORT_B, 1);
    host_advance_ms(100);
    good.data[0] = 1;
    host_rx_push(CG_PORT_A, &good);
    guard_poll(&G);
    CHECK(G.stats.tx_lost == 1);                    /* TX FIFO full: counted, never stuck */
}

static void test_workshop_key_debounce(void) {
    static const uint8_t s10[3] = { 0x02, 0x10, 0x03 };
    cg_frame_t f = mkf(0x7E0, 3, s10);
    guard_config_t cfg;
    host_reset();
    guard_config_default(&cfg);
    guard_init(&G, &cfg);
    host_set_workshop(1);
    guard_poll(&G);
    CHECK(G.workshop_on == 0);                      /* a fresh edge does not open anything */
    host_advance_ms(10);
    guard_poll(&G);
    CHECK(G.workshop_on == 0);
    EXPECT(f, 1000000u, CG_DROP, GW_06);
    host_advance_ms(15);
    guard_poll(&G);
    CHECK(G.workshop_on == 1 && host_led(CG_LED_DIAG) == 1);
    host_set_workshop(0);
    guard_poll(&G);
    host_advance_ms(30);
    guard_poll(&G);
    CHECK(G.workshop_on == 0);
}

static void test_tamper_latch_event(void) {
    cg_event_t e;
    setup(0, 0);
    host_set_tamper(1);
    guard_poll(&G);
    guard_poll(&G);
    CHECK(G.lockdown == 1);
    CHECK(guard_event_pop(&G, &e) && e.kind == CG_EV_LOCKDOWN && e.rule == GW_09);
    CHECK(!guard_event_pop(&G, &e));                /* a single latch event */
    host_set_tamper(0);
    CHECK(G.lockdown == 1);                         /* the latch stays after the lid closes */
    CHECK(host_led(CG_LED_BLOCK) == 1);
}

static void test_event_json_and_mac(void) {
    uint8_t d[4] = { 0x31, 0x75, 0, 0 };
    cg_frame_t f = mkf(0x3C0, 4, d);
    cg_event_t e;
    char line[CG_EVENT_JSON_MAX];
    uint8_t mac[32];
    char hex[3];
    const char *p;
    int i;
    setup(0, 0);
    EXPECT(f, 1234567u, CG_DROP, GW_04);
    CHECK(guard_event_pop(&G, &e));
    CHECK(guard_event_to_json(&e, line, sizeof line) > 0);
    CHECK(strncmp(line, "{\"t\":1.234,\"ev\":\"BLOCK\",\"rule\":\"GW-04\",\"dir\":\"A>B\",\"id\":\"0x3C0\",\"dlc\":4,"
                        "\"data\":\"31750000\",\"seq\":0,\"mac\":\"", 100) == 0);
    p = strstr(line, ",\"mac\":\"");
    CHECK(p != 0);
    se_hmac_sha256((const uint8_t *)line, (uint16_t)(p - line), mac);
    for (i = 0; i < 8; i++) { snprintf(hex, sizeof hex, "%02x", mac[i]); CHECK(strncmp(p + 8 + 2 * i, hex, 2) == 0); }
    CHECK(strcmp(p + 8 + 16, "\"}") == 0);          /* MAC covers exactly the text before it */
    CHECK(guard_event_to_json(&e, line, 20) == 0);  /* too small: refuses instead of truncating */
    host_evt_clear();
    EXPECT(f, 2000000u, CG_DROP, GW_04);
    guard_flush_events(&G);
    CHECK(host_evt_len() > 0 && host_evt_data()[host_evt_len() - 1] == '\n');
}

static void test_event_coalescing_and_overflow(void) {
    uint8_t d[4] = { 0x31, 0x75, 0, 0 };
    cg_frame_t f = mkf(0x3C0, 4, d);
    cg_event_t e;
    uint32_t i, n = 0;
    setup(0, 0);
    for (i = 0; i < 10u; i++) EXPECT(f, 1000000u + i * 5000u, CG_DROP, GW_04);   /* 10 blocks in 45 ms */
    while (guard_event_pop(&G, &e)) n++;
    CHECK(n == 1u && G.stats.events_suppressed == 9u);                             /* one event per rule per 100 ms */
    for (i = 0; i < 40u; i++) {                                                    /* one event per 100 ms -> overflows */
        EXPECT(f, 2000000u + i * 100000u, CG_DROP, GW_04);
        if (i % 3u == 0u) (void)ev_at(&(cg_frame_t){ 0x555u, 0, 2, { 0 } }, CG_A_TO_B, 2000000u + i * 100000u + 1u);
    }
    CHECK(G.stats.events_lost > 0u);
    n = 0;
    while (guard_event_pop(&G, &e)) n++;
    CHECK(n == CG_EVENT_QUEUE - 1u);                                               /* ring keeps the newest 15 */
}

/* ---------------------------------------------------------------- parity with the Python model */

static void test_vectors_parity(void) {
    uint32_t c, i, frames = 0, mismatches = 0;
    for (c = 0; c < CGV_N_CASES; c++) {
        const cgv_case_t *cs = &cgv_cases[c];
        setup(cs->workshop, cs->tamper);
        policy_init(&G.pol);            /* identical initial bucket / counter state as the Python model */
        for (i = 0; i < cs->n; i++) {
            const cgv_frame_t *v = &cgv_frames[cs->first + i];
            cg_frame_t f;
            cg_verdict_t r;
            memset(&f, 0, sizeof f);
            f.id = v->id; f.ext = v->ext; f.dlc = v->dlc;
            memcpy(f.data, v->data, 8);
            r = guard_process(&G, &f, v->dir ? CG_B_TO_A : CG_A_TO_B, v->t_us);
            frames++;
            if (r.decision != v->drop || r.rule != v->rule) {
                if (mismatches++ < 10u)
                    printf("  MISMATCH case %s frame %u id 0x%X: C=%u/%u python=%u/%u\n", cs->name, (unsigned)i,
                           (unsigned)v->id, r.decision, r.rule, v->drop, v->rule);
            }
        }
    }
    printf("  parity: %u cases, %u frames, %u mismatches\n", (unsigned)CGV_N_CASES, (unsigned)frames, (unsigned)mismatches);
    CHECK(mismatches == 0u);
    CHECK(frames == CGV_N_FRAMES);
}

static void test_watchdog_and_leds(void) {
    setup(0, 0);
    CHECK(host_led(CG_LED_PWR) == 1);
    CHECK(host_wdt_kicks() > 0);
}

static void test_footprint(void) {
    printf("  guard_t = %u B, policy_state = %u B, event = %u B, tables = %u B\n", (unsigned)sizeof(guard_t),
           (unsigned)sizeof(policy_state_t), (unsigned)sizeof(cg_event_t), (unsigned)(sizeof(cg_msgs) + sizeof(cg_sigs)));
    CHECK(sizeof(guard_t) < 1024);                  /* budget: well below 1 % of the 144 KB RAM */
}

int main(void) {
    printf("GOK-Guard tests\n");
    RUN(test_crc_vectors); RUN(test_hmac_vector); RUN(test_selfcheck);
    RUN(test_forward_legit); RUN(test_gw01); RUN(test_gw02); RUN(test_gw03_bucket); RUN(test_clock_wrap);
    RUN(test_gw04); RUN(test_gw05); RUN(test_gw06_gw07); RUN(test_gw08_flood); RUN(test_gw09_tamper); RUN(test_gw10);
    RUN(test_fail_closed); RUN(test_b_to_a);
    RUN(test_poll_forwarding); RUN(test_workshop_key_debounce); RUN(test_tamper_latch_event);
    RUN(test_event_json_and_mac); RUN(test_event_coalescing_and_overflow);
    RUN(test_vectors_parity); RUN(test_watchdog_and_leds); RUN(test_footprint);
    printf("%d tests, %d checks, %d failed\n", g_tests, g_checks, g_fail);
    printf(g_fail ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_fail ? 1 : 0;
}
