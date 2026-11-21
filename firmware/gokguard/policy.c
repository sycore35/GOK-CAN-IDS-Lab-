#include "policy.h"

static const char *const rule_names[CG_N_RULES] = {
    "-", "GW-01", "GW-02", "GW-03", "GW-04", "GW-05", "GW-06", "GW-07", "GW-08", "GW-09", "GW-10"
};

const char *policy_rule_name(uint8_t rule) { return rule < CG_N_RULES ? rule_names[rule] : "GW-??"; }

uint8_t policy_crc8(const uint8_t *data, uint8_t n) {
    uint8_t crc = 0xFFu, i, b;
    for (i = 0; i < n; i++) {
        crc ^= data[i];
        for (b = 0; b < 8u; b++) crc = (uint8_t)((crc & 0x80u) ? ((crc << 1) ^ 0x1Du) : (crc << 1));
    }
    return (uint8_t)(crc ^ 0xFFu);
}

int policy_selfcheck(void) {
    uint32_t i, j, used = 0;
    for (i = 0; i < CG_N_MSGS; i++) {
        const cg_msg_t *m = &cg_msgs[i];
        if (m->dlc > 8u || m->rate_fps == 0u) return 0;
        if (i && cg_msgs[i - 1u].id >= m->id) return 0;                 /* sorted, unique */
        if ((uint32_t)m->sig_first != used) return 0;
        for (j = 0; j < m->sig_n; j++) {
            const cg_sig_t *s = &cg_sigs[m->sig_first + j];
            if (s->len == 0u || s->len > 32u || (uint32_t)s->start + s->len > (uint32_t)m->dlc * 8u) return 0;
            if (s->raw_min > s->raw_max) return 0;
        }
        used += m->sig_n;
        if ((m->flags & CG_F_COUNTER_CRC) && (m->crc_byte >= m->dlc || m->cnt_len == 0u || m->cnt_len > 8u)) return 0;
    }
    return used == CG_N_SIGS;   /* rates/bursts > 0 are enforced by tools/policy_compiler.py */
}

static void bucket_init(cg_bucket_t *b, uint32_t burst) { b->tokens = burst * 1000000u; b->last_us = 0; }

/* Token bucket in integer micro-frames: exact, identical in the Python mirror. Elapsed time is clamped to 1 s
 * (also covers uint32 wrap-around and clock jumps). Returns 1 if a frame may pass. */
static int bucket_take(cg_bucket_t *b, uint32_t rate_fps, uint32_t burst, uint32_t now_us) {
    uint32_t el = now_us - b->last_us;
    uint64_t tok;
    if (el > 1000000u) el = 1000000u;
    b->last_us = now_us;
    tok = (uint64_t)b->tokens + (uint64_t)el * rate_fps;
    if (tok > (uint64_t)burst * 1000000u) tok = (uint64_t)burst * 1000000u;
    if (tok < 1000000u) { b->tokens = (uint32_t)tok; return 0; }
    b->tokens = (uint32_t)(tok - 1000000u);
    return 1;
}

void policy_init(policy_state_t *st) {
    uint32_t i;
    bucket_init(&st->total, CG_TOTAL_BURST);
    for (i = 0; i < CG_N_MSGS; i++) {
        bucket_init(&st->per_id[i], CG_ID_BURST);
        st->last_counter[i] = 0;
        st->counter_valid[i] = 0;
    }
}

static int is_uds_id(uint32_t id) {
    uint32_t i;
    for (i = 0; i < CG_N_UDS_IDS; i++) if (cg_uds_ids[i] == id) return 1;
    return 0;
}

static int is_dangerous(int svc) {
    uint32_t i;
    if (svc < 0) return 0;
    for (i = 0; i < CG_N_DANGEROUS; i++) if (cg_dangerous[i] == (uint8_t)svc) return 1;
    return 0;
}

/* ISO-TP: single frame -> service at byte 1, first frame -> byte 2; consecutive/flow-control carry none (-1). */
static int uds_service(const cg_frame_t *f) {
    uint8_t pci, n;
    if (f->dlc < 2u) return -1;
    pci = (uint8_t)(f->data[0] >> 4);
    n = (uint8_t)(f->data[0] & 0x0Fu);
    if (pci == 0u && n >= 1u && n <= (uint8_t)(f->dlc - 1u)) return f->data[1];
    if (pci == 1u && f->dlc >= 3u) return f->data[2];
    return -1;
}

static uint32_t sig_raw(const cg_frame_t *f, const cg_sig_t *s) {
    uint64_t v = 0;
    uint8_t i;
    for (i = 0; i < 8u; i++) v |= (uint64_t)f->data[i] << (8u * i);
    v >>= s->start;
    if (s->len < 32u) v &= ((uint64_t)1 << s->len) - 1u;
    return (uint32_t)v;
}

static cg_verdict_t V(uint8_t d, uint8_t r) { cg_verdict_t v; v.decision = d; v.rule = r; return v; }

cg_verdict_t policy_evaluate(policy_state_t *st, const policy_ctx_t *ctx, const cg_frame_t *f,
                             cg_dir_t dir, uint32_t t_us) {
    const cg_msg_t *m = 0;
    uint32_t i, idx = 0;
    /* B -> A is the protected domain talking out: always allowed (also while locked). */
    if (dir == CG_B_TO_A) return V(CG_FORWARD, CG_RULE_NONE);
    if (dir != CG_A_TO_B) return V(CG_DROP, GW_01);                    /* fail-closed on a corrupt direction */

    if (ctx->locked) return V(CG_DROP, GW_09);                          /* tamper / failed self-check */
    if (f->dlc > 8u) return V(CG_DROP, GW_02);                          /* not a valid classic frame */
    if (!bucket_take(&st->total, CG_TOTAL_RATE_FPS, CG_TOTAL_BURST, t_us)) return V(CG_DROP, GW_08);

    if (!f->ext && is_uds_id(f->id)) {                                   /* workshop (diagnostic) traffic */
        if (ctx->workshop_key) return V(CG_FORWARD, CG_RULE_NONE);
        return V(CG_DROP, is_dangerous(uds_service(f)) ? GW_07 : GW_06);
    }

    if (!f->ext) {
        for (i = 0; i < CG_N_MSGS; i++) if (cg_msgs[i].id == f->id) { m = &cg_msgs[i]; idx = i; break; }
    }
    if (!m) return V(CG_DROP, GW_01);                                    /* not in the DBC */
    if (f->dlc != m->dlc) return V(CG_DROP, GW_02);

    if (m->flags & CG_F_COUNTER_CRC) {
        uint8_t cnt = (uint8_t)((f->data[m->cnt_start >> 3] >> (m->cnt_start & 7u)) & (uint8_t)((1u << m->cnt_len) - 1u));
        if (policy_crc8(f->data, m->crc_byte) != f->data[m->crc_byte]) return V(CG_DROP, GW_05);
        {
            uint8_t ok = (uint8_t)(!st->counter_valid[idx] ||
                                   cnt == (uint8_t)((st->last_counter[idx] + 1u) & ((1u << m->cnt_len) - 1u)));
            st->last_counter[idx] = cnt;
            st->counter_valid[idx] = 1;
            if (!ok) return V(CG_DROP, GW_05);
        }
    }
    for (i = 0; i < m->sig_n; i++) {
        const cg_sig_t *s = &cg_sigs[m->sig_first + i];
        uint32_t raw = sig_raw(f, s);
        if (raw < s->raw_min || raw > s->raw_max) return V(CG_DROP, GW_04);
    }
    if (m->flags & CG_F_CRITICAL) return V(CG_DROP, GW_10);
    if (!(m->flags & CG_F_A_ALLOWED)) return V(CG_DROP, GW_01);           /* direction not permitted for this ID */
    if (!bucket_take(&st->per_id[idx], m->rate_fps, CG_ID_BURST, t_us)) return V(CG_DROP, GW_03);
    return V(CG_FORWARD, CG_RULE_NONE);
}
