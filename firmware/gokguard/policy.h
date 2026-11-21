/* policy.h -- GOK-GW1 gateway policy GW-01..GW-10: a pure function (frame, direction, time, context) -> decision.
 * Python mirror: src/gateway_model.py (the evaluation ORDER below must match it exactly). */
#ifndef CG_POLICY_H
#define CG_POLICY_H

#include <stdint.h>
#include "can_frame.h"
#include "policy_generated.h"

typedef enum { CG_A_TO_B = 0, CG_B_TO_A = 1 } cg_dir_t;
typedef enum { CG_FORWARD = 0, CG_DROP = 1 } cg_decision_t;

/* 0 = no rule (forwarded). */
enum { CG_RULE_NONE = 0, GW_01 = 1, GW_02, GW_03, GW_04, GW_05, GW_06, GW_07, GW_08, GW_09, GW_10, CG_N_RULES = 11 };

typedef struct { uint32_t tokens; uint32_t last_us; } cg_bucket_t;   /* tokens in micro-frames (1 frame = 1e6) */

typedef struct {
    cg_bucket_t total;                 /* GW-08 */
    cg_bucket_t per_id[CG_N_MSGS];     /* GW-03 */
    uint8_t last_counter[CG_N_MSGS];   /* GW-05 */
    uint8_t counter_valid[CG_N_MSGS];
} policy_state_t;

typedef struct {
    uint8_t workshop_key;   /* debounced workshop switch closed */
    uint8_t locked;         /* tamper latch / failed self-check: GW-09 */
} policy_ctx_t;

typedef struct { uint8_t decision; uint8_t rule; } cg_verdict_t;

void policy_init(policy_state_t *st);
cg_verdict_t policy_evaluate(policy_state_t *st, const policy_ctx_t *ctx, const cg_frame_t *f,
                             cg_dir_t dir, uint32_t t_us);

/* CRC-8 SAE J1850 (poly 0x1D, init 0xFF, xorout 0xFF) -- identical to src/dbc_decoder.py:calc_crc8_sae_j1850. */
uint8_t policy_crc8(const uint8_t *data, uint8_t n);
/* Table sanity (sorted IDs, signals inside DLC, counts). 1 = ok. Failure => guard stays locked (fail-closed). */
int policy_selfcheck(void);
const char *policy_rule_name(uint8_t rule);   /* "GW-01".. ; "-" for none */

#endif
