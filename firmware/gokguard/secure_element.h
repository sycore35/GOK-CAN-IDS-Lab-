/* secure_element.h -- trust-anchor abstraction for event-log authentication and (later) signed policy.
 * Target: ATECC608A (I2C): HMAC key lives in a slot and never leaves the chip (SHA/HMAC command).
 * Host: se_host.c, a software HMAC-SHA256 with a FIXED TEST KEY -- a stand-in, NOT secure. */
#ifndef CG_SECURE_ELEMENT_H
#define CG_SECURE_ELEMENT_H

#include <stdint.h>

/* Returns 0 on success. */
int se_init(void);
/* out = HMAC-SHA256(device_key, data). Returns 0 on success. */
int se_hmac_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]);

#endif
