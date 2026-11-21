/* Software stand-in for the ATECC608A (host tests only). Fixed key, plain SHA-256 (FIPS 180-4). */
#include "secure_element.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

typedef struct { uint32_t h[8]; uint8_t buf[64]; uint32_t nbuf; uint32_t total; } sha_t;

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void block(sha_t *s, const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) | ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(sha_t *s) {
    static const uint32_t iv[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    memcpy(s->h, iv, sizeof iv); s->nbuf = 0; s->total = 0;
}

static void sha_update(sha_t *s, const uint8_t *d, uint32_t n) {
    s->total += n;
    while (n--) {
        s->buf[s->nbuf++] = *d++;
        if (s->nbuf == 64u) { block(s, s->buf); s->nbuf = 0; }
    }
}

static void sha_final(sha_t *s, uint8_t out[32]) {
    uint32_t bits_hi = s->total >> 29, bits_lo = s->total << 3;
    uint8_t pad = 0x80;
    int i;
    sha_update(s, &pad, 1);
    pad = 0;
    while (s->nbuf != 56u) sha_update(s, &pad, 1);
    for (i = 3; i >= 0; i--) { uint8_t b = (uint8_t)(bits_hi >> (8 * i)); sha_update(s, &b, 1); }
    for (i = 3; i >= 0; i--) { uint8_t b = (uint8_t)(bits_lo >> (8 * i)); sha_update(s, &b, 1); }
    for (i = 0; i < 8; i++) { out[4*i] = (uint8_t)(s->h[i] >> 24); out[4*i+1] = (uint8_t)(s->h[i] >> 16); out[4*i+2] = (uint8_t)(s->h[i] >> 8); out[4*i+3] = (uint8_t)s->h[i]; }
}

/* Exposed for the RFC 4231 test (not part of secure_element.h). */
void se_host_hmac_with_key(const uint8_t *key, uint16_t klen, const uint8_t *data, uint16_t len, uint8_t out[32]);
void se_host_hmac_with_key(const uint8_t *key, uint16_t klen, const uint8_t *data, uint16_t len, uint8_t out[32]) {
    uint8_t k[64], ipad[64], inner[32];
    sha_t s;
    int i;
    memset(k, 0, sizeof k);
    if (klen > 64u) { sha_init(&s); sha_update(&s, key, klen); sha_final(&s, k); } else memcpy(k, key, klen);
    for (i = 0; i < 64; i++) ipad[i] = k[i] ^ 0x36u;
    sha_init(&s); sha_update(&s, ipad, 64); sha_update(&s, data, len); sha_final(&s, inner);
    for (i = 0; i < 64; i++) ipad[i] = k[i] ^ 0x5Cu;
    sha_init(&s); sha_update(&s, ipad, 64); sha_update(&s, inner, 32); sha_final(&s, out);
}

static const uint8_t test_key[16] = "CG-HOST-TESTKEY-";

int se_init(void) { return 0; }
int se_hmac_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]) {
    se_host_hmac_with_key(test_key, 16, data, len, out);
    return 0;
}
