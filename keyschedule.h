#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Make use of _mm_aeskeygenassist_si128 so no memory lookups are needed anymore
// and we can stay in the mmx register :D

#define AES_128_key_exp_inv(r, k, rcon) { \
__m128i k0 = k; \
k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4)); \
__m128i t0 = _mm_aeskeygenassist_si128(k0, rcon); \
t0 = _mm_srli_si128(t0, 12); \
r = _mm_xor_si128(t0, k0); }

__attribute__((always_inline)) static void KeyExpansionFast(__m128i key_schedule[20]) {
  AES_128_key_exp_inv(key_schedule[9], key_schedule[10], 0x36);
  AES_128_key_exp_inv(key_schedule[8], key_schedule[9], 0x1B);
  AES_128_key_exp_inv(key_schedule[7], key_schedule[8], 0x80);
  AES_128_key_exp_inv(key_schedule[6], key_schedule[7], 0x40);
  AES_128_key_exp_inv(key_schedule[5], key_schedule[6], 0x20);
  AES_128_key_exp_inv(key_schedule[4], key_schedule[5], 0x10);
  AES_128_key_exp_inv(key_schedule[3], key_schedule[4], 0x08);
  AES_128_key_exp_inv(key_schedule[2], key_schedule[3], 0x04);
  AES_128_key_exp_inv(key_schedule[1], key_schedule[2], 0x02);
  AES_128_key_exp_inv(key_schedule[0], key_schedule[1], 0x01);
}