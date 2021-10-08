#ifndef __SUMHASH_H__
#define __SUMHASH_H__

#include <stddef.h>
#include <stdint.h>

#define SUMHASH512_N_ROWS 8
#define SUMHASH512_M_BITS 1024

#define SUMHASH512_BLOCK_SIZE 64    // m_bits/8 - n_rows*8 
#define SUMHASH512_DIGEST_SIZE 64 // n_rows*8

typedef struct sumhash512_state {
    uint8_t salt[SUMHASH512_BLOCK_SIZE]; // salt block. NULL means unsalted mode

    uint64_t state[SUMHASH512_N_ROWS];
    uint64_t count[2];
    uint8_t  buf[SUMHASH512_BLOCK_SIZE];
    uint32_t has_salt;
} sumhash512_state;

int sumhash_lib_init();

void sumhash512_init(sumhash512_state *state);
void sumhash512_init_salted(sumhash512_state *state, const uint8_t salt[SUMHASH512_BLOCK_SIZE]);

void sumhash512_update(sumhash512_state *state, const uint8_t *in, unsigned long long inlen);
void sumhash512_final(sumhash512_state *state, uint8_t *out);

void sumhash512(uint8_t *out, const uint8_t *in, unsigned int inlen);
void sumhash512_salted(uint8_t *out, const uint8_t *in, unsigned int inlen, const uint8_t salt[SUMHASH512_BLOCK_SIZE]);

#endif
