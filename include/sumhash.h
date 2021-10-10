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
    uint32_t use_salt;
} sumhash512_state;


/******************************************************************
 *  sumhash512_init - initializes the sumhash512_state struct
 *  so it can be used on the following sumhash512 functions
 * 
 * IN : state - the struct to be initialized
 ******************************************************************/
void sumhash512_init(sumhash512_state *state);

/******************************************************************
 *  sumhash512_init_salted - initializes the sumhash512_state struct
 *  using a salt array.
 * 
 * IN : state - the struct to be initialized
 * IN : salt - salted data which will be used by the sumhash512 function.
 ******************************************************************/
void sumhash512_init_salted(sumhash512_state *state, const uint8_t salt[SUMHASH512_BLOCK_SIZE]);

/******************************************************************
 *  sumhash512_update - append data to the hash function input
 * 
 * IN : state - sumhash512_state struct (already initialized)
 * IN : in - array of bytes to be consumed be the hash function.
 * IN : inlen - the size in bytes of the in array.
 ******************************************************************/
void sumhash512_update(sumhash512_state *state, const uint8_t *in, unsigned long long inlen);

/******************************************************************
 *  sumhash512_final - return the digest result of the sumhash512 function 
 * 
 * IN : state - sumhash512_state struct (already initialized)
 * OUT : out - array in which the digest result will be returned.
 *              the size MUST have size of SUMHASH512_DIGEST_SIZE
 ******************************************************************/
void sumhash512_final(sumhash512_state *state, uint8_t *out);

/******************************************************************
 *  sumhash512 - calculate sumhash on a given input.
 * 
 * OUT : out - array in which the digest result will be returned.
 *              the size MUST have size of SUMHASH512_DIGEST_SIZE
 * IN : in - array of bytes on which hash will be evaluated.
 * IN : inlen - the size in bytes of the in array.
 ******************************************************************/
void sumhash512(uint8_t *out, const uint8_t *in, unsigned int inlen);

/******************************************************************
 *  sumhash512 - calculate sumhash on a given input and a salt input
 * 
 * OUT : out - array in which the digest result will be returned.
 *              the size MUST have size of SUMHASH512_DIGEST_SIZE
 * IN : in - array of bytes on which hash will be evaluated.
 * IN : inlen - the size in bytes of the in array.
 * IN : salt - salted data used by the sumhash512 function.
 ******************************************************************/
void sumhash512_salted(uint8_t *out, const uint8_t *in, unsigned int inlen, const uint8_t salt[SUMHASH512_BLOCK_SIZE]);

#endif
