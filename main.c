#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sumhash.h"
#include "fips202.h"

void encodeHex(char *dst, uint8_t *data, int len) {
    char *ptr = dst;
    for (int i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%02x", data[i]);
    }
}

int main() {
    int input_len = 6000;
    keccak_state shake;
    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash input", 13);
    uint8_t input[input_len];
    shake256_squeeze(input, input_len, &shake);

    sumhash_state st;
    uint8_t out[SUMHASH512_DIGEST_LENGTH];

    sumhash512_init(&st);
    sumhash512_update(&st, input, input_len);
    sumhash512_final(&st, out);

    char hexbuf[1024];
    encodeHex(hexbuf, out, SUMHASH512_DIGEST_LENGTH);
    char *expected =  "1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa";
    if (strcmp(hexbuf, expected) != 0) {
        printf("got %s, want %s\n", hexbuf, expected);
        //return 1;
    }

    uint8_t salt[SUMHASH512_BLOCK_SIZE];
    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash salt", 12);
    shake256_squeeze(salt, SUMHASH512_BLOCK_SIZE, &shake);

    sumhash512_init_salted(&st, salt);
    sumhash512_update(&st, input, input_len);
    sumhash512_final(&st, out);

    encodeHex(hexbuf, out, SUMHASH512_DIGEST_LENGTH);
    expected = "bc0f4251957352da5102970a32ecad694d88e9f9c4230a2b13d2c7037107245e64e1f7e7dbeca625e2f7d1cd5f63d9070e0255b687301ade29fab952dd44abc7";

    if (strcmp(hexbuf, expected) != 0) {
        printf("got %s, want %s\n", hexbuf, expected);
        return 1;
    }

    printf("OK\n");
}