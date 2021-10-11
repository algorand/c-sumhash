#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "include/sumhash512.h"
#include "src/fips202.h"


#define TV_DIFF_US(a, b)                                                \
    (((b).tv_sec - (a).tv_sec) * 1000000 + ((b).tv_usec - (a).tv_usec))


void benchmark_sumhash512(){
    static const uint32_t NUMBER_OF_ITERS = 4200;
    keccak_state shake;
    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash input", 13);
    const int input_len = 600;
    uint8_t input[input_len];
    shake256_squeeze(input, input_len, &shake);

    struct timeval start, end;
    unsigned long acc_time = 0;
    for (uint32_t i = 0; i < NUMBER_OF_ITERS; ++i){
            
        gettimeofday(&start, NULL);
        sumhash512_state hash;
        sumhash512_init(&hash);
        sumhash512_update(&hash, (uint8_t*)input, input_len);
        uint8_t output [SUMHASH512_DIGEST_SIZE];
        sumhash512_final(&hash, output);
        gettimeofday(&end, NULL);
        acc_time += TV_DIFF_US(start,end);
    }

    printf("benchmark %s: avg time : %f usec\n", __FUNCTION__, (double)acc_time/NUMBER_OF_ITERS);
}


int main() {
    benchmark_sumhash512();
    return 0;
}

