#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "include/sumhash512.h"
#include "src/fips202.h"

#define TESTS_INPUT_LEN 6000

#define TV_DIFF_US(a, b)                                                \
    (((b).tv_sec - (a).tv_sec) * 1000000 + ((b).tv_usec - (a).tv_usec))


void benchmark_sumhash512(){
    static const uint32_t INIT_NUMBER_OF_ITERS = 4200;
    static const uint32_t NUMBER_OF_WARMUP_ITERS = 100;
    static const uint32_t LOWER_TIME_BOUND = 100000;
    keccak_state shake;
    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash input", 13);
    uint8_t input[TESTS_INPUT_LEN];
    shake256_squeeze(input, TESTS_INPUT_LEN, &shake);

    struct timeval start, end;
    double acc_time = 0;
    
    // warmup!
    for (uint32_t i = 0; i < NUMBER_OF_WARMUP_ITERS; ++i){
        sumhash512_state hash;
        sumhash512_init(&hash);
        sumhash512_update(&hash, (uint8_t*)input, TESTS_INPUT_LEN);
        uint8_t output [SUMHASH512_DIGEST_SIZE];
        sumhash512_final(&hash, output);
    }
    
    uint32_t number_of_iters = INIT_NUMBER_OF_ITERS;
    do {
        gettimeofday(&start, NULL);
        for (uint32_t i = 0; i < number_of_iters; ++i){

            sumhash512_state hash;
            sumhash512_init(&hash);
            sumhash512_update(&hash, (uint8_t*)input, TESTS_INPUT_LEN);
            uint8_t output [SUMHASH512_DIGEST_SIZE];
            sumhash512_final(&hash, output);
        }
        gettimeofday(&end, NULL);
        acc_time = TV_DIFF_US(start,end);
        number_of_iters *= 2;
    } while( acc_time < (double)LOWER_TIME_BOUND);



    printf("benchmark %s: avg time : %f usec\n", __FUNCTION__, (double)acc_time/number_of_iters);
}


int main() {
    benchmark_sumhash512();
    return 0;
}

