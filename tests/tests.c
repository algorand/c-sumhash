#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "include/sumhash512.h"
#include "fips202.h"

void encode_hex(char *dst, uint8_t *data, int len) {
    char *ptr = dst;
    for (int i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%02x", data[i]);
    }
}

void print_hex(uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

#define TESTS_INPUT_LEN 6000
#define TEST_ELEMENT_SIZE 256 

typedef struct test_element_t {
    char string_to_be_hashed[TEST_ELEMENT_SIZE];
    char expected_output[TEST_ELEMENT_SIZE];
}test_element;


const test_element test_vector[] = {
	{
		"",
		"591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0",
	},
	{
		"a",
		"ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6",
	},
	{
		"ab",
		"ef09d55b6add510f1706a52c4b45420a6945d0751d73b801cbc195a54bc0ade0c9ebe30e09c2c00864f2bd1692eba79500965925e2be2d1ac334425d8d343694",
	},
	{
		"abc",
		"a8e9b8259a93b8d2557434905790114a2a2e979fbdc8aa6fd373315a322bf0920a9b49f3dc3a744d8c255c46cd50ff196415c8245cdbb2899dec453fca2ba0f4",
	},
	{
		"abcd",
		"1d4277f17e522c4607bc2912bb0d0ac407e60e3c86e2b6c7daa99e1f740fe2b4fc928defad8e1ccc4e7d96b79896ffe086836c172a3db40a154d2229484f359b",
	},
	{
		"You must be the change you wish to see in the world. -Mahatma Gandhi",
		"5c5f63ac24392d640e5799c4164b7cc03593feeec85844cc9691ea0612a97caabc8775482624e1cd01fb8ce1eca82a17dd9d4b73e00af4c0468fd7d8e6c2e4b5",
	},
	{
		"I think, therefore I am. – Rene Descartes.",
		"2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a",
	},
};

int test_sanity(){
    printf ("running test: %s\n", __FUNCTION__);
    
    keccak_state shake;
    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash input", 13);

    uint8_t input[TESTS_INPUT_LEN];
    shake256_squeeze(input, TESTS_INPUT_LEN, &shake);

    sumhash512_state hash;
    sumhash512_init(&hash);
    sumhash512_update(&hash, (uint8_t*)input, TESTS_INPUT_LEN);
    uint8_t output [SUMHASH512_DIGEST_SIZE];
    sumhash512_final(&hash, output);

    char *expected =  "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";
    char hex_buf[1024];
    encode_hex(hex_buf, output, SUMHASH512_DIGEST_SIZE);
    if (strcmp(hex_buf, expected) != 0){
        printf("got %s, expected %s\n", hex_buf, expected);
        return -1;
    }
    return 0;
}

int test_salt(){
    printf ("running test: %s\n", __FUNCTION__);
    
    keccak_state shake;
    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash input", 13);

    uint8_t input[TESTS_INPUT_LEN];
    shake256_squeeze(input, TESTS_INPUT_LEN, &shake);

    uint8_t salt[SUMHASH512_BLOCK_SIZE];

    shake256_init(&shake);
    shake256_absorb_once(&shake, (uint8_t*)"sumhash salt", 12);
    shake256_squeeze(salt, SUMHASH512_BLOCK_SIZE, &shake);

    sumhash512_state hash;
    sumhash512_init_salted(&hash, salt);    
    sumhash512_update(&hash, input, TESTS_INPUT_LEN);
    uint8_t output [SUMHASH512_DIGEST_SIZE];
    sumhash512_final(&hash, output);

    char *expected = "c9be08eed13218c30f8a673f7694711d87dfec9c7b0cb1c8e18bf68420d4682530e45c1cd5d886b1c6ab44214161f06e091b0150f28374d6b5ca0c37efc2bca7";
    char hex_buf[1024];
    encode_hex(hex_buf, output, SUMHASH512_DIGEST_SIZE);
    if (strcmp(hex_buf, expected) != 0){
        printf("got %s, expected %s\n", hex_buf, expected);
        return -1;
    }
    return 0;
}

int test_run_test_vector() {
    printf ("running test: %s\n", __FUNCTION__);
    
    for (uint32_t i = 0 ; i < sizeof(test_vector)/sizeof(test_vector[0]); ++i){
        sumhash512_state hash;
        sumhash512_init(&hash);
        sumhash512_update(&hash, (uint8_t*)test_vector[i].string_to_be_hashed, strlen(test_vector[i].string_to_be_hashed));

        uint8_t output [SUMHASH512_DIGEST_SIZE];
        sumhash512_final(&hash, output);

        char hex_buf[1024];
        encode_hex(hex_buf, output, SUMHASH512_DIGEST_SIZE);
        if (strcmp(hex_buf, test_vector[i].expected_output) != 0 ){
            printf("got %s, expected %s\n", hex_buf, test_vector[i].expected_output);
            return -1;
        }
    }
    return 0;
}


int test_run_test_simple_api() {
    printf ("running test: %s\n", __FUNCTION__);
    
    for (uint32_t i = 0 ; i < sizeof(test_vector)/sizeof(test_vector[0]); ++i){
        uint8_t output [SUMHASH512_DIGEST_SIZE];
        sumhash512(output, (uint8_t*)test_vector[i].string_to_be_hashed, strlen(test_vector[i].string_to_be_hashed));
    
        char hex_buf[1024];
        encode_hex(hex_buf, output, SUMHASH512_DIGEST_SIZE);
        if (strcmp(hex_buf, test_vector[i].expected_output) != 0 ){
            printf("got %s, expected %s\n", hex_buf, test_vector[i].expected_output);
            return -1;
        }
    }
    return 0;
}

int main() {
    if (test_sanity() != 0) {
        printf("Test failed!\n");
    }
    if (test_salt() != 0) {
        printf("Test failed!\n");
    }
    if (test_run_test_vector() != 0) {
        printf("Test failed!\n");
    }
    if (test_run_test_simple_api() != 0) {
        printf("Test failed!\n");
    }
    else {
        printf("All tests passed\n");
        return 0;
    }
    return 1;
}

