#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "include/sumhash512.h"
#include "src/fips202.h"

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
		"0e7698f535975ebaf1fdcd38819589aa9906595ea9e86c73aded6964651d869a2c1579fbdd9c977ec5f5fc3b61749db57cad898f80f5c69f9a8f013cb7aafedc",
	},
	{
		"a",
		"4aa8bd2e6d455ff812cecd8dcd258e1c9f97561888e3474c9740c71ad31c86522d980f522e2964c733d4f52d94897ce143674b20fc41feae95ee092154925eda",
	},
	{
		"ab",
		"a33ae2accf2d45021fa57831ed0152a24aa5553a45f240a1d29b5e732f87b697b50c5e4fe25f442b3e30ec035a44ae95045912d59ae5993f05575b6bb3017188",
	},
	{
		"abc",
		"3fb641e5b7ffdce77abf80104b458dab1a0012729d158f4dac96a43993b26ad1b58261f090e50b20e242d02e531834aa5a76c5a99ab2e49d01b282eceeae6ec8",
	},
	{
		"abcd",
		"e5775a6f14bdb1cca1b0c2378e9c0c140332efe9bb48ebe32236a52902580e1ad199670cb3f9a773931a4b1467e899e91dd23bc95a4929f132ef9b34fd1c3de4",
	},
	{
		"You must be the change you wish to see in the world. -Mahatma Gandhi",
		"2495462abaa3b2eaa84b32eae9d97e1031dfde9cfebe78e8de1df110a0f1a80f918e4f652b8f6c754698413ebbfac41f74ec1a25111769a7633151e49b90ecfe",
	},
	{
		"I think, therefore I am. – Rene Descartes.",
		"4a22a6207adb7a978a980c8bfb173d96d24d5faf3f22848f8bd4de09c24f11180d3eeafdc06a13d3f9e62458460ece5587e0b1cbca875663cf19d146788b1dd4",
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

    char *expected =  "1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa";
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

    char *expected =  "bc0f4251957352da5102970a32ecad694d88e9f9c4230a2b13d2c7037107245e64e1f7e7dbeca625e2f7d1cd5f63d9070e0255b687301ade29fab952dd44abc7";
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

