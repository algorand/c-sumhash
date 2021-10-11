C-Sumhash
====================

Algorand's subset-sum hash function implementation in C.

# Build And Tests

```bash
git clone https://github.com/algorand/c-sumhash
make
```

The ```make``` command builds the library and runs the tests.
The output can be found in the build directory:
```bash
./build/libsumhash.a
```

# Usage 

```C
#include <stdio.h>
#include <string.h>

#include "include/sumhash512.h"

int main() {
    char* input = "Algorand";
    sumhash512_state hash;
    sumhash512_init(&hash);
    sumhash512_update(&hash, (uint8_t*)input, strlen(input));
    uint8_t output [SUMHASH512_DIGEST_SIZE];
    sumhash512_final(&hash, output);

    return 0;
}
```

Simple API usage:
```C
#include <stdio.h>
#include <string.h>

#include "include/sumhash512.h"

int main() {
    char* input = "Algorand";
    uint8_t output [SUMHASH512_DIGEST_SIZE];
    sumhash512(output, (uint8_t*)input, strlen(input));

    return 0;
}
```


The ```include/sumhash.h``` header contains more information about the functions usage

# Spec

The specification of the function as well as the security parameters
can be found [here](https://github.com/algorand/snark-friendly-crypto/tree/master/spec)  
