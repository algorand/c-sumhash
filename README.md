Sumhash
====================

Algorand's subset-sum hash function implementation in C.

# Build And Tests

```bash
git clone https://github.com/algorand/sumhash-c
make
```

The ```make``` command will build the library and run the function on the test vector.
The output can be found on the build dir:
```bash
./build/libsumhash.a
```

# Usage 

```C
#include <stdio.h>
#include <string.h>

#include "include/sumhash.h"

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

The ```include/sumhash.h``` header contains more information about the functions usage

# Spec

The specification of the function as well as the security parameters
can be found [here](https://github.com/algorand/snark-friendly-crypto/tree/master/spec)  
