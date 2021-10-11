#ifndef __SUMHASH_UTILS_H__
#define __SUMHASH_UTILS_H__
#include <stdint.h>

#ifndef __BYTE_ORDER__
    #error "could not determine machine byte order"
#endif


static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

static inline uint64_t
load64_le(const uint8_t src[8])
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] <<  8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
#endif
}

static void
le64enc_vect(unsigned char *dst, const uint64_t *src, size_t len)
{

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(dst, src, len);
#else
    size_t i;
    for (i = 0; i < len / 8; i++) {
        store64_le(dst + i * 8, src[i]);
    }
#endif
}

#endif
