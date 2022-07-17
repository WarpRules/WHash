#ifndef WHASH_UTILITIES_HH__
#define WHASH_UTILITIES_HH__
#include <cstddef>

namespace WHash
{
    /* Compares two given byte arrays for equality (mainly intended for comparing if two
       hashes are equal). The main idea with this is that the function will always take
       the same amount of time regardless of whether the two arrays are equal or not
       (or where the first difference between them is). This is to minimize the possibility
       of side-channel attacks based on how long an array/hash comparison takes.
    */
    bool byteArraysEqual(const void*, const void*, std::size_t bytesAmount);
}


inline bool WHash::byteArraysEqual(const void* a1, const void* a2, std::size_t bytesAmount)
{
    const unsigned char *ba1 = static_cast<const unsigned char*>(a1);
    const unsigned char *ba2 = static_cast<const unsigned char*>(a2);
    unsigned char diff = 0;
    for(std::size_t i = 0; i < bytesAmount; ++i)
        diff |= ba1[i] ^ ba2[i];
    return diff == 0;
}

#endif
