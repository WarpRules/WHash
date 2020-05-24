#ifndef WHASH_SHA1_HH__
#define WHASH_SHA1_HH__

#include <cstring>
#include <cstdint>

#define WHASH_SHA1_VERSION 0x010000
#define WHASH_SHA1_VERSION_STRING "1.0.0"
#define WHASH_SHA1_COPYRIGHT_STRING "WHash SHA1 v" WHASH_SHA1_VERSION_STRING " (C)2020 Juha Nieminen"

namespace WHash { class SHA1; }

class WHash::SHA1
{
 public:
    static const unsigned kDigestBytes = 20;

    SHA1();

    void initialize();
    void update(const void* inputBytes, std::size_t inputBytesSize);
    const unsigned char* finish();
    const unsigned char* currentHash() const { return mHashData.hash; }


 private:
    union HashData
    {
        std::uint32_t h0, h1, h2, h3, h4;
        unsigned char hash[20];
    };

    std::uint8_t mBuffer[64];
    std::uint64_t mInputBytesTotalSize;
    unsigned mBufferIndex;
    HashData mHashData;

    void processBuffer();
    static std::uint32_t bigEndianBytesToUInt32(const std::uint8_t*);
    static void assignAsBigEndian(unsigned char*, std::uint32_t);
};

inline WHash::SHA1::SHA1()
{
    initialize();
}

inline void WHash::SHA1::initialize()
{
    mHashData.h0 = UINT32_C(0x67452301);
    mHashData.h1 = UINT32_C(0xEFCDAB89);
    mHashData.h2 = UINT32_C(0x98BADCFE);
    mHashData.h3 = UINT32_C(0x10325476);
    mHashData.h4 = UINT32_C(0xC3D2E1F0);
    mInputBytesTotalSize = 0;
    mBufferIndex = 0;
}

inline std::uint32_t WHash::SHA1::bigEndianBytesToUInt32(const std::uint8_t* bytes)
{
    return ((static_cast<std::uint32_t>(bytes[0]) << 24) |
            (static_cast<std::uint32_t>(bytes[1]) << 16) |
            (static_cast<std::uint32_t>(bytes[2]) << 8) |
            static_cast<std::uint32_t>(bytes[3]));
}

inline void WHash::SHA1::assignAsBigEndian(unsigned char* dest, std::uint32_t value)
{
    dest[0] = static_cast<unsigned char>(value >> 24);
    dest[1] = static_cast<unsigned char>(value >> 16);
    dest[2] = static_cast<unsigned char>(value >> 8);
    dest[3] = static_cast<unsigned char>(value);
}

inline void WHash::SHA1::processBuffer()
{
    std::uint32_t w[80];

    for(unsigned i = 0; i < 16; ++i)
        w[i] = bigEndianBytesToUInt32(mBuffer + i*4);

    for(unsigned i = 16; i < 32; ++i)
    {
        const std::uint32_t v = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (v << 1) | (v >> 31);
    }

    for(unsigned i = 32; i < 80; ++i)
    {
        const std::uint32_t v = w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32];
        w[i] = (v << 2) | (v >> 30);
    }

    std::uint32_t a = mHashData.h0;
    std::uint32_t b = mHashData.h1;
    std::uint32_t c = mHashData.h2;
    std::uint32_t d = mHashData.h3;
    std::uint32_t e = mHashData.h4;

    for(unsigned i = 0; i < 20; ++i)
    {
        const std::uint32_t f = (b & c) | (~b & d);
        const std::uint32_t temp = ((a << 5) | (a >> (32-5))) + f + e + UINT32_C(0x5A827999) + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }

    for(unsigned i = 20; i < 40; ++i)
    {
        const std::uint32_t f = b ^ c ^ d;
        const std::uint32_t temp = ((a << 5) | (a >> (32-5))) + f + e + UINT32_C(0x6ED9EBA1) + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }

    for(unsigned i = 40; i < 60; ++i)
    {
        const std::uint32_t f = (b & c) | (b & d) | (c & d);
        const std::uint32_t temp = ((a << 5) | (a >> (32-5))) + f + e + UINT32_C(0x8F1BBCDC) + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }

    for(unsigned i = 60; i < 80; ++i)
    {
        const std::uint32_t f = b ^ c ^ d;
        const std::uint32_t temp = ((a << 5) | (a >> (32-5))) + f + e + UINT32_C(0xCA62C1D6) + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }

    mHashData.h0 += a;
    mHashData.h1 += b;
    mHashData.h2 += c;
    mHashData.h3 += d;
    mHashData.h4 += e;
}

inline void WHash::SHA1::update(const void* inputBytes, std::size_t inputBytesSize)
{
    mInputBytesTotalSize += static_cast<std::uint64_t>(inputBytesSize);

    if(mBufferIndex + inputBytesSize < 64)
    {
        std::memcpy(mBuffer + mBufferIndex, inputBytes, inputBytesSize);
        mBufferIndex += static_cast<unsigned>(inputBytesSize);
    }
    else
    {
        const unsigned char* inputData = static_cast<const unsigned char*>(inputBytes);

        if(mBufferIndex > 0)
        {
            const unsigned bytesToCopy = 64 - mBufferIndex;
            std::memcpy(mBuffer + mBufferIndex, inputData, bytesToCopy);
            mBufferIndex = 0;
            inputData += bytesToCopy;
            inputBytesSize -= bytesToCopy;
            processBuffer();
        }

        while(inputBytesSize >= 64)
        {
            std::memcpy(mBuffer, inputData, 64);
            inputData += 64;
            inputBytesSize -= 64;
            processBuffer();
        }

        if(inputBytesSize > 0)
        {
            std::memcpy(mBuffer, inputData, inputBytesSize);
            mBufferIndex = static_cast<unsigned>(inputBytesSize);
        }
    }
}

inline const unsigned char* WHash::SHA1::finish()
{
    const std::uint64_t inputBytesTotalSize = mInputBytesTotalSize;

    unsigned char appendData[64+8] = { 0x80 };
    unsigned appendDataSize = 64 - mBufferIndex;
    if(appendDataSize < 9) appendDataSize += 64;

    unsigned char* dataSizeDest = appendData + (appendDataSize - 8);
    dataSizeDest[0] = static_cast<unsigned char>(inputBytesTotalSize >> (8*7));
    dataSizeDest[1] = static_cast<unsigned char>(inputBytesTotalSize >> (8*6));
    dataSizeDest[2] = static_cast<unsigned char>(inputBytesTotalSize >> (8*5));
    dataSizeDest[3] = static_cast<unsigned char>(inputBytesTotalSize >> (8*4));
    dataSizeDest[4] = static_cast<unsigned char>(inputBytesTotalSize >> (8*3));
    dataSizeDest[5] = static_cast<unsigned char>(inputBytesTotalSize >> (8*2));
    dataSizeDest[6] = static_cast<unsigned char>(inputBytesTotalSize >> 8);
    dataSizeDest[7] = static_cast<unsigned char>(inputBytesTotalSize);

    update(appendData, appendDataSize);

    assignAsBigEndian(mHashData.hash, mHashData.h0);
    assignAsBigEndian(mHashData.hash+4, mHashData.h1);
    assignAsBigEndian(mHashData.hash+8, mHashData.h2);
    assignAsBigEndian(mHashData.hash+12, mHashData.h3);
    assignAsBigEndian(mHashData.hash+16, mHashData.h4);

    return mHashData.hash;
}
#endif
