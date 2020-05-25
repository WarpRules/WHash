#ifndef WHASH_SHA2_BASE_HH__
#define WHASH_SHA2_BASE_HH__

#include <cstring>
#include <cstdint>

namespace WHash
{
    template<typename UInt_t, unsigned kRounds,
             unsigned kSigmaR1, unsigned kSigmaR2, unsigned kSigmaS1,
             unsigned kSigmaR3, unsigned kSigmaR4, unsigned kSigmaS2,
             unsigned kSumR1, unsigned kSumR2, unsigned kSumR3,
             unsigned kSumR4, unsigned kSumR5, unsigned kSumR6,
             UInt_t... kRoundConstants>
    class SHA2_base
    {
     public:
        void update(const void* inputBytes, std::size_t inputBytesSize);
        const unsigned char* finish();
        const unsigned char* currentHash() const { return mHashData.hash; }


     protected:
        union HashData
        {
            struct { UInt_t h0, h1, h2, h3, h4, h5, h6, h7; };
            unsigned char hash[sizeof(UInt_t)*8];
        };

        std::uint8_t mBuffer[sizeof(UInt_t)*16];
        std::uint64_t mInputBytesTotalSize;
        unsigned mBufferIndex;
        HashData mHashData;

        void processBuffer(const std::uint8_t*);
    };

    template<typename UInt_t>
    UInt_t bigEndianBytesToUInt(const std::uint8_t*);

    void assignAsBigEndian(unsigned char*, std::uint32_t);
    void assignAsBigEndian(unsigned char*, std::uint64_t);
    constexpr std::uint32_t rotateRight(std::uint32_t, unsigned);
    constexpr std::uint64_t rotateRight(std::uint64_t, unsigned);
}

template<>
inline std::uint32_t WHash::bigEndianBytesToUInt<std::uint32_t>(const std::uint8_t* bytes)
{
    return ((static_cast<std::uint32_t>(bytes[0]) << (8*3)) |
            (static_cast<std::uint32_t>(bytes[1]) << (8*2)) |
            (static_cast<std::uint32_t>(bytes[2]) << 8) |
            static_cast<std::uint32_t>(bytes[3]));
}

template<>
inline std::uint64_t WHash::bigEndianBytesToUInt<std::uint64_t>(const std::uint8_t* bytes)
{
    return ((static_cast<std::uint64_t>(bytes[0]) << (8*7)) |
            (static_cast<std::uint64_t>(bytes[1]) << (8*6)) |
            (static_cast<std::uint64_t>(bytes[2]) << (8*5)) |
            (static_cast<std::uint64_t>(bytes[3]) << (8*4)) |
            (static_cast<std::uint64_t>(bytes[4]) << (8*3)) |
            (static_cast<std::uint64_t>(bytes[5]) << (8*2)) |
            (static_cast<std::uint64_t>(bytes[6]) << 8) |
            static_cast<std::uint64_t>(bytes[7]));
}

inline void WHash::assignAsBigEndian(unsigned char* dest, std::uint32_t value)
{
    dest[0] = static_cast<unsigned char>(value >> (8*3));
    dest[1] = static_cast<unsigned char>(value >> (8*2));
    dest[2] = static_cast<unsigned char>(value >> 8);
    dest[3] = static_cast<unsigned char>(value);
}

inline void WHash::assignAsBigEndian(unsigned char* dest, std::uint64_t value)
{
    dest[0] = static_cast<unsigned char>(value >> (8*7));
    dest[1] = static_cast<unsigned char>(value >> (8*6));
    dest[2] = static_cast<unsigned char>(value >> (8*5));
    dest[3] = static_cast<unsigned char>(value >> (8*4));
    dest[4] = static_cast<unsigned char>(value >> (8*3));
    dest[5] = static_cast<unsigned char>(value >> (8*2));
    dest[6] = static_cast<unsigned char>(value >> 8);
    dest[7] = static_cast<unsigned char>(value);
}

constexpr std::uint32_t WHash::rotateRight(std::uint32_t value, unsigned bits)
{
    return (value >> bits) | (value << (32-bits));
}

constexpr std::uint64_t WHash::rotateRight(std::uint64_t value, unsigned bits)
{
    return (value >> bits) | (value << (64-bits));
}

template<typename UInt_t, unsigned kRounds,
         unsigned kSigmaR1, unsigned kSigmaR2, unsigned kSigmaS1,
         unsigned kSigmaR3, unsigned kSigmaR4, unsigned kSigmaS2,
         unsigned kSumR1, unsigned kSumR2, unsigned kSumR3,
         unsigned kSumR4, unsigned kSumR5, unsigned kSumR6,
         UInt_t... kRoundConstants>
inline void
WHash::SHA2_base<UInt_t, kRounds,
                 kSigmaR1, kSigmaR2, kSigmaS1,
                 kSigmaR3, kSigmaR4, kSigmaS2,
                 kSumR1, kSumR2, kSumR3,
                 kSumR4, kSumR5, kSumR6, kRoundConstants...>::processBuffer
(const std::uint8_t* buffer)
{
    const UInt_t roundConstants[kRounds] = { kRoundConstants... };

    UInt_t w[kRounds];

    for(unsigned i = 0; i < 16; ++i)
        w[i] = WHash::bigEndianBytesToUInt<UInt_t>(buffer + i*sizeof(UInt_t));

    for(unsigned i = 16; i < kRounds; ++i)
    {
        const UInt_t w0 = w[i - 15], w1 = w[i - 2];
        const UInt_t s0 = rotateRight(w0, kSigmaR1) ^ rotateRight(w0, kSigmaR2) ^ (w0 >> kSigmaS1);
        const UInt_t s1 = rotateRight(w1, kSigmaR3) ^ rotateRight(w1, kSigmaR4) ^ (w1 >> kSigmaS2);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    UInt_t a = mHashData.h0;
    UInt_t b = mHashData.h1;
    UInt_t c = mHashData.h2;
    UInt_t d = mHashData.h3;
    UInt_t e = mHashData.h4;
    UInt_t f = mHashData.h5;
    UInt_t g = mHashData.h6;
    UInt_t h = mHashData.h7;

    for(unsigned i = 0; i < kRounds; ++i)
    {
        const UInt_t s1 = rotateRight(e, kSumR1) ^ rotateRight(e, kSumR2) ^ rotateRight(e, kSumR3);
        const UInt_t ch = (e & f) ^ (~e & g);
        const UInt_t temp1 = h + s1 + ch + roundConstants[i] + w[i];
        const UInt_t s0 = rotateRight(a, kSumR4) ^ rotateRight(a, kSumR5) ^ rotateRight(a, kSumR6);
        const UInt_t maj = (a & b) ^ (a & c) ^ (b & c);
        const UInt_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    mHashData.h0 += a;
    mHashData.h1 += b;
    mHashData.h2 += c;
    mHashData.h3 += d;
    mHashData.h4 += e;
    mHashData.h5 += f;
    mHashData.h6 += g;
    mHashData.h7 += h;
}

template<typename UInt_t, unsigned kRounds,
         unsigned kSigmaR1, unsigned kSigmaR2, unsigned kSigmaS1,
         unsigned kSigmaR3, unsigned kSigmaR4, unsigned kSigmaS2,
         unsigned kSumR1, unsigned kSumR2, unsigned kSumR3,
         unsigned kSumR4, unsigned kSumR5, unsigned kSumR6,
         UInt_t... kRoundConstants>
inline void
WHash::SHA2_base<UInt_t, kRounds,
                 kSigmaR1, kSigmaR2, kSigmaS1,
                 kSigmaR3, kSigmaR4, kSigmaS2,
                 kSumR1, kSumR2, kSumR3,
                 kSumR4, kSumR5, kSumR6, kRoundConstants...>::update
(const void* inputBytes, std::size_t inputBytesSize)
{
    const unsigned kBufferSize = sizeof(UInt_t)*16;

    mInputBytesTotalSize += static_cast<std::uint64_t>(inputBytesSize);

    if(mBufferIndex + inputBytesSize < kBufferSize)
    {
        std::memcpy(mBuffer + mBufferIndex, inputBytes, inputBytesSize);
        mBufferIndex += static_cast<unsigned>(inputBytesSize);
    }
    else
    {
        const unsigned char* inputData = static_cast<const unsigned char*>(inputBytes);

        if(mBufferIndex > 0)
        {
            const unsigned bytesToCopy = kBufferSize - mBufferIndex;
            std::memcpy(mBuffer + mBufferIndex, inputData, bytesToCopy);
            mBufferIndex = 0;
            inputData += bytesToCopy;
            inputBytesSize -= bytesToCopy;
            processBuffer(mBuffer);
        }

        while(inputBytesSize >= kBufferSize)
        {
            processBuffer(inputData);
            inputData += kBufferSize;
            inputBytesSize -= kBufferSize;
        }

        if(inputBytesSize > 0)
        {
            std::memcpy(mBuffer, inputData, inputBytesSize);
            mBufferIndex = static_cast<unsigned>(inputBytesSize);
        }
    }
}

template<typename UInt_t, unsigned kRounds,
         unsigned kSigmaR1, unsigned kSigmaR2, unsigned kSigmaS1,
         unsigned kSigmaR3, unsigned kSigmaR4, unsigned kSigmaS2,
         unsigned kSumR1, unsigned kSumR2, unsigned kSumR3,
         unsigned kSumR4, unsigned kSumR5, unsigned kSumR6,
         UInt_t... kRoundConstants>
inline const unsigned char*
WHash::SHA2_base<UInt_t, kRounds,
                 kSigmaR1, kSigmaR2, kSigmaS1,
                 kSigmaR3, kSigmaR4, kSigmaS2,
                 kSumR1, kSumR2, kSumR3,
                 kSumR4, kSumR5, kSumR6, kRoundConstants...>::finish()
{
    const unsigned kWordSize = sizeof(UInt_t);
    const unsigned kBufferSize = kWordSize * 16;
    const unsigned kLengthSize = kWordSize * 2;
    const std::uint64_t inputTotalBits = mInputBytesTotalSize * 8;

    unsigned char appendData[kBufferSize + kLengthSize] = { 0x80 };
    unsigned appendDataSize = kBufferSize - mBufferIndex;
    if(appendDataSize < kLengthSize + 1) appendDataSize += kBufferSize;

    unsigned char* dataSizeDest = appendData + (appendDataSize - 8);
    dataSizeDest[0] = static_cast<unsigned char>(inputTotalBits >> (8*7));
    dataSizeDest[1] = static_cast<unsigned char>(inputTotalBits >> (8*6));
    dataSizeDest[2] = static_cast<unsigned char>(inputTotalBits >> (8*5));
    dataSizeDest[3] = static_cast<unsigned char>(inputTotalBits >> (8*4));
    dataSizeDest[4] = static_cast<unsigned char>(inputTotalBits >> (8*3));
    dataSizeDest[5] = static_cast<unsigned char>(inputTotalBits >> (8*2));
    dataSizeDest[6] = static_cast<unsigned char>(inputTotalBits >> 8);
    dataSizeDest[7] = static_cast<unsigned char>(inputTotalBits);

    update(appendData, appendDataSize);

    assignAsBigEndian(mHashData.hash, mHashData.h0);
    assignAsBigEndian(mHashData.hash + kWordSize, mHashData.h1);
    assignAsBigEndian(mHashData.hash + kWordSize*2, mHashData.h2);
    assignAsBigEndian(mHashData.hash + kWordSize*3, mHashData.h3);
    assignAsBigEndian(mHashData.hash + kWordSize*4, mHashData.h4);
    assignAsBigEndian(mHashData.hash + kWordSize*5, mHashData.h5);
    assignAsBigEndian(mHashData.hash + kWordSize*6, mHashData.h6);
    assignAsBigEndian(mHashData.hash + kWordSize*7, mHashData.h7);

    return mHashData.hash;
}
#endif
