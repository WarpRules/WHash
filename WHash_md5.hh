#ifndef WHASH_MD5_HH__
#define WHASH_MD5_HH__

#include <cstring>
#include <cstdint>

#define WHASH_MD5_VERSION 0x010000
#define WHASH_MD5_VERSION_STRING "1.0.0"
#define WHASH_MD5_COPYRIGHT_STRING "WHash MD5 v" WHASH_MD5_VERSION_STRING " (C)2020 Juha Nieminen"

namespace WHash { class MD5; }

class WHash::MD5
{
 public:
    static const unsigned kDigestBytes = 16;

    void initialize();
    void update(const void* inputBytes, std::size_t inputBytesSize);
    const unsigned char* finish();
    const unsigned char* currentHash() const { return mHash; }


 private:
    struct CTXdata
    {
        std::uint32_t lo = 0, hi = 0;
        std::uint32_t a = UINT32_C(0x67452301), b = UINT32_C(0xefcdab89);
        std::uint32_t c = UINT32_C(0x98badcfe), d = UINT32_C(0x10325476);
        unsigned char buffer[64];
        std::uint32_t block[16];
    } mCTXdata;

    unsigned char mHash[16];

    static inline std::uint32_t F(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (z ^ (x & (y ^ z))); }
    static inline std::uint32_t G(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (y ^ (z & (x ^ y))); }
    static inline std::uint32_t H(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return ((x ^ y) ^ z); }
    static inline std::uint32_t H2(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x ^ (y ^ z)); }
    static inline std::uint32_t I(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (y ^ (x | ~z)); }

    template<std::uint32_t(*func)(std::uint32_t, std::uint32_t, std::uint32_t)>
    void step(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d,
              std::uint32_t x, std::uint32_t t, std::uint32_t s);
    std::uint32_t setBlockValue(const unsigned char*, unsigned);
    const void* body(const void*, std::size_t);
};


template<std::uint32_t(*func)(std::uint32_t, std::uint32_t, std::uint32_t)>
inline void WHash::MD5::step(std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d,
                             std::uint32_t x, std::uint32_t t, std::uint32_t s)
{
    a += func(b, c, d) + x + t;
    a = ((a << s) | (a >> (32 - s)));
    a += b;
}

inline std::uint32_t WHash::MD5::setBlockValue(const unsigned char* ptr, unsigned n)
{
    return mCTXdata.block[n] = ((std::uint32_t)ptr[n * 4] |
                                ((std::uint32_t)ptr[n * 4 + 1] << 8) |
                                ((std::uint32_t)ptr[n * 4 + 2] << 16) |
                                ((std::uint32_t)ptr[n * 4 + 3] << 24));
}

inline const void* WHash::MD5::body(const void* data, std::size_t size)
{
    const unsigned char *ptr = (const unsigned char *)data;
    std::uint32_t a = mCTXdata.a, b = mCTXdata.b, c = mCTXdata.c, d = mCTXdata.d;

    do
    {
        const std::uint32_t saved_a = a, saved_b = b, saved_c = c, saved_d = d;

        step<F>(a, b, c, d, setBlockValue(ptr, 0), UINT32_C(0xd76aa478), 7);
        step<F>(d, a, b, c, setBlockValue(ptr, 1), UINT32_C(0xe8c7b756), 12);
        step<F>(c, d, a, b, setBlockValue(ptr, 2), UINT32_C(0x242070db), 17);
        step<F>(b, c, d, a, setBlockValue(ptr, 3), UINT32_C(0xc1bdceee), 22);
        step<F>(a, b, c, d, setBlockValue(ptr, 4), UINT32_C(0xf57c0faf), 7);
        step<F>(d, a, b, c, setBlockValue(ptr, 5), UINT32_C(0x4787c62a), 12);
        step<F>(c, d, a, b, setBlockValue(ptr, 6), UINT32_C(0xa8304613), 17);
        step<F>(b, c, d, a, setBlockValue(ptr, 7), UINT32_C(0xfd469501), 22);
        step<F>(a, b, c, d, setBlockValue(ptr, 8), UINT32_C(0x698098d8), 7);
        step<F>(d, a, b, c, setBlockValue(ptr, 9), UINT32_C(0x8b44f7af), 12);
        step<F>(c, d, a, b, setBlockValue(ptr, 10), UINT32_C(0xffff5bb1), 17);
        step<F>(b, c, d, a, setBlockValue(ptr, 11), UINT32_C(0x895cd7be), 22);
        step<F>(a, b, c, d, setBlockValue(ptr, 12), UINT32_C(0x6b901122), 7);
        step<F>(d, a, b, c, setBlockValue(ptr, 13), UINT32_C(0xfd987193), 12);
        step<F>(c, d, a, b, setBlockValue(ptr, 14), UINT32_C(0xa679438e), 17);
        step<F>(b, c, d, a, setBlockValue(ptr, 15), UINT32_C(0x49b40821), 22);

        step<G>(a, b, c, d, mCTXdata.block[1], UINT32_C(0xf61e2562), 5);
        step<G>(d, a, b, c, mCTXdata.block[6], UINT32_C(0xc040b340), 9);
        step<G>(c, d, a, b, mCTXdata.block[11], UINT32_C(0x265e5a51), 14);
        step<G>(b, c, d, a, mCTXdata.block[0], UINT32_C(0xe9b6c7aa), 20);
        step<G>(a, b, c, d, mCTXdata.block[5], UINT32_C(0xd62f105d), 5);
        step<G>(d, a, b, c, mCTXdata.block[10], UINT32_C(0x02441453), 9);
        step<G>(c, d, a, b, mCTXdata.block[15], UINT32_C(0xd8a1e681), 14);
        step<G>(b, c, d, a, mCTXdata.block[4], UINT32_C(0xe7d3fbc8), 20);
        step<G>(a, b, c, d, mCTXdata.block[9], UINT32_C(0x21e1cde6), 5);
        step<G>(d, a, b, c, mCTXdata.block[14], UINT32_C(0xc33707d6), 9);
        step<G>(c, d, a, b, mCTXdata.block[3], UINT32_C(0xf4d50d87), 14);
        step<G>(b, c, d, a, mCTXdata.block[8], UINT32_C(0x455a14ed), 20);
        step<G>(a, b, c, d, mCTXdata.block[13], UINT32_C(0xa9e3e905), 5);
        step<G>(d, a, b, c, mCTXdata.block[2], UINT32_C(0xfcefa3f8), 9);
        step<G>(c, d, a, b, mCTXdata.block[7], UINT32_C(0x676f02d9), 14);
        step<G>(b, c, d, a, mCTXdata.block[12], UINT32_C(0x8d2a4c8a), 20);

        step<H>(a, b, c, d, mCTXdata.block[5], UINT32_C(0xfffa3942), 4);
        step<H2>(d, a, b, c, mCTXdata.block[8], UINT32_C(0x8771f681), 11);
        step<H>(c, d, a, b, mCTXdata.block[11], UINT32_C(0x6d9d6122), 16);
        step<H2>(b, c, d, a, mCTXdata.block[14], UINT32_C(0xfde5380c), 23);
        step<H>(a, b, c, d, mCTXdata.block[1], UINT32_C(0xa4beea44), 4);
        step<H2>(d, a, b, c, mCTXdata.block[4], UINT32_C(0x4bdecfa9), 11);
        step<H>(c, d, a, b, mCTXdata.block[7], UINT32_C(0xf6bb4b60), 16);
        step<H2>(b, c, d, a, mCTXdata.block[10], UINT32_C(0xbebfbc70), 23);
        step<H>(a, b, c, d, mCTXdata.block[13], UINT32_C(0x289b7ec6), 4);
        step<H2>(d, a, b, c, mCTXdata.block[0], UINT32_C(0xeaa127fa), 11);
        step<H>(c, d, a, b, mCTXdata.block[3], UINT32_C(0xd4ef3085), 16);
        step<H2>(b, c, d, a, mCTXdata.block[6], UINT32_C(0x04881d05), 23);
        step<H>(a, b, c, d, mCTXdata.block[9], UINT32_C(0xd9d4d039), 4);
        step<H2>(d, a, b, c, mCTXdata.block[12], UINT32_C(0xe6db99e5), 11);
        step<H>(c, d, a, b, mCTXdata.block[15], UINT32_C(0x1fa27cf8), 16);
        step<H2>(b, c, d, a, mCTXdata.block[2], UINT32_C(0xc4ac5665), 23);

        step<I>(a, b, c, d, mCTXdata.block[0], UINT32_C(0xf4292244), 6);
        step<I>(d, a, b, c, mCTXdata.block[7], UINT32_C(0x432aff97), 10);
        step<I>(c, d, a, b, mCTXdata.block[14], UINT32_C(0xab9423a7), 15);
        step<I>(b, c, d, a, mCTXdata.block[5], UINT32_C(0xfc93a039), 21);
        step<I>(a, b, c, d, mCTXdata.block[12], UINT32_C(0x655b59c3), 6);
        step<I>(d, a, b, c, mCTXdata.block[3], UINT32_C(0x8f0ccc92), 10);
        step<I>(c, d, a, b, mCTXdata.block[10], UINT32_C(0xffeff47d), 15);
        step<I>(b, c, d, a, mCTXdata.block[1], UINT32_C(0x85845dd1), 21);
        step<I>(a, b, c, d, mCTXdata.block[8], UINT32_C(0x6fa87e4f), 6);
        step<I>(d, a, b, c, mCTXdata.block[15], UINT32_C(0xfe2ce6e0), 10);
        step<I>(c, d, a, b, mCTXdata.block[6], UINT32_C(0xa3014314), 15);
        step<I>(b, c, d, a, mCTXdata.block[13], UINT32_C(0x4e0811a1), 21);
        step<I>(a, b, c, d, mCTXdata.block[4], UINT32_C(0xf7537e82), 6);
        step<I>(d, a, b, c, mCTXdata.block[11], UINT32_C(0xbd3af235), 10);
        step<I>(c, d, a, b, mCTXdata.block[2], UINT32_C(0x2ad7d2bb), 15);
        step<I>(b, c, d, a, mCTXdata.block[9], UINT32_C(0xeb86d391), 21);

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ptr += 64;
    } while (size -= 64);

    mCTXdata.a = a;
    mCTXdata.b = b;
    mCTXdata.c = c;
    mCTXdata.d = d;

    return ptr;
}

inline void WHash::MD5::initialize()
{
    mCTXdata = CTXdata();
}

inline void WHash::MD5::update(const void* inputBytes, std::size_t inputBytesSize)
{
    const std::uint32_t saved_lo = mCTXdata.lo;
    if((mCTXdata.lo = (saved_lo + inputBytesSize) & UINT32_C(0x1fffffff)) < saved_lo)
        mCTXdata.hi++;
    mCTXdata.hi += inputBytesSize >> 29;

    const unsigned used = saved_lo & UINT32_C(0x3f);

    if(used)
    {
        unsigned available = 64 - used;

        if (inputBytesSize < available)
        {
            std::memcpy(&mCTXdata.buffer[used], inputBytes, inputBytesSize);
            return;
        }

        std::memcpy(&mCTXdata.buffer[used], inputBytes, available);
        inputBytes = static_cast<const unsigned char*>(inputBytes) + available;
        inputBytesSize -= available;
        body(mCTXdata.buffer, 64);
    }

    if(inputBytesSize >= 64)
    {
        inputBytes = body(inputBytes, inputBytesSize & ~std::size_t(0x3f));
        inputBytesSize &= UINT32_C(0x3f);
    }

    std::memcpy(mCTXdata.buffer, inputBytes, inputBytesSize);
}

inline const unsigned char* WHash::MD5::finish()
{
    unsigned used = mCTXdata.lo & 0x3f;

    mCTXdata.buffer[used++] = 0x80;

    unsigned available = 64 - used;

    if(available < 8)
    {
        std::memset(&mCTXdata.buffer[used], 0, available);
        body(mCTXdata.buffer, 64);
        used = 0;
        available = 64;
    }

    std::memset(&mCTXdata.buffer[used], 0, available - 8);

    mCTXdata.lo <<= 3;
    mCTXdata.buffer[56] = mCTXdata.lo;
    mCTXdata.buffer[57] = mCTXdata.lo >> 8;
    mCTXdata.buffer[58] = mCTXdata.lo >> 16;
    mCTXdata.buffer[59] = mCTXdata.lo >> 24;
    mCTXdata.buffer[60] = mCTXdata.hi;
    mCTXdata.buffer[61] = mCTXdata.hi >> 8;
    mCTXdata.buffer[62] = mCTXdata.hi >> 16;
    mCTXdata.buffer[63] = mCTXdata.hi >> 24;

    body(mCTXdata.buffer, 64);

    mHash[0] = mCTXdata.a;
    mHash[1] = mCTXdata.a >> 8;
    mHash[2] = mCTXdata.a >> 16;
    mHash[3] = mCTXdata.a >> 24;
    mHash[4] = mCTXdata.b;
    mHash[5] = mCTXdata.b >> 8;
    mHash[6] = mCTXdata.b >> 16;
    mHash[7] = mCTXdata.b >> 24;
    mHash[8] = mCTXdata.c;
    mHash[9] = mCTXdata.c >> 8;
    mHash[10] = mCTXdata.c >> 16;
    mHash[11] = mCTXdata.c >> 24;
    mHash[12] = mCTXdata.d;
    mHash[13] = mCTXdata.d >> 8;
    mHash[14] = mCTXdata.d >> 16;
    mHash[15] = mCTXdata.d >> 24;

    return mHash;
}

#endif
