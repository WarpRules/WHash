#include "../WHash_md5.hh"
#include <cstdio>
#include <array>
#include <vector>

using MD5Sum = std::array<unsigned char, 16>;

static std::vector<unsigned char> gDataBuffer;

static bool compare(const MD5Sum& expected, const unsigned char* calculated)
{
    for(unsigned i = 0; i < 16; ++i)
        if(expected[i] != calculated[i])
            return false;
    return true;
}

static bool testMD5(std::size_t totalDataAmount, std::size_t chunkSize,
                    unsigned char (*dataGeneratorFunc)(),
                    const MD5Sum& expectedSum)
{
    if(gDataBuffer.size() < chunkSize) gDataBuffer.resize(chunkSize);

    WHash::MD5 md5Calculator;

    for(std::size_t chunkIndex = 0; chunkIndex < totalDataAmount; chunkIndex += chunkSize)
    {
        const std::size_t dataAmount = (chunkIndex + chunkSize > totalDataAmount ?
                                        totalDataAmount - chunkIndex : chunkSize);

        for(std::size_t i = 0; i < dataAmount; ++i)
            gDataBuffer[i] = dataGeneratorFunc();

        md5Calculator.update(&gDataBuffer[0], dataAmount);
    }

    const unsigned char* md5Sum = md5Calculator.finish();
    return compare(expectedSum, md5Sum);
}

constexpr unsigned char asciiToNibble(char c)
{
    return (c >= '0' && c <= '9' ? c - '0' :
            c >= 'A' && c <= 'F' ? c - 'A' + 10 :
            c >= 'a' && c <= 'f' ? c - 'a' + 10 : 0);
}

constexpr unsigned char asciiToByte(char c1, char c2)
{
    return (asciiToNibble(c1) << 4) | asciiToNibble(c2);
}

MD5Sum operator"" _md5sum(const char* hexStr, std::size_t len)
{
    MD5Sum sum;
    for(std::size_t i = 0; i < 32 && i < len; i += 2)
        sum[i/2] = asciiToByte(hexStr[i], hexStr[i+1]);
    return sum;
}

#define ERR_RET return std::printf("%u: Check failed\n", __LINE__), 1

int main()
{
    if(!testMD5(0, 0, nullptr, "d41d8cd98f00b204e9800998ecf8427e"_md5sum)) ERR_RET;
}
