#include "../WHash_md5.hh"
#include <cstdio>
#include <array>
#include <memory>

using MD5Sum = std::array<unsigned char, 16>;

static std::unique_ptr<unsigned char[]> gDataBuffer;
static std::size_t gDataBufferSize = 0;

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
    if(gDataBufferSize < chunkSize) gDataBuffer = std::make_unique<unsigned char[]>(chunkSize);

    WHash::MD5 md5Calculator;

    for(std::size_t chunkIndex = 0; chunkIndex < totalDataAmount; chunkIndex += chunkSize)
    {
        const std::size_t dataAmount = (chunkIndex + chunkSize > totalDataAmount ?
                                        totalDataAmount - chunkIndex : chunkSize);

        for(std::size_t i = 0; i < dataAmount; ++i)
            gDataBuffer[i] = dataGeneratorFunc();

        md5Calculator.update(gDataBuffer.get(), dataAmount);
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

struct LCG
{
    std::uint32_t mSeed = 0;
    unsigned mCounter = 0;

    void setSeed(std::uint32_t seed)
    {
        mSeed = seed;
        mCounter = 0;
    }

    unsigned char getNext()
    {
        if(mCounter == 4)
        {
            mSeed = mSeed * UINT32_C(3363461597) + UINT32_C(8346591);
            mCounter = 0;
        }
        return (mSeed >> (8*mCounter++));
    }
};

LCG gLCG;

unsigned char getRandomByte() { return gLCG.getNext(); }

#define ERR_RET return std::printf("%u: Check failed\n", __LINE__), 1

int main()
{
    if(!testMD5(0, 0, nullptr, "d41d8cd98f00b204e9800998ecf8427e"_md5sum)) ERR_RET;

    const struct
    {
        unsigned dataLength;
        MD5Sum md5Sum;
    }
    testData[] =
    {
        { 1, "93b885adfe0da089cdf634904fd59f71"_md5sum },
        { 2, "25daad3d9e60b45043a70c4ab7d3b1c6"_md5sum },
        { 3, "37dc50d0203ca1ba9548ad9a28769fd2"_md5sum },
        { 4, "edcfae989540fd42e4b8556d5b723bb6"_md5sum },
        { 5, "7063788c14149c075216244621ba59fb"_md5sum },
        { 6, "45457beedb40f5da27f351c163422485"_md5sum },
        { 7, "59bdb5183f45978b2c69914cbf123e0c"_md5sum },
        { 8, "389afd2b85e71d556374c8a813728106"_md5sum },
        { 9, "006b54d6e7129d3d3d48cfecc8b13a20"_md5sum },
        { 10, "51d74b729f9e4675c0331ce5622ef4c2"_md5sum },
        { 60, "fd8c95a4016b977af7b388d442277b7d"_md5sum },
        { 61, "e1a169458335fd0e2a9054d77d604fe9"_md5sum },
        { 62, "3b568d0a5e7ca9035282e2c4af2a1271"_md5sum },
        { 63, "c0a1906709da0c89175faa6bf317ada6"_md5sum },
        { 64, "29da72b40626d871bb7ff2212ad9ba90"_md5sum },
        { 65, "8e27c6e0d7de85d0e64d687c0fb61e40"_md5sum },
        { 66, "43ddd6c8eae1f10889d883c07d5333f8"_md5sum },
        { 67, "09597dedc35334cbf38026a3069ef1b1"_md5sum },
        { 68, "e59f1295a0315d5da62d1798cc576cd1"_md5sum },
        { 126, "1cd5a32d7c87a55eb889b09a4fde32f3"_md5sum },
        { 127, "0ae3251f9eecac5ca7fb13b7deaa98b1"_md5sum },
        { 128, "e4af8f9ef323db764a10cbafb6be990a"_md5sum },
        { 129, "d9443e8cfe112b175cd9163b7603a64d"_md5sum },
        { 130, "aacf9d20ec4a48f988888324d8d37f7c"_md5sum },
        { 1000, "f6813c8e7c068534b1d61638df58057e"_md5sum },
        { 20000, "f82cdc7f6acd765599439e625a1e7c58"_md5sum },
        { 300000, "9d1f1df3aab3759a8a9bd67ed79844c9"_md5sum },
        { 4000000, "28f136d2dc1ff347d0326c98f407e5a6"_md5sum },
        { 50000000, "ba15fbeebd514b6d29335e9c8200b0e7"_md5sum }
    };

    const std::size_t kChunkSizes[] =
    {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 21, 22, 23, 24, 25, 26, 30, 31, 32, 33, 34, 35,
        62, 63, 64, 65, 66, 254, 255, 256, 257, 2000, 4095, 4096, 4097, 28000, 350000
    };

    const unsigned kTestDataAmount = sizeof(testData)/sizeof(*testData);
    for(unsigned dataIndex = 0; dataIndex < kTestDataAmount; ++dataIndex)
    {
        for(unsigned chunkSizeIndex = 0;
            chunkSizeIndex < sizeof(kChunkSizes)/sizeof(std::size_t);
            ++chunkSizeIndex)
        {
            gLCG.setSeed(dataIndex);

            if(!testMD5(testData[dataIndex].dataLength, kChunkSizes[chunkSizeIndex],
                        getRandomByte, testData[dataIndex].md5Sum))
            {
                std::printf("%u: Test failed with dataIndex:%u, chunkSizeIndex:%u\n", __LINE__,
                            dataIndex, chunkSizeIndex);
                return 1;
            }

            if(kChunkSizes[chunkSizeIndex] >= testData[dataIndex].dataLength)
                break;
        }
    }

    std::printf("Tests ok.\n");
}
