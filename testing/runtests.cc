#define GENERATE_HASHES 0

#include "../WHash_md5.hh"
#include "../WHash_sha1.hh"
#include <cstdio>
#include <cstdint>
#include <array>
#include <memory>

static std::unique_ptr<unsigned char[]> gDataBuffer;
static std::size_t gDataBufferSize = 0;

template<std::size_t kHashSize>
static bool compare(const std::array<unsigned char, kHashSize>& expected,
                    const unsigned char* calculated)
{
    for(unsigned i = 0; i < kHashSize; ++i)
        if(expected[i] != calculated[i])
            return false;
    return true;
}

template<typename HashCalculator_t, std::size_t kHashSize>
static bool testHash(HashCalculator_t& hashCalculator,
                     std::size_t totalDataAmount, std::size_t chunkSize,
                     unsigned char (*dataGeneratorFunc)(),
                     const std::array<unsigned char, kHashSize>& expectedHash)
{
    if(gDataBufferSize < chunkSize)
    {
        gDataBuffer = std::make_unique<unsigned char[]>(chunkSize);
        gDataBufferSize = chunkSize;
    }

    for(std::size_t chunkIndex = 0; chunkIndex < totalDataAmount; chunkIndex += chunkSize)
    {
        const std::size_t dataAmount = (chunkIndex + chunkSize > totalDataAmount ?
                                        totalDataAmount - chunkIndex : chunkSize);

        for(std::size_t i = 0; i < dataAmount; ++i)
            gDataBuffer[i] = dataGeneratorFunc();

        hashCalculator.update(gDataBuffer.get(), dataAmount);
    }

    const unsigned char* hash = hashCalculator.finish();
    return compare(expectedHash, hash);
}

using MD5Hash = std::array<unsigned char, 16>;
using SHA1Hash = std::array<unsigned char, 20>;

constexpr unsigned char asciiToNibble(char c)
{
    return (c >= '0' && c <= '9' ? c - '0' :
            c >= 'A' && c <= 'F' ? c - 'A' + 10 :
            c >= 'a' && c <= 'f' ? c - 'a' + 10 : 0);
}

constexpr char nibbleToAscii(unsigned char n)
{
    return n < 10 ? '0' + n : ('a' - 10) + n;
}

constexpr unsigned char asciiToByte(char c1, char c2)
{
    return (asciiToNibble(c1) << 4) | asciiToNibble(c2);
}

template<std::size_t kSize>
std::array<unsigned char, kSize> hexStrToByteArray(const char* hexStr, std::size_t len)
{
    std::array<unsigned char, kSize> bytes;
    for(std::size_t i = 0; i < kSize*2 && i < len; i += 2)
        bytes[i/2] = asciiToByte(hexStr[i], hexStr[i+1]);
    return bytes;
}

MD5Hash operator"" _md5hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<16>(hexStr, len); }

SHA1Hash operator"" _sha1hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<20>(hexStr, len); }

struct LCG
{
    std::uint32_t mSeed = 0;
    unsigned mCounter = 0;

    void setSeed(std::uint32_t seed)
    {
        mSeed = seed * UINT32_C(3363461597) + UINT32_C(8346591);
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

#if GENERATE_HASHES
static void printFirstWord(const char* str)
{
    const char* strEnd = str;
    while(*strEnd && *strEnd != ' ') ++strEnd;
    std::fwrite(str, 1, strEnd - str, stdout);
}
#endif

[[maybe_unused]]
static void printInHex(const unsigned char* data, std::size_t size)
{
    for(std::size_t i = 0; i < size; ++i)
        std::printf("%c%c", nibbleToAscii(data[i] >> 4), nibbleToAscii(data[i] & 0xF));
}

template<std::size_t kSize>
int printErrorMsg(const char* hashName, unsigned dataIndex, unsigned chunkSizeIndex,
                  const std::array<unsigned char, kSize>& expected,
                  const unsigned char* calculated)
{
    std::printf("%s test failed with dataIndex:%u, chunkSizeIndex:%u\n", hashName, dataIndex, chunkSizeIndex);
    std::printf("Expected: ");
    printInHex(expected.data(), kSize);
    std::printf("\n     Got: ");
    printInHex(calculated, kSize);
    std::printf("\n");
    return 1;
}

int main()
{
    const unsigned kDataLengths[] =
    {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 53, 54, 55, 56, 62, 63, 64, 65, 66,
        117, 118, 119, 120, 126, 127, 128, 129, 130, 923, 924, 925, 1022, 1023, 1024, 1025,
        20000, 300000, 4000000, 5000000
    };

    const unsigned kTestDataAmount = sizeof(kDataLengths)/sizeof(*kDataLengths);

#if GENERATE_HASHES
    char outputBuffer1[80], outputBuffer2[80];

    for(unsigned dataIndex = 0; dataIndex < kTestDataAmount; ++dataIndex)
    {
        gLCG.setSeed(dataIndex);
        std::FILE* oFile = std::fopen("testsdata.dat", "wb");

        const unsigned dataLength = kDataLengths[dataIndex];
        for(unsigned i = 0; i < dataLength; ++i)
            std::fputc(gLCG.getNext(), oFile);

        std::fclose(oFile);

        std::FILE* iStream = popen("md5sum testsdata.dat", "r");
        std::fgets(outputBuffer1, 80, iStream);
        pclose(iStream);

        iStream = popen("sha1sum testsdata.dat", "r");
        std::fgets(outputBuffer2, 80, iStream);
        pclose(iStream);

        std::printf("        { \"");
        printFirstWord(outputBuffer1);
        std::printf("\"_md5hash, \"");
        printFirstWord(outputBuffer2);
        std::printf("\"_sha1hash },\n");
    }

    std::remove("testsdata.dat");
#else
    const struct
    {
        MD5Hash md5hash;
        SHA1Hash sha1hash;
    }
    kHashes[] =
    {
        { "d41d8cd98f00b204e9800998ecf8427e"_md5hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709"_sha1hash },
        { "4dcde376fbc212f73c0b00b7909fc4cf"_md5hash, "08dbbf42caba6501b69b1cea7a9b84e358e66ddb"_sha1hash },
        { "559bf01ee292366c1fca4a2bfb2b17b6"_md5hash, "9721e02a6a23830ac58283a26581ab9e3cee6551"_sha1hash },
        { "4828d3b519fe50d5908893bfd24b1972"_md5hash, "ec2b762b8452afcfcbd9867d226de0f1d8856ab7"_sha1hash },
        { "c7b645c4cd931258f050db14df4f2353"_md5hash, "9ba196ff91399a9a2010a72cff238d5c246ab1ee"_sha1hash },
        { "8fbe428bfc4e4a09209725d295958a97"_md5hash, "4d1d3917d290305de10c7e9a6a4a0475aeaa9fd6"_sha1hash },
        { "98f21512ce635362c3f34728a49799a4"_md5hash, "6358df85fb8b69f066729a73eb1ed3021050c7da"_sha1hash },
        { "d199b6456a0aa5e798283cde0c807765"_md5hash, "074a16536d9bec56e2cc6341e649e9a3faa5ac8c"_sha1hash },
        { "52dd7e5ab4b40408b7c1e6ecb084f8bd"_md5hash, "c3c1b1110adb7c7fd83d4f508e6f44bbe6638339"_sha1hash },
        { "e2a71510a93eac869fa17ae4e831bae8"_md5hash, "524f2b743ff8d07395ac5e5d384f35be82bdec43"_sha1hash },
        { "ac424dafa379ba8ca7cdef3ba7c13895"_md5hash, "79d730378eaccec325d0c3afeb5c9a62c22db047"_sha1hash },
        { "1226bc97fba5fcc76b14c9318dea7bc3"_md5hash, "593881b29e151c1968083b123d4c6d7220b7d9d9"_sha1hash },
        { "aaf7935eada1868795125693df975585"_md5hash, "6d15e824adf9dbfa227a22a066035d45c7db1a62"_sha1hash },
        { "e200de49c1ea4d5ba15525f3d8d996a7"_md5hash, "945d4333545720c470c3c616165d8e8435510ca2"_sha1hash },
        { "c442d86851ccbd4eee78cf05e09093cd"_md5hash, "401c06774dfed956435d687ef65971e941944217"_sha1hash },
        { "5d65303d5609d6588a3cc9cf38187408"_md5hash, "80a8c16124c15b8e3a88c73e9d2de1a65606fe1a"_sha1hash },
        { "cfae4b94aec0755c38d8ca8afcd87ce2"_md5hash, "f5143fc32b558f45d0ab490a51c6d49a828a478a"_sha1hash },
        { "d27bb22bbeaf92bc0e188a0109f912ad"_md5hash, "8fb853604ab5be17c1609c80b39a356376dabd18"_sha1hash },
        { "4d778b35ad841642a654ecd35dced827"_md5hash, "f2ea3d79263c1d2629b756ec5e84035227ecbaad"_sha1hash },
        { "75517656a73fcb4d9768e68af03aec59"_md5hash, "63dc03c6400ee63377bd02adf3f0f078548a3595"_sha1hash },
        { "203e7732728ab2ad086aa50a739fd82a"_md5hash, "cae167281aa1b1fd3ac7d60f82ee26f7633d5a95"_sha1hash },
        { "a2758bbea3f3c059a1850f71183149ec"_md5hash, "11b1b5fc585babc230d610b2ef6280b5901159d9"_sha1hash },
        { "937eec3072ed7343acd44d9c281cd2d7"_md5hash, "4d1b997a2d8c36561cce21a3dd27ec273fddf29b"_sha1hash },
        { "b5f60307b7898e4372c838a379f42733"_md5hash, "0d66982b0c81ebe0d0263d81391ebe8e9cf2b7d7"_sha1hash },
        { "3b11aee4f7272cebadbdd9c58aacae39"_md5hash, "7017b30060cc52213b80ad8948fd9c9a208356d1"_sha1hash },
        { "0a38fa543233640eebbfcf5d535812de"_md5hash, "8b7db445e6e39dd4f7147b23c8bbed6914b79354"_sha1hash },
        { "ca36a1163dade565cc017587589a4970"_md5hash, "a5d6f7e3bc753b5d1a9831e6206d095acffcb3ed"_sha1hash },
        { "2b7d7dc535b33b28b244e093bb9c0866"_md5hash, "fc1dbe30c36d1192b420f5a8303d14e8a5a04498"_sha1hash },
        { "e91edefa3d755fdadbde18705ad07b87"_md5hash, "0c17ab0ecc5d097c6c325f7608794d46ff64133f"_sha1hash },
        { "976934a50bccb627855bd9739194bf55"_md5hash, "6da53b45b430ded24cd5c0200c6d4aad9b0317d1"_sha1hash },
        { "1c3afcedc386f1149a1862cad16c8982"_md5hash, "f44f8e3caca876f2d434ba3860213a02a4c5044f"_sha1hash },
        { "569e1d7e974437beccc26605572ef43c"_md5hash, "3bc775351b8bb3cc0324a7f55c096decf8d06501"_sha1hash },
        { "3395cef3c8944b192a39de1c9b88285a"_md5hash, "9d1184ffea53fb49135bcdabcbbe0ca8928d2d4e"_sha1hash },
        { "a2a5904baec7762004e0b72f9a2fdfbf"_md5hash, "d99c724e1d197305ae15c9d09599ffd1a9d015f6"_sha1hash },
        { "3c15c0a45fa0ffc40657f7eed58d62cb"_md5hash, "dc196883e3d2e34ee9d11010f3d2424b822fa2c9"_sha1hash },
        { "0ae75fbe754bcc55d1c5b34d9da4aee2"_md5hash, "4048757bac0cd14e68ca495aa11c17d81d958892"_sha1hash },
        { "c76d791ddb256ba72cecc47d57415517"_md5hash, "baa1ca69a90f0095f9450298315040f1650abeb6"_sha1hash },
        { "023c3b711903e56bf823d64bb994aedc"_md5hash, "f158083117a2101498ad777506bd4acf589c77c3"_sha1hash },
        { "939dbdabe253ef36a91191514fa1e035"_md5hash, "3640a63ec0a4d5ec83b7cba3bda77b8239522731"_sha1hash },
        { "4519692f6c47f6465336c54c29a6801c"_md5hash, "8345ec118b4677f6e502cb13b6876c9ca1efcee7"_sha1hash },
    };

    const std::size_t kChunkSizes[] =
    {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 21, 22, 23, 24, 25, 26, 30, 31, 32, 33, 34, 35,
        62, 63, 64, 65, 66, 254, 255, 256, 257, 2000, 4095, 4096, 4097, 28000, 350000
    };

    for(unsigned dataIndex = 0; dataIndex < kTestDataAmount; ++dataIndex)
    {
        for(unsigned chunkSizeIndex = 0;
            chunkSizeIndex < sizeof(kChunkSizes)/sizeof(std::size_t);
            ++chunkSizeIndex)
        {
            WHash::MD5 md5Calculator;
            gLCG.setSeed(dataIndex);

            if(!testHash(md5Calculator, kDataLengths[dataIndex], kChunkSizes[chunkSizeIndex],
                         getRandomByte, kHashes[dataIndex].md5hash))
            {
                return printErrorMsg("MD5", dataIndex, chunkSizeIndex, kHashes[dataIndex].md5hash,
                                     md5Calculator.currentHash());
            }

            WHash::SHA1 sha1Calculator;
            gLCG.setSeed(dataIndex);

            if(!testHash(sha1Calculator, kDataLengths[dataIndex], kChunkSizes[chunkSizeIndex],
                         getRandomByte, kHashes[dataIndex].sha1hash))
            {
                return printErrorMsg("SHA1", dataIndex, chunkSizeIndex, kHashes[dataIndex].sha1hash,
                                     sha1Calculator.currentHash());
            }

            if(kChunkSizes[chunkSizeIndex] >= kDataLengths[dataIndex])
                break;
        }
    }

    std::printf("Tests ok.\n");
#endif
}
