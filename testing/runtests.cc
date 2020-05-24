#define GENERATE_HASHES 0

#include "../WHash_md5.hh"
#include "../WHash_sha1.hh"
#include "../WHash_sha256.hh"
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
using SHA256Hash = std::array<unsigned char, 32>;

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

SHA256Hash operator"" _sha256hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<32>(hexStr, len); }

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
    char outputBuffer1[80], outputBuffer2[80], outputBuffer3[80];

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

        iStream = popen("sha256sum testsdata.dat", "r");
        std::fgets(outputBuffer3, 80, iStream);
        pclose(iStream);

        std::printf("        { \"");
        printFirstWord(outputBuffer1);
        std::printf("\"_md5hash, \"");
        printFirstWord(outputBuffer2);
        std::printf("\"_sha1hash,\n          \"");
        printFirstWord(outputBuffer3);
        std::printf("\"_sha256hash },\n");
    }

    std::remove("testsdata.dat");
#else
    const struct
    {
        MD5Hash md5hash;
        SHA1Hash sha1hash;
        SHA256Hash sha256hash;
    }
    kHashes[] =
    {
        { "d41d8cd98f00b204e9800998ecf8427e"_md5hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709"_sha1hash,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"_sha256hash },
        { "4dcde376fbc212f73c0b00b7909fc4cf"_md5hash, "08dbbf42caba6501b69b1cea7a9b84e358e66ddb"_sha1hash,
          "26e5bfe4b0686167e3e4e0aac40cbae03515171d375f91ea563c9c044e9c5cc7"_sha256hash },
        { "559bf01ee292366c1fca4a2bfb2b17b6"_md5hash, "9721e02a6a23830ac58283a26581ab9e3cee6551"_sha1hash,
          "88bd293545d2b0498a07013b70d83de1e30805479415839a16996cf3126afa32"_sha256hash },
        { "4828d3b519fe50d5908893bfd24b1972"_md5hash, "ec2b762b8452afcfcbd9867d226de0f1d8856ab7"_sha1hash,
          "264b45fa029c54c5eaa3adcfc9614ad31cedf4e1a0c7bf5779f319e8b76a22cd"_sha256hash },
        { "c7b645c4cd931258f050db14df4f2353"_md5hash, "9ba196ff91399a9a2010a72cff238d5c246ab1ee"_sha1hash,
          "3a432c33c035b8ffbcaecb2578be92f65aaca71e8f74984c6bd52f3f95aae692"_sha256hash },
        { "8fbe428bfc4e4a09209725d295958a97"_md5hash, "4d1d3917d290305de10c7e9a6a4a0475aeaa9fd6"_sha1hash,
          "fd87874ccbd450ae91f9e2ab1f70be6a2452437c96d7a41eb0c4b657d9e849cf"_sha256hash },
        { "98f21512ce635362c3f34728a49799a4"_md5hash, "6358df85fb8b69f066729a73eb1ed3021050c7da"_sha1hash,
          "f38f88bf6c3961930f870a2b121a2be4c333dc7bb0659e15783345fca61731a2"_sha256hash },
        { "d199b6456a0aa5e798283cde0c807765"_md5hash, "074a16536d9bec56e2cc6341e649e9a3faa5ac8c"_sha1hash,
          "c2126624efdb7e98500def5b04d195a80b6c37e2b74c73d0a1a2fc569271090f"_sha256hash },
        { "52dd7e5ab4b40408b7c1e6ecb084f8bd"_md5hash, "c3c1b1110adb7c7fd83d4f508e6f44bbe6638339"_sha1hash,
          "258269e964ebc16f24b688df5b78aa6116d15e37486cbcbbb82054cf48bf1f95"_sha256hash },
        { "e2a71510a93eac869fa17ae4e831bae8"_md5hash, "524f2b743ff8d07395ac5e5d384f35be82bdec43"_sha1hash,
          "277bf15e3b413ad5dd5c5647d28c42e7e3f38c11c7ec9a535c527cebed839996"_sha256hash },
        { "ac424dafa379ba8ca7cdef3ba7c13895"_md5hash, "79d730378eaccec325d0c3afeb5c9a62c22db047"_sha1hash,
          "9ad64cb89adbcbdbfb4c693c82a3b1a4aeaa6149ab87722e4492cf97ed48286a"_sha256hash },
        { "1226bc97fba5fcc76b14c9318dea7bc3"_md5hash, "593881b29e151c1968083b123d4c6d7220b7d9d9"_sha1hash,
          "c32b709f3db08315c83e37e3992c558fee64e2ba22aae07b4fbdb11e89d2afb1"_sha256hash },
        { "aaf7935eada1868795125693df975585"_md5hash, "6d15e824adf9dbfa227a22a066035d45c7db1a62"_sha1hash,
          "4121821a93a99518787516782eac1567b57923fde325a4c942d138624fe880d3"_sha256hash },
        { "e200de49c1ea4d5ba15525f3d8d996a7"_md5hash, "945d4333545720c470c3c616165d8e8435510ca2"_sha1hash,
          "d9d30c9f724b3edd0b1a4633800c1292a8d41b448466576b821ce6274dd2a87e"_sha256hash },
        { "c442d86851ccbd4eee78cf05e09093cd"_md5hash, "401c06774dfed956435d687ef65971e941944217"_sha1hash,
          "7d07c2d2b9d2942228bb70f144129273975bae6956d1b825a2085ea64da489de"_sha256hash },
        { "5d65303d5609d6588a3cc9cf38187408"_md5hash, "80a8c16124c15b8e3a88c73e9d2de1a65606fe1a"_sha1hash,
          "ec6cbe1176613a6e365e9b8fefeace842864c7d7e3d706b27aadfde5d7f3b930"_sha256hash },
        { "cfae4b94aec0755c38d8ca8afcd87ce2"_md5hash, "f5143fc32b558f45d0ab490a51c6d49a828a478a"_sha1hash,
          "1d349866e667dcf16727394266410a0a055b1eb9b4cf0737d996985143b87a1a"_sha256hash },
        { "d27bb22bbeaf92bc0e188a0109f912ad"_md5hash, "8fb853604ab5be17c1609c80b39a356376dabd18"_sha1hash,
          "4fada1cefe4ca87be9f329059eb59632887952263d5597eb8ee59b55e63f4b80"_sha256hash },
        { "4d778b35ad841642a654ecd35dced827"_md5hash, "f2ea3d79263c1d2629b756ec5e84035227ecbaad"_sha1hash,
          "04c973b682b84507dee481686756e918408c84b5149c09ceeb23af302508c163"_sha256hash },
        { "75517656a73fcb4d9768e68af03aec59"_md5hash, "63dc03c6400ee63377bd02adf3f0f078548a3595"_sha1hash,
          "3988a390034e03b2c7603f2954d32ae3a26c589f4e376ce01de2cef51cb8353c"_sha256hash },
        { "203e7732728ab2ad086aa50a739fd82a"_md5hash, "cae167281aa1b1fd3ac7d60f82ee26f7633d5a95"_sha1hash,
          "9dc196ebf8055a23c14ca20f325f50e4d368c47be3eb56d14db120a6e943c14a"_sha256hash },
        { "a2758bbea3f3c059a1850f71183149ec"_md5hash, "11b1b5fc585babc230d610b2ef6280b5901159d9"_sha1hash,
          "104a659a8b6338ca22861f230badd93af4ead8d9f4be6fd236cce00ed37a8f61"_sha256hash },
        { "937eec3072ed7343acd44d9c281cd2d7"_md5hash, "4d1b997a2d8c36561cce21a3dd27ec273fddf29b"_sha1hash,
          "00f780008a3e572f60dd26fe7cef23df638616ac0830af41d26a753d9932f9cb"_sha256hash },
        { "b5f60307b7898e4372c838a379f42733"_md5hash, "0d66982b0c81ebe0d0263d81391ebe8e9cf2b7d7"_sha1hash,
          "fd8a4d58f629ca3b3dd2a603b37eee2178a09f17b29da8bf854c9ffac506c70a"_sha256hash },
        { "3b11aee4f7272cebadbdd9c58aacae39"_md5hash, "7017b30060cc52213b80ad8948fd9c9a208356d1"_sha1hash,
          "374d22d9d844ceaa117c140f4fec81c917be7d0a242b494ec6f29e5ff42c4f16"_sha256hash },
        { "0a38fa543233640eebbfcf5d535812de"_md5hash, "8b7db445e6e39dd4f7147b23c8bbed6914b79354"_sha1hash,
          "f53361f4222da4a930591b5685afc86267fee32c71c745644dc3971ffb0dfcdb"_sha256hash },
        { "ca36a1163dade565cc017587589a4970"_md5hash, "a5d6f7e3bc753b5d1a9831e6206d095acffcb3ed"_sha1hash,
          "5a140fab9ce861041340ee61744c19346580ade8e4a05c67d21f5ec698bf7ad5"_sha256hash },
        { "2b7d7dc535b33b28b244e093bb9c0866"_md5hash, "fc1dbe30c36d1192b420f5a8303d14e8a5a04498"_sha1hash,
          "44cc0067fc92a7f242ebbb5b74362e3bd86e9eb2230f5d09db7845af075b40fa"_sha256hash },
        { "e91edefa3d755fdadbde18705ad07b87"_md5hash, "0c17ab0ecc5d097c6c325f7608794d46ff64133f"_sha1hash,
          "c5d2edd7ac44758bc20c9457eb7d0a37e94c3027c568faba4abb73d58f346958"_sha256hash },
        { "976934a50bccb627855bd9739194bf55"_md5hash, "6da53b45b430ded24cd5c0200c6d4aad9b0317d1"_sha1hash,
          "3298f0dbc53df5027dadc941a0ca9311366597a5eea9826100f562ceba150385"_sha256hash },
        { "1c3afcedc386f1149a1862cad16c8982"_md5hash, "f44f8e3caca876f2d434ba3860213a02a4c5044f"_sha1hash,
          "25dc3825ca13a2941ca8e06c293ef689c844811d686ed7f229d792123efdaefd"_sha256hash },
        { "569e1d7e974437beccc26605572ef43c"_md5hash, "3bc775351b8bb3cc0324a7f55c096decf8d06501"_sha1hash,
          "5dc30e52f13cc035030d442993120448fe89d3a9fe3460a64d8aeb3ead0ae2c1"_sha256hash },
        { "3395cef3c8944b192a39de1c9b88285a"_md5hash, "9d1184ffea53fb49135bcdabcbbe0ca8928d2d4e"_sha1hash,
          "903ed14acb0cfd8045ed72e95894bcebd7a9be8e586c7799e9acfdeaa2a0c5b3"_sha256hash },
        { "a2a5904baec7762004e0b72f9a2fdfbf"_md5hash, "d99c724e1d197305ae15c9d09599ffd1a9d015f6"_sha1hash,
          "98fffccf61a1ccbe73efbd3c0f11f3676043cbb85702405c544ef01e0276ca99"_sha256hash },
        { "3c15c0a45fa0ffc40657f7eed58d62cb"_md5hash, "dc196883e3d2e34ee9d11010f3d2424b822fa2c9"_sha1hash,
          "517ca17c0f324b1b2c33c78ce1e5155ad44a604bb7581f26dfc5c775884a3f31"_sha256hash },
        { "0ae75fbe754bcc55d1c5b34d9da4aee2"_md5hash, "4048757bac0cd14e68ca495aa11c17d81d958892"_sha1hash,
          "2e3a6a02eae0cd6ff5a5bba3cfb5cc12da41dcf227b6b20f8ab8ef0fdbafaaf5"_sha256hash },
        { "c76d791ddb256ba72cecc47d57415517"_md5hash, "baa1ca69a90f0095f9450298315040f1650abeb6"_sha1hash,
          "f7c374ad7641a5f07a918f6d3430cd38ae5a4628a7c4cc622929538c55f20364"_sha256hash },
        { "023c3b711903e56bf823d64bb994aedc"_md5hash, "f158083117a2101498ad777506bd4acf589c77c3"_sha1hash,
          "ae9ae297e737c17e7101eb60cff791d8dde0a5b3dd7012fbc333c773da4053eb"_sha256hash },
        { "939dbdabe253ef36a91191514fa1e035"_md5hash, "3640a63ec0a4d5ec83b7cba3bda77b8239522731"_sha1hash,
          "d6497b2577810a82e050344d977d8dc645b6f0a0ec2e497f12ccc3273cfb8b40"_sha256hash },
        { "4519692f6c47f6465336c54c29a6801c"_md5hash, "8345ec118b4677f6e502cb13b6876c9ca1efcee7"_sha1hash,
          "d8ec80b2f96dd3bdc46753158c1e14cc25e8527010975f72fbc96e2f3688f26c"_sha256hash },
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

            WHash::SHA256 sha256Calculator;
            gLCG.setSeed(dataIndex);

            if(!testHash(sha256Calculator, kDataLengths[dataIndex], kChunkSizes[chunkSizeIndex],
                         getRandomByte, kHashes[dataIndex].sha256hash))
            {
                return printErrorMsg("SHA256", dataIndex, chunkSizeIndex, kHashes[dataIndex].sha256hash,
                                     sha256Calculator.currentHash());
            }

            if(kChunkSizes[chunkSizeIndex] >= kDataLengths[dataIndex])
                break;
        }
    }

    std::printf("Tests ok.\n");
#endif
}
