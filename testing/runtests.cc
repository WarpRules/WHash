#define GENERATE_HASHES 0

#include "../WHash_crc.hh"
#include "../WHash_crc32.hh"
#include "../WHash_md5.hh"
#include "../WHash_sha1.hh"
#include "../WHash_sha224.hh"
#include "../WHash_sha256.hh"
#include "../WHash_sha384.hh"
#include "../WHash_sha512.hh"
#include "../WHash_sha3.hh"
#include "../WHash_utilities.hh"
#include <cstdio>
#include <cstdint>
#include <cctype>
#include <array>
#include <memory>


using CRC32Hash = std::array<unsigned char, 4>;
using MD5Hash = std::array<unsigned char, 16>;
using SHA1Hash = std::array<unsigned char, 20>;
using SHA224Hash = std::array<unsigned char, 28>;
using SHA256Hash = std::array<unsigned char, 32>;
using SHA384Hash = std::array<unsigned char, 48>;
using SHA512Hash = std::array<unsigned char, 64>;

struct TestHashData
{
    CRC32Hash crc32hash;
    MD5Hash md5hash;
    SHA1Hash sha1hash;
    SHA224Hash sha224hash;
    SHA256Hash sha256hash;
    SHA384Hash sha384hash;
    SHA512Hash sha512hash;
    SHA224Hash sha3_224hash;
    SHA256Hash sha3_256hash;
    SHA384Hash sha3_384hash;
    SHA512Hash sha3_512hash;
};


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

CRC32Hash operator"" _crc32hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<4>(hexStr, len); }

MD5Hash operator"" _md5hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<16>(hexStr, len); }

SHA1Hash operator"" _sha1hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<20>(hexStr, len); }

SHA224Hash operator"" _sha224hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<28>(hexStr, len); }

SHA256Hash operator"" _sha256hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<32>(hexStr, len); }

SHA384Hash operator"" _sha384hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<48>(hexStr, len); }

SHA512Hash operator"" _sha512hash(const char* hexStr, std::size_t len)
{ return hexStrToByteArray<64>(hexStr, len); }


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
    while(*strEnd && std::isalnum(*strEnd)) ++strEnd;
    std::fwrite(str, 1, strEnd - str, stdout);
}
#endif

[[maybe_unused]]
static void printInHex(const unsigned char* data, std::size_t size)
{
    for(std::size_t i = 0; i < size; ++i)
        std::printf("%c%c", nibbleToAscii(data[i] >> 4), nibbleToAscii(data[i] & 0xF));
}

template<typename HashCalculator_t, std::size_t kHashSize>
bool runTest(const char* hashName, unsigned dataIndex, unsigned dataLength, unsigned chunkSize,
             const std::array<unsigned char, kHashSize>& expectedHash)
{
    HashCalculator_t hashCalculator;
    gLCG.setSeed(dataIndex);

    if(!testHash(hashCalculator, dataLength, chunkSize, getRandomByte, expectedHash))
    {
        std::printf("%s test failed with dataIndex:%u, chunkSize:%u\n", hashName, dataIndex, chunkSize);
        std::printf("Expected: ");
        printInHex(expectedHash.data(), kHashSize);
        std::printf("\n     Got: ");
        printInHex(hashCalculator.currentHash(), kHashSize);
        std::printf("\n");
        return false;
    }
    return true;
}

template<typename CRCCalculator_t>
bool runCRCTest(const char* name, typename CRCCalculator_t::Value_t check)
{
    const char* data = "123456789";
    CRCCalculator_t calculator;
    calculator.update(data, 9);
    calculator.finish();

    if(calculator.crcValue() != check)
    {
        std::printf("%s failed test: Check CRC should have been %llX but class returned %llX.\n",
                    name, static_cast<unsigned long long>(check),
                    static_cast<unsigned long long>(calculator.crcValue()));
        return false;
    }
    return true;
}

bool runCRCTests()
{
    /* Parameters and check values are from
       http://reveng.sourceforge.net/crc-catalogue/all.htm
    */
#define RUN_CRC_TEST(name, check) runCRCTest<WHash::CRC::name>("WHash::CRC::" #name, check)
    return (RUN_CRC_TEST(CRC3_rohc, 0x06) &&
            RUN_CRC_TEST(CRC4_g704, 0x07) &&
            RUN_CRC_TEST(CRC5_g704, 0x07) &&
            RUN_CRC_TEST(CRC5_usb, 0x19) &&
            RUN_CRC_TEST(CRC6_darc, 0x26) &&
            RUN_CRC_TEST(CRC6_g704, 0x06) &&
            RUN_CRC_TEST(CRC7_rohc, 0x53) &&
            RUN_CRC_TEST(CRC8_aes, 0x97) &&
            RUN_CRC_TEST(CRC8_autosar, 0xdf) &&
            RUN_CRC_TEST(CRC8_bluetooth, 0x26) &&
            RUN_CRC_TEST(CRC8_cdma2000, 0xda) &&
            RUN_CRC_TEST(CRC8_darc, 0x15) &&
            RUN_CRC_TEST(CRC8_dvbs2, 0xbc) &&
            RUN_CRC_TEST(CRC8_gsma, 0x37) &&
            RUN_CRC_TEST(CRC8_gsmb, 0x94) &&
            RUN_CRC_TEST(CRC8_itu, 0xa1) &&
            RUN_CRC_TEST(CRC8_icode, 0x7e) &&
            RUN_CRC_TEST(CRC8_lte, 0xea) &&
            RUN_CRC_TEST(CRC8_maxim, 0xa1) &&
            RUN_CRC_TEST(CRC8_mifare, 0x99) &&
            RUN_CRC_TEST(CRC8_nrsc5, 0xf7) &&
            RUN_CRC_TEST(CRC8_opensafety, 0x3e) &&
            RUN_CRC_TEST(CRC8_rohc, 0xd0) &&
            RUN_CRC_TEST(CRC8_saej1850, 0x4b) &&
            RUN_CRC_TEST(CRC8_smbus, 0xf4) &&
            RUN_CRC_TEST(CRC8_wcdma, 0x25) &&
            RUN_CRC_TEST(CRC10_atm, 0x199) &&
            RUN_CRC_TEST(CRC10_cdma2000, 0x233) &&
            RUN_CRC_TEST(CRC10_gsm, 0x12a) &&
            RUN_CRC_TEST(CRC11_flexray, 0x5a3) &&
            RUN_CRC_TEST(CRC11_umts, 0x061) &&
            RUN_CRC_TEST(CRC12_cdma2000, 0xd4d) &&
            RUN_CRC_TEST(CRC12_dect, 0xf5b) &&
            RUN_CRC_TEST(CRC12_gsm, 0xb34) &&
            RUN_CRC_TEST(CRC12_umts, 0xdaf) &&
            RUN_CRC_TEST(CRC13_bbc, 0x04fa) &&
            RUN_CRC_TEST(CRC14_darc, 0x082d) &&
            RUN_CRC_TEST(CRC14_gsm, 0x30ae) &&
            RUN_CRC_TEST(CRC15_can, 0x059e) &&
            RUN_CRC_TEST(CRC15_mpt1327, 0x2566) &&
            RUN_CRC_TEST(CRC16_arc, 0xbb3d) &&
            RUN_CRC_TEST(CRC16_cdma2000, 0x4c06) &&
            RUN_CRC_TEST(CRC16_cms, 0xaee7) &&
            RUN_CRC_TEST(CRC16_dds110, 0x9ecf) &&
            RUN_CRC_TEST(CRC16_dectr, 0x007e) &&
            RUN_CRC_TEST(CRC16_dectx, 0x007f) &&
            RUN_CRC_TEST(CRC16_dnp, 0xea82) &&
            RUN_CRC_TEST(CRC16_en13757, 0xc2b7) &&
            RUN_CRC_TEST(CRC16_genibus, 0xd64e) &&
            RUN_CRC_TEST(CRC16_gsm, 0xce3c) &&
            RUN_CRC_TEST(CRC16_ibm3740, 0x29b1) &&
            RUN_CRC_TEST(CRC16_ibmsdlc, 0x906e) &&
            RUN_CRC_TEST(CRC16_iso, 0xbf05) &&
            RUN_CRC_TEST(CRC16_kermit, 0x2189) &&
            RUN_CRC_TEST(CRC16_lj1200, 0xbdf4) &&
            RUN_CRC_TEST(CRC16_maxim, 0x44c2) &&
            RUN_CRC_TEST(CRC16_mcrf4xx, 0x6f91) &&
            RUN_CRC_TEST(CRC16_modbus, 0x4b37) &&
            RUN_CRC_TEST(CRC16_nrsc5, 0xa066) &&
            RUN_CRC_TEST(CRC16_opensafetya, 0x5d38) &&
            RUN_CRC_TEST(CRC16_opensafetyb, 0x20fe) &&
            RUN_CRC_TEST(CRC16_profibus, 0xa819) &&
            RUN_CRC_TEST(CRC16_riello, 0x63d0) &&
            RUN_CRC_TEST(CRC16_spifujitsu, 0xe5cc) &&
            RUN_CRC_TEST(CRC16_t10dif, 0xd0db) &&
            RUN_CRC_TEST(CRC16_teledisk, 0x0fb3) &&
            RUN_CRC_TEST(CRC16_tms37157, 0x26b1) &&
            RUN_CRC_TEST(CRC16_umts, 0xfee8) &&
            RUN_CRC_TEST(CRC16_usb, 0xb4c8) &&
            RUN_CRC_TEST(CRC16_xmodem, 0x31c3) &&
            RUN_CRC_TEST(CRC17_canfd, 0x04f03) &&
            RUN_CRC_TEST(CRC21_canfd, 0xed841) &&
            //RUN_CRC_TEST(CRC24_ble, 0xc25a56) &&
            RUN_CRC_TEST(CRC24_flexraya, 0x7979bd) &&
            RUN_CRC_TEST(CRC24_flexrayb, 0x1f23b8) &&
            RUN_CRC_TEST(CRC24_interlaken, 0xb4f3e6) &&
            RUN_CRC_TEST(CRC24_ltea, 0xcde703) &&
            RUN_CRC_TEST(CRC24_lteb, 0x23ef52) &&
            RUN_CRC_TEST(CRC24_openpgp, 0x21cf02) &&
            RUN_CRC_TEST(CRC24_os9, 0x200fa5) &&
            RUN_CRC_TEST(CRC30_cdma, 0x04c34abf) &&
            RUN_CRC_TEST(CRC31_philips, 0x0ce9e46c) &&
            RUN_CRC_TEST(CRC32_aixm, 0x3010bf7f) &&
            RUN_CRC_TEST(CRC32_autosar, 0x1697d06a) &&
            RUN_CRC_TEST(CRC32_base91d, 0x87315576) &&
            RUN_CRC_TEST(CRC32_bzip2, 0xfc891918) &&
            RUN_CRC_TEST(CRC32_cdromedc, 0x6ec2edc4) &&
            RUN_CRC_TEST(CRC32_cksum, 0x765e7680) &&
            RUN_CRC_TEST(CRC32_iscsi, 0xe3069283) &&
            RUN_CRC_TEST(CRC32_isohdlc, 0xcbf43926) &&
            RUN_CRC_TEST(CRC32_jamcrc, 0x340bc6d9) &&
            RUN_CRC_TEST(CRC32_mpeg2, 0x0376e6e7) &&
            RUN_CRC_TEST(CRC32_xfer, 0xbd0be338) &&
            RUN_CRC_TEST(CRC40_gsm, 0xd4164fc646) &&
            RUN_CRC_TEST(CRC64_ecma182, 0x6c40df5f0b497347) &&
            RUN_CRC_TEST(CRC64_goiso, 0xb90956c775a41001) &&
            RUN_CRC_TEST(CRC64_we, 0x62ec59e3f1a4f00a) &&
            RUN_CRC_TEST(CRC64_xz, 0x995dc9bbdf1939fa));
}

static void printArray(const unsigned char *a, std::size_t bytesAmount)
{
    if(bytesAmount == 0) std::printf("[]");
    std::printf("[ %u", a[0]);
    for(std::size_t i = 1; i < bytesAmount; ++i)
        std::printf(", %u", a[i]);
    std::printf(" ]");
}

static bool checkByteArraysEqual(const unsigned char *a1, const unsigned char *a2, std::size_t bytesAmount, bool expected)
{
    const bool result = WHash::byteArraysEqual(a1, a2, bytesAmount);
    if(result != expected)
    {
        std::printf("Comparing array:\n");
        printArray(a1, bytesAmount);
        std::printf("\nand:\n");
        printArray(a2, bytesAmount);
        std::printf("\nreturned %i instead of %i\n", result, expected);
        return false;
    }
    return true;
}

static bool runUtilitiesTests()
{
    const unsigned char data1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const unsigned char data2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11 };
    for(std::size_t i = 0; i <= 10; ++i)
        if(!checkByteArraysEqual(data1, data2, i, true))
            return false;
    return checkByteArraysEqual(data1, data2, 11, false);
}

extern TestHashData kTestHashes[];

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
    char outputBuffer1[16];
    char outputBuffer2[6][80];
    char outputBuffer3[4][160];

    for(unsigned dataIndex = 0; dataIndex < kTestDataAmount; ++dataIndex)
    {
        gLCG.setSeed(dataIndex);
        std::FILE* oFile = std::fopen("testsdata.dat", "wb");

        const unsigned dataLength = kDataLengths[dataIndex];
        for(unsigned i = 0; i < dataLength; ++i)
            std::fputc(gLCG.getNext(), oFile);

        std::fclose(oFile);

        std::FILE* iStream = popen("crc32 testsdata.dat", "r");
        std::fgets(outputBuffer1, 16, iStream);
        pclose(iStream);

        iStream = popen("md5sum testsdata.dat", "r");
        std::fgets(outputBuffer2[0], 80, iStream);
        pclose(iStream);

        iStream = popen("sha1sum testsdata.dat", "r");
        std::fgets(outputBuffer2[1], 80, iStream);
        pclose(iStream);

        iStream = popen("sha224sum testsdata.dat", "r");
        std::fgets(outputBuffer2[2], 80, iStream);
        pclose(iStream);

        iStream = popen("sha256sum testsdata.dat", "r");
        std::fgets(outputBuffer2[3], 80, iStream);
        pclose(iStream);

        iStream = popen("sha384sum testsdata.dat", "r");
        std::fgets(outputBuffer3[0], 160, iStream);
        pclose(iStream);

        iStream = popen("sha512sum testsdata.dat", "r");
        std::fgets(outputBuffer3[1], 160, iStream);
        pclose(iStream);

        iStream = popen("./sha3_224sum testsdata.dat", "r");
        std::fgets(outputBuffer2[4], 80, iStream);
        pclose(iStream);

        iStream = popen("./sha3_256sum testsdata.dat", "r");
        std::fgets(outputBuffer2[5], 80, iStream);
        pclose(iStream);

        iStream = popen("./sha3_384sum testsdata.dat", "r");
        std::fgets(outputBuffer3[2], 160, iStream);
        pclose(iStream);

        iStream = popen("./sha3_512sum testsdata.dat", "r");
        std::fgets(outputBuffer3[3], 160, iStream);
        pclose(iStream);

        std::printf("    { \"");
        printFirstWord(outputBuffer1);
        std::printf("\"_crc32hash, \"");
        printFirstWord(outputBuffer2[0]);
        std::printf("\"_md5hash,\n      \"");
        printFirstWord(outputBuffer2[1]);
        std::printf("\"_sha1hash,\n      \"");
        printFirstWord(outputBuffer2[2]);
        std::printf("\"_sha224hash,\n      \"");
        printFirstWord(outputBuffer2[3]);
        std::printf("\"_sha256hash,\n      \"");
        printFirstWord(outputBuffer3[0]);
        std::printf("\"_sha384hash,\n      \"");
        printFirstWord(outputBuffer3[1]);
        std::printf("\"_sha512hash,\n      \"");
        printFirstWord(outputBuffer2[4]);
        std::printf("\"_sha224hash,\n      \"");
        printFirstWord(outputBuffer2[5]);
        std::printf("\"_sha256hash,\n      \"");
        printFirstWord(outputBuffer3[2]);
        std::printf("\"_sha384hash,\n      \"");
        printFirstWord(outputBuffer3[3]);
        std::printf("\"_sha512hash },\n");
    }

    std::remove("testsdata.dat");
#else
    if(!runCRCTests()) return 1;

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
            if(!runTest<WHash::CRC32>("CRC32", dataIndex, kDataLengths[dataIndex],
                                      kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].crc32hash) ||
               !runTest<WHash::MD5>("MD5", dataIndex, kDataLengths[dataIndex],
                                    kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].md5hash) ||
               !runTest<WHash::SHA1>("SHA1", dataIndex, kDataLengths[dataIndex],
                                    kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha1hash) ||
               !runTest<WHash::SHA224>("SHA224", dataIndex, kDataLengths[dataIndex],
                                       kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha224hash) ||
               !runTest<WHash::SHA256>("SHA256", dataIndex, kDataLengths[dataIndex],
                                       kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha256hash) ||
               !runTest<WHash::SHA384>("SHA384", dataIndex, kDataLengths[dataIndex],
                                       kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha384hash) ||
               !runTest<WHash::SHA512>("SHA512", dataIndex, kDataLengths[dataIndex],
                                       kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha512hash) ||
               !runTest<WHash::SHA3_224>("SHA3_224", dataIndex, kDataLengths[dataIndex],
                                         kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha3_224hash) ||
               !runTest<WHash::SHA3_256>("SHA3_256", dataIndex, kDataLengths[dataIndex],
                                         kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha3_256hash) ||
               !runTest<WHash::SHA3_384>("SHA3_384", dataIndex, kDataLengths[dataIndex],
                                         kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha3_384hash) ||
               !runTest<WHash::SHA3_512>("SHA3_512", dataIndex, kDataLengths[dataIndex],
                                         kChunkSizes[chunkSizeIndex], kTestHashes[dataIndex].sha3_512hash))
            {
                return 1;
            }

            if(kChunkSizes[chunkSizeIndex] >= kDataLengths[dataIndex])
                break;
        }
    }

    if(!runUtilitiesTests()) return 1;

    std::printf("Tests ok.\n");
#endif
}


#if !GENERATE_HASHES
TestHashData kTestHashes[] =
{
    { "00000000"_crc32hash, "d41d8cd98f00b204e9800998ecf8427e"_md5hash,
      "da39a3ee5e6b4b0d3255bfef95601890afd80709"_sha1hash,
      "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"_sha224hash,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"_sha256hash,
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"_sha384hash,
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"_sha512hash,
      "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7"_sha224hash,
      "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"_sha256hash,
      "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004"_sha384hash,
      "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26"_sha512hash },
    { "10d5102a"_crc32hash, "4dcde376fbc212f73c0b00b7909fc4cf"_md5hash,
      "08dbbf42caba6501b69b1cea7a9b84e358e66ddb"_sha1hash,
      "805e5dc12e3c2db1bf3609480e0cbce469379f856d178ec54ac2e75c"_sha224hash,
      "26e5bfe4b0686167e3e4e0aac40cbae03515171d375f91ea563c9c044e9c5cc7"_sha256hash,
      "5ed9b8864d0b5ff88b9ab3007340659566a39b935d1009be24744e2600ce4e3a4b3463aa424bc32ca4afa4d3bd00af02"_sha384hash,
      "8baa474d1383af0a7c3efaa26b279621e81c0c73336ee77edb9c54a04327a3260853a6693065e2a6d4a55e3a208cf2e240642a24fc08b05ae4b5eef508910742"_sha512hash,
      "62570E6692156BF7616F14CDF2BE1CF6B2B7052E69CD21F8D4048EF0"_sha224hash,
      "998C2D7F4B0CC30534E323AE6163800310862417C17F0F82A17AC1B55D7923DA"_sha256hash,
      "45A1933E1C002DF36A4F0F649B770179EE672548F8BB6454083C326BC9280C7AC53CA06C1033E7913B6B35A7CB43D475"_sha384hash,
      "DB09FEEB2EB756782D9C425B8D3697C310E9436BABA689BE0CD2509CCB076C85ED87F3CB199EFCC70F61484E79B7E093EBF2BC21918BC2EF3430E1F75217D038"_sha512hash },
    { "71e53e3d"_crc32hash, "559bf01ee292366c1fca4a2bfb2b17b6"_md5hash,
      "9721e02a6a23830ac58283a26581ab9e3cee6551"_sha1hash,
      "1a3134243aa9fa287967f92ac2a915cd9f71be28d2d1c437093ec6c2"_sha224hash,
      "88bd293545d2b0498a07013b70d83de1e30805479415839a16996cf3126afa32"_sha256hash,
      "c6007c91034a1e1a8b4fc8b2632eabf792c7c2041745317abd3be5032c2ad901cdac26c7396b9e734d22e173448f66be"_sha384hash,
      "15e74aa7a81e667a4ee3d3f6d7bf9c43c1edc7ea2314f48ff8856972f577771eb730c1d83a0e4a29817289e73bdf07a65fafcf730bd5ae78628f713d0317bf75"_sha512hash,
      "9B175E80A7B7B89BB8D75E90F25C86C22A8FE06C4764A32E3F64D65D"_sha224hash,
      "ABE495B7ED9D51308E087FA92B863D1CF0BE74EE6D6454FDD00640947FADF99B"_sha256hash,
      "995416D638713C879D54AB27A03C692F81EE55F29C218FB6EDB06D1C4EBE7D14D6A259FB8DB0575A633432A6FDC8188A"_sha384hash,
      "413DD7AD676AC1309AC6D3E37934B0F2B196C16039D8F08D04802EC61E0C1D60CBBB60D6DBF0897B577950B6841778C3BB78FFD23C2C31C2030310D66527A144"_sha512hash },
    { "5cb0d261"_crc32hash, "4828d3b519fe50d5908893bfd24b1972"_md5hash,
      "ec2b762b8452afcfcbd9867d226de0f1d8856ab7"_sha1hash,
      "edc505e63618c21de32f6195af3618329e94556b68f3d21df588e91b"_sha224hash,
      "264b45fa029c54c5eaa3adcfc9614ad31cedf4e1a0c7bf5779f319e8b76a22cd"_sha256hash,
      "c7fe97d068a142110a5e4006310b1c5cf28fae582d0e1a606fbc4a5347c7ee5464ae69b1589d4c2ec9e9aa9e72b4c8b9"_sha384hash,
      "99f5d4318c449008821c84bb6febfbf54c00470364b45c82bfcad747b2270f30737210d6a842ae00c5045b5d60952338723e89c1ff9e5a96c66116f8797e5355"_sha512hash,
      "62F15926A93E6939BBED35253F2A78C2087B06B7BA959A0B17C4779F"_sha224hash,
      "9A3458D63629FBE6DEB5F1A078E57C56ACA8DF62FBA5941E27D39C2A5592551A"_sha256hash,
      "8759B2BB91DFC41EA98B04696330ACE15AFD4C61730FCD1A8DC9C7A85EE4016BBA3760A0F982AFE124D90BB60910008D"_sha384hash,
      "8F74ED7C29D63A8FEF5C86325D729DABE63C97962DD70E64E0031E6F88596E3A36CA1DD7ADB9D981A65FFE201B3B7B7ABEED326E62A7368BE1014D97BE1C4CA2"_sha512hash },
    { "1351f702"_crc32hash, "c7b645c4cd931258f050db14df4f2353"_md5hash,
      "9ba196ff91399a9a2010a72cff238d5c246ab1ee"_sha1hash,
      "548deb203530c11d84852353a8f2dfdbfd3d46bd48b1bdb48bba854e"_sha224hash,
      "3a432c33c035b8ffbcaecb2578be92f65aaca71e8f74984c6bd52f3f95aae692"_sha256hash,
      "46a10550421f15874b81ed40add45de458cd42a4390568998ece12c74ec6bf78c8f64ea6510661f0e8e4b2d98462d7fc"_sha384hash,
      "e52188c46f68e9f0b273ebbb5585cb6a5e304eb4f4c367802423d4c3709a6b045b9e281b070defe88d4a32425e6bbdcf4eb8f897358b68ebbdca9a977df7d26e"_sha512hash,
      "286B5613C61F68926178E6CDE6F7F2DAA34D9814A834FE7E8EC0257B"_sha224hash,
      "58D3E5A168A38A643D1CC0268AF3396D82E02A1DAC5B669E9A961090455A2872"_sha256hash,
      "0CCBAAB1567E38DE0A673F052466EA9F04FEB6C35AD380E07C3F36D81AF344512EA37833448351CF2635086A56E61B2F"_sha384hash,
      "943980F7D24AF5EBE21F72722C087ACA70077C80FBA5EF3634167463AA3D9C7CF9C955814DF7CDF98F02A368090A62C3A1F666DF7EDE05392EEFDA3AB2CB35D2"_sha512hash },
    { "2c26e947"_crc32hash, "8fbe428bfc4e4a09209725d295958a97"_md5hash,
      "4d1d3917d290305de10c7e9a6a4a0475aeaa9fd6"_sha1hash,
      "eea56c8bf54b73ba38fd59d33f0af4357cd140698269a11ba35f221b"_sha224hash,
      "fd87874ccbd450ae91f9e2ab1f70be6a2452437c96d7a41eb0c4b657d9e849cf"_sha256hash,
      "46597e27738ae60b53f399ddb86e3a709798674039be646eca2a30a6f0aaee3651fa7a0c2243ed75cce06f755a301835"_sha384hash,
      "c9a59be237874ee753c266d570ed8b4feda444f2bb04046fdd4393b299e66ebf153ba969d701b0fbbbd036212a7ba4f6a71594019d387b24892b4c546cde68c1"_sha512hash,
      "149FB022FECF679865014B713EDE6776AADAF509F8204884FE2DD08F"_sha224hash,
      "49CF199ACAD5B06B67AAB8685D4A871E601F3AE2BDF68A0B651CA0AC00B32F94"_sha256hash,
      "18CBE7F53D889CE87E45A0702E317AFFEA4A9B51F0BD63A13AED0E3DD490E449A0AE807511E8D184576484D444C190B0"_sha384hash,
      "B82777FC974580BB4529AAE5D934088D1A63D4866494F829EAC500A9DBEE0B5C71CF056F4BD8E2E10AE908C9D7DC9772382A765F02FE0277A44045782111DFAD"_sha512hash },
    { "7278b786"_crc32hash, "98f21512ce635362c3f34728a49799a4"_md5hash,
      "6358df85fb8b69f066729a73eb1ed3021050c7da"_sha1hash,
      "63f27c97ed4a22298725a0e71e952efc7bee3377d1b3c13fc18aa936"_sha224hash,
      "f38f88bf6c3961930f870a2b121a2be4c333dc7bb0659e15783345fca61731a2"_sha256hash,
      "a6f6baaf946bdf11568abfec7084a9e84a887521177b96e66b21c5f504eb55c4fcdc29a56ca3793d004ab2c3c3718215"_sha384hash,
      "ea08dcdcce7304cb2e430695817a4482deacbea29ec2c2e596a752940ff405111b6afe0e9e1afe4ed4f6250fc35f4dae7123326da8a9a7caf2f1c427f054fa43"_sha512hash,
      "A5768859B35AB31FBC750F6F3D4CB4168154818C4A0E4185449667F7"_sha224hash,
      "5417DF8F9DDFDC814062936081EFE85D2C4499726A76D26AB8E257D7ACCD5FA1"_sha256hash,
      "4361982EA08987ECCEB9B76C949F5D2056B3890EFFC35A99AD14B1CC74F79BD989572EC389751F0B61574A649A9CC9A4"_sha384hash,
      "76B6AA778EF2F1B8BC6182D8272D1F4F765AA785D708516A7BCD7EFD801C02EC472EB654CE3A68491325DEE0D0279B00FEA961CDB57F7DD4A39E097923243714"_sha512hash },
    { "3a012e81"_crc32hash, "d199b6456a0aa5e798283cde0c807765"_md5hash,
      "074a16536d9bec56e2cc6341e649e9a3faa5ac8c"_sha1hash,
      "35b0155209512ccd33ecd36ad654cd114788f47027f3350b1f5bc6d5"_sha224hash,
      "c2126624efdb7e98500def5b04d195a80b6c37e2b74c73d0a1a2fc569271090f"_sha256hash,
      "a2b0406080643a3ee28141bc079e34eaa5d411abd7b44b820d1b61b57532186c895661d7089940e50a00270d435a279e"_sha384hash,
      "8ab47709d8b90a626b338ad57b7a9f74180fb275d8a135ef8d68d416976c8aaf8079f338483dee1ba84e41ecf504918f4cb73ffe4ac1923e8096610979bb2b24"_sha512hash,
      "E68E0EEE4E2EB8831B7FE7C28D90F10586C650D4EE044D615C315053"_sha224hash,
      "C18C9F73D8D23FF2A9256746BF9970C0F2D94FCD6F71930B107E56264BD87DEF"_sha256hash,
      "B02CE3F5D90A6A4DB2844573CBDC7E6E178902D80935F6532AC75F5CEDC7754DFDB11351DB2FEFA9972E457AE3EFBD54"_sha384hash,
      "E56392EA0EF66564800DF05570528D6DC70E2CAD39F6835C6B4A3638DE59D7C85D9870015F0791C31A4728B4377290ACCF29FA46035CE73D0F8D8B17D1D10BD4"_sha512hash },
    { "87f2e3f3"_crc32hash, "52dd7e5ab4b40408b7c1e6ecb084f8bd"_md5hash,
      "c3c1b1110adb7c7fd83d4f508e6f44bbe6638339"_sha1hash,
      "bf78c488686709a5eee3bd0f6d2d48f7f1bf29bb15dba07312082198"_sha224hash,
      "258269e964ebc16f24b688df5b78aa6116d15e37486cbcbbb82054cf48bf1f95"_sha256hash,
      "e4b70c95bbab88e17fdf45c5fd60949eba222d87d92a207d22c589bcbec8e58a077d7582420d03ede5d20e3676e31d7f"_sha384hash,
      "472466bb927ec6b3e54a24a7d6e64e0ca83971f8b7b972d7e7db83cf5153bd72a9fe4471884768d9019a6cfc2fe5867883996c9c14e38d5ddfdde3d34391ad6e"_sha512hash,
      "49F6B3842D8F2695123CC61C059C97129FDDFBCCD2C0ED04547FD4C7"_sha224hash,
      "68C7B201FFDEB8C394EB2CEF07AF55913A8C1E91962F849D43369895590FEDC8"_sha256hash,
      "E9C79ED6378496DCE7F4C01876B4B94D05007821B4A3F0035FF72C268EB10E76123F9BA5EC82D06552D18C2E405184F4"_sha384hash,
      "D5C8A8F8C8DE70B4CC6E47ABCB9ED8121CEBF0CE45283F43AE8B0C891C3D1D007FE0B9A263BC39C697E03CC94D42368F71EDDD53F846990C8ACFB265840CA217"_sha512hash },
    { "035abd30"_crc32hash, "e2a71510a93eac869fa17ae4e831bae8"_md5hash,
      "524f2b743ff8d07395ac5e5d384f35be82bdec43"_sha1hash,
      "95c42eb10c9bf7bd5f3f40a0e1bb49db5caddb082fe192326a36b0dd"_sha224hash,
      "277bf15e3b413ad5dd5c5647d28c42e7e3f38c11c7ec9a535c527cebed839996"_sha256hash,
      "1595f961694301ebb876c4ea801042c1b857945e0992f315a2969aab8fb3e6654869b6ef671091fe2451397fee7cc41d"_sha384hash,
      "07076a56be800893e57ba52708b90811aa768fd405602b2a1bc0636e922e209102e8a2100b9310bf32df6f20e546acb204146654b6a76204f92a9875c44b2367"_sha512hash,
      "03F50F7674204020C23A9399A3BCDE34B659B1FA1D2847D66BF94EE3"_sha224hash,
      "E4A43445E918CA7D068657065F301625BA09A0C6716973F5E2AE7784206FC0B9"_sha256hash,
      "F1AABAE30D58144BA7027D86F8E54C7F7F7DC2E61BAD32217C2CBE2F0FB754730A0B5B0E0D7B8E7298C0325A5DE47B7B"_sha384hash,
      "3E64CF827121C132B6CAC9591F8046F04023B8352A22C15A4D7AAF1CC470C6E78DB6DE93D156E432CF6893B5D09A1A57F599F1949379135F171CA3C2D86DD430"_sha512hash },
    { "bce1d042"_crc32hash, "ac424dafa379ba8ca7cdef3ba7c13895"_md5hash,
      "79d730378eaccec325d0c3afeb5c9a62c22db047"_sha1hash,
      "92b02d53366f06a370b05977205affb598f95be62235252666af3146"_sha224hash,
      "9ad64cb89adbcbdbfb4c693c82a3b1a4aeaa6149ab87722e4492cf97ed48286a"_sha256hash,
      "ba2ec451b8092b433477daa4e51a5c9ca2415dc43f05f68c32608a3f2c1950c0aaf55f391cc6e6413c81ad4cc8fefffc"_sha384hash,
      "3284f7f2f53d76138c7762f445df285ee23712a5524bd7322c06140f611041e8800dbd3bef32150350b41b3489198d176dc95c79a74898e22560e5d782ab05e3"_sha512hash,
      "1B6F27F00BAB51CF0A1185ADE457F361992BBDA9BCAB6EE472C45A83"_sha224hash,
      "6A3DAA99640BECAB25780C15BCA4A55BDBACBF4D73D929E0F858BAE7F9E246FD"_sha256hash,
      "EE84CF826C683F37FEC602B8956D61713A626A2388D602544BE9E5AD55FF80B335446F5674939142CC7B81FB91E55F3C"_sha384hash,
      "6AA324764D251A4494E0FE42F2D96530EB0EBEE2F773F95733DAC1469B41734FB6BE2BBE29838C0E98CEFEC16E91EC43341305457C56FC31B1A44FDF45FB7519"_sha512hash },
    { "a6113011"_crc32hash, "1226bc97fba5fcc76b14c9318dea7bc3"_md5hash,
      "593881b29e151c1968083b123d4c6d7220b7d9d9"_sha1hash,
      "603efb9b8cddae61ebd1d6ef06d97638090cd6486883082303bb9c89"_sha224hash,
      "c32b709f3db08315c83e37e3992c558fee64e2ba22aae07b4fbdb11e89d2afb1"_sha256hash,
      "9b2362521aeb59ab6db5f84478a54bc7be4d6c67bd36f6f7cddcb93146093bfe39d34d1c4114f3ddc73744537804b5ba"_sha384hash,
      "dbe7ec7d0ab9b772f8fc122dd6b2e28f57fd0132bae9b2dcc5a8771647cab05f26af37813b87d841d3e52f5d2aebdd6d62412847933ef590645ae3acb855cb7c"_sha512hash,
      "8A607D0673E68653D1C6E27913358031CB692354F1F7075AE19900FB"_sha224hash,
      "3A18F1BFDBAD0CC382F5135E71E533A77893CFDE5582CFF19CF4923D21B213C5"_sha256hash,
      "215920B7456247780214489B7F5E22501348EC9E5DE03218708ADC0ED8EAEFFD8FF6097781136313E11EFC341B16FFFB"_sha384hash,
      "3107A18E2C9F7BC2990977E277876840451B78FBC131C536465A956770A60FDD416AC99F86003517DDF38CBC68ED4C88C7567B4DD597E25182AB7DF6F69EA7E8"_sha512hash },
    { "7652d8b7"_crc32hash, "aaf7935eada1868795125693df975585"_md5hash,
      "6d15e824adf9dbfa227a22a066035d45c7db1a62"_sha1hash,
      "d4439be60b86b43f34552de85d62cf60f4370d52db8822ca200cc5a2"_sha224hash,
      "4121821a93a99518787516782eac1567b57923fde325a4c942d138624fe880d3"_sha256hash,
      "df1d3059cb3e303e403afbe98b4c09146de1c4885b2c79f55fbb66bd148fd4be79f6b839f6c6922b3db99f74a22cbf19"_sha384hash,
      "2dc9b4f0140b48147eaf75cf22e216ac634eadee3c594918f8d41e945db8312af83362724b3b83c99067d9e4addc4c7a0dfb8c946f05cdf852d55828d0d5e6c5"_sha512hash,
      "0EE806311822D28D1CE48D28404BF602C80C2410FA270FE2ECBF74A2"_sha224hash,
      "CB8B5A66E60267C15EB7422B7D6842E872E965D8065B41BB5713189931847BEE"_sha256hash,
      "0A6F20A3394433B2DD3467518BD8E356C56A39592548714FC179143EA90D77C3512BA74901FC2A37F79A288F90BB4BEF"_sha384hash,
      "58860CA9A025F127BD878F3EFDC68C9C6AA0E7CBCFD87479FE40A7ACE6D91E2582700EC66005E113214B49F92C4108F41118E851CAD05C594F6BC531012112B8"_sha512hash },
    { "42005523"_crc32hash, "e200de49c1ea4d5ba15525f3d8d996a7"_md5hash,
      "945d4333545720c470c3c616165d8e8435510ca2"_sha1hash,
      "293eecf321d0bf279b61770ae345b0fc3c7ac6f74e4c509ce769ab5b"_sha224hash,
      "d9d30c9f724b3edd0b1a4633800c1292a8d41b448466576b821ce6274dd2a87e"_sha256hash,
      "5fc9967ed983bc7f521ec164d4581ccbea6ec0746d6bd3d5b808e2f8e227a74b7a70dfbb061590a025dbb1e2ca32b12a"_sha384hash,
      "f2c8d5e9b81ab1c860f3f023a11a0019e7e6735d88cad8ce2b4f915b3410f18bc61358ba0d63cbf563595da847e9f077ac344550c8677ebdbd584bc49af5fae4"_sha512hash,
      "8990F9D47E1AFDE2907D94D5EF61D5545527085742503AC9664B7CD2"_sha224hash,
      "B2893DCAD8A1A256367D8A1AD2F2C3FA6AC718649C4F859DD05E5F25C806510E"_sha256hash,
      "3DD74588FF9FA730AC551DA88A1FA546A8551671672A4BDE3D3D67C65E4E7E6AFD5EFBB1BB4E97EB9CCEA7FDCAA932EB"_sha384hash,
      "55C4770950156701BAEFC3615182B01AFC82E9593469179449709629F869D64110CBBC5E2E89F27302F41AA8A937AE516AF1F3836E91AF3E607ABB0AD148C5D6"_sha512hash },
    { "93740649"_crc32hash, "c442d86851ccbd4eee78cf05e09093cd"_md5hash,
      "401c06774dfed956435d687ef65971e941944217"_sha1hash,
      "14fc35b410971a8b2c6ea2759bf6aec619c55073a41da2ec8a1fb0ef"_sha224hash,
      "7d07c2d2b9d2942228bb70f144129273975bae6956d1b825a2085ea64da489de"_sha256hash,
      "2f89e0d446a9ec8d969b19a0d684d858f42d294c43f254e517127b945a8262682246af2bba473abf5bb538e0edb2c627"_sha384hash,
      "1ed1cc2b06edd6c1c45f06f244a85c791aa1c670537f4b32501acf4d3705b8ca1b9c4b9c511e78d4b284b98826e3c8f105180c23c6253fe932468113ef62bb44"_sha512hash,
      "1D26DFA407FEDF34486A05C7241CCF761D55AE2FB436BB45518C4E7A"_sha224hash,
      "BA82CB97C985F1114E996CB21874DDE95B56CC986B7485C72FE9BD666F2DACE2"_sha256hash,
      "6E56CD202ACC073B3F8B0BEFF844BF8D1874347C37F0CB1BF8FE0FFAA0C270A0CDE3DDC2EFE0B90286D10D119BB95EC6"_sha384hash,
      "3A56B2BA18014F80019B7D1990F9F3290158069E63996EE038CF08551B2900FD50607591C1D2613545A04B086EAD8279F448A5F18B755702559B15447CAC1D8E"_sha512hash },
    { "f55970f3"_crc32hash, "5d65303d5609d6588a3cc9cf38187408"_md5hash,
      "80a8c16124c15b8e3a88c73e9d2de1a65606fe1a"_sha1hash,
      "bd3eef7fcc67c3c9e1f7df0dac340ce7437d1cc8c41ef5bd473c2e4f"_sha224hash,
      "ec6cbe1176613a6e365e9b8fefeace842864c7d7e3d706b27aadfde5d7f3b930"_sha256hash,
      "c46ebd7644cb8bd7c834f27a8759ba330f24dd0a15526add856d37eeb4f09c8495c2f62cb614ae328b03174400de1b9f"_sha384hash,
      "d6e56ec235a19ba59603b9e34f78df6453fa75a2b535eee0ac495ae833342d241375c130bd892f275bf52698a0f4ca34fe2389248be23e4fe52cac09f94d576c"_sha512hash,
      "E187AA5CF10A6786C6343641454BB291EE83990D378A4A49A8CD73E4"_sha224hash,
      "A9DE31945BB7F038F0D079E29272211C1509F7DA4F08F3049DC89F8AFA63D48D"_sha256hash,
      "776B07D3C0C1901AE0CAEF92AD61FCA52EA24933BE83D7F87626E07A7CEFBC08135400FA6C0C13135BCC271C8D08696F"_sha384hash,
      "07398D27FCDBB70D0C651720AD6DDB4889881CBBCBC9C88C4FE31C4520A80CA0D06430B725909FE5C43CE205860D223D949C36B4DC51A56815E964DD3D74ABAC"_sha512hash },
    { "bcc30280"_crc32hash, "cfae4b94aec0755c38d8ca8afcd87ce2"_md5hash,
      "f5143fc32b558f45d0ab490a51c6d49a828a478a"_sha1hash,
      "28d2b6e39b51a039e11a53a81cdffda333481771c29ca1e969d625cc"_sha224hash,
      "1d349866e667dcf16727394266410a0a055b1eb9b4cf0737d996985143b87a1a"_sha256hash,
      "7ad4ac908fce5d2a616635b1bcc2968a5dd752a3c26591a968e0d2bddbc13c0f00fa798e5c2a9c25e3cb710d37a9a25c"_sha384hash,
      "c7100df0af1b58280e147c498a3cb663e76df6f146fdf7679530555ac53e88ccc171b2e7501c646c1bf376d56c08dc9ed8b3723f159d4225facdb51194b7e89d"_sha512hash,
      "C0C925E71729A3B26FB7845CE9E76274FFFD09EBFDAEA53DC7CC6131"_sha224hash,
      "5559CE091E6A5B85962A162E1CFA7F3DFB219550FFF05F56DBF3219361A8CA86"_sha256hash,
      "818A690B41D1874387ACA6C3C023DB5C795BF0BF69B51C97573593DB08E60E4A9171943DF9C45E2872ACCB8E8411D232"_sha384hash,
      "F8596B055F6A6405B192B3BAD5223688B814E93E6E940DF00482D3D75E1C748F4E639E89561A6E05612B0AE872BDDAE915130D5945084B4B9DBE5ACF3FD68138"_sha512hash },
    { "b34e6876"_crc32hash, "d27bb22bbeaf92bc0e188a0109f912ad"_md5hash,
      "8fb853604ab5be17c1609c80b39a356376dabd18"_sha1hash,
      "5c9aad191c31ae2dbf19be444616aa2d52a1583f04c93edfc3b63da8"_sha224hash,
      "4fada1cefe4ca87be9f329059eb59632887952263d5597eb8ee59b55e63f4b80"_sha256hash,
      "6dd897845a7370fc6143761cd07feacf3a98292e2ba8c766d104f3ea25324ba7392ac144852c20155f8d3ed3b6cb1fc7"_sha384hash,
      "0e9bdeb6ca7c735d053915e3ec7935387dc8a1f4cc068d5f36b5fe2a367cf408770b37bd51f025b0b0d89c3d4ea09271a6419a320bcf132bdeee98477d9e43aa"_sha512hash,
      "21AC2A0B8F74181C4C4BE9EEFA6565D92AAEBA69326BA5DE8C035899"_sha224hash,
      "7C2829E51B4102589CE9A75A1CF7DA58A858B3C48D64806B9B814327AEF0EA5D"_sha256hash,
      "D45EE174E85114E2944AAC6A4C90ED46EFE91FA5650A86A8940CCF5E082E2EECAAC14D68C2E001688BB404D7217AA8B1"_sha384hash,
      "7A3CE96C68A96F1AF1B28D4C104AD2349405D05BB09850001437B4FFAF96EBD80F5AA1C3A755CE6F6960D9DE070EDF63D693EC170D3A1385FEB0030419425C4D"_sha512hash },
    { "e5ea203d"_crc32hash, "4d778b35ad841642a654ecd35dced827"_md5hash,
      "f2ea3d79263c1d2629b756ec5e84035227ecbaad"_sha1hash,
      "70e13b39ea0e567b66c0e80894d3ac39097bf59dea45aaed0e3d34a2"_sha224hash,
      "04c973b682b84507dee481686756e918408c84b5149c09ceeb23af302508c163"_sha256hash,
      "3cfb4224c3ef46316dace9af9b8fc466b68c67d918d02c1e05c1f7064ffdfdb2efb4b966b77b3d55deb0966b4f17e517"_sha384hash,
      "2334e6b59193a418d08c8a4850c8190aecf6a9244e476524a77ade77a1f2c3654c46f65ea945ce3eb4b4a5605404d2fb3b095611e9056a95cd4bc4972aa688c5"_sha512hash,
      "8AE15D90F4367F23FC7FF4C40E8D0C32880E213726F06A177AAD8A14"_sha224hash,
      "72121777B3BE0E14BBC47A53ACC105209033FAEF451FE9E7D47DFE38BBAFDE22"_sha256hash,
      "ACC846BC6C930B3275749F027A7723C9646761D294D812CF496965F5692807BDD99962F1FE5BD9071187ACA28135BEB7"_sha384hash,
      "06B4B148F702617164D7064D73793733AA65B46FA60087EEF17D7C0DF2B01C846ACE1741C0F4F95F1E2996BEEA68786CBC32ACF07F0B413761682D3C1DB4EB2B"_sha512hash },
    { "91a27272"_crc32hash, "75517656a73fcb4d9768e68af03aec59"_md5hash,
      "63dc03c6400ee63377bd02adf3f0f078548a3595"_sha1hash,
      "005c06e3a8faeab1cde2ec293cfb3b8033714d2e42ddab88503c7020"_sha224hash,
      "3988a390034e03b2c7603f2954d32ae3a26c589f4e376ce01de2cef51cb8353c"_sha256hash,
      "9abccec053f112619aeab0de521bb9d76b949923e83a55719bddbe2721777437270f3ebae70177bf4ddb778b37948b13"_sha384hash,
      "a9477e4dc7ce9c5334cf4eb2cd9731f1eccd7053657decf92e9bd91ed1d561abfc93566ba5f73811b63957d7712c3bd54b4c6a969995a45bf5a65ec0625f3e23"_sha512hash,
      "38D6FB2EE6E2B726E95238683B9F8ACDF31140F11507DE027E862841"_sha224hash,
      "6C10E6E7106D7D35968AF0A641D89C65733EE4DBEF61EFFF406C456775798E1A"_sha256hash,
      "E97A89997536F1D651F9FD0E21C99460728A37EDE04A63A2F3BA0896FDA0A8EDDBE86970A83A366342769F44692EC1ED"_sha384hash,
      "0ADEB53658F714F875C3C09ABAC46CA79463CA81D36DA38381BBA743AD87570BCC59C33504BD0D5CB399FD83DA31B159B8C6F8E5FEB76EF8515D70F18CA20C68"_sha512hash },
    { "83548757"_crc32hash, "203e7732728ab2ad086aa50a739fd82a"_md5hash,
      "cae167281aa1b1fd3ac7d60f82ee26f7633d5a95"_sha1hash,
      "e1fd555507e1a0f3a6894fe34ea4e6e1fd8991638b27d44a291191ac"_sha224hash,
      "9dc196ebf8055a23c14ca20f325f50e4d368c47be3eb56d14db120a6e943c14a"_sha256hash,
      "986be438174541c0a7e5d9eaca82bb710e10699a7eb5a308ef370552256896cd770517042e9d2c7b09cb02b99c9b4804"_sha384hash,
      "6e453b3423102963ae3cf92a46c422944a69f8a1487cd58c0964bfed8fcf709bd2337c56f4bcf9e9ea7482bf362c7d425284b423847c2f9e90b118cfb7711911"_sha512hash,
      "F275B8B07D7EC4A45DC60353CA124074222FC503FFE0DD1B4A69CF09"_sha224hash,
      "FD682CE8E8C664079B0CD1E99BEBFA6B69105FAF72FA6A344A17C3C03AF2585D"_sha256hash,
      "D0AF6D681CCA4831BC20D76CC6DD344DC166D2CCB3B30C3C4DF2E49C0DB9FD2A26125A64D6941CE8ECD115C9CE1D1E03"_sha384hash,
      "531F037AF6A72FCC245A08D6054A13835DA2AD842A344E7634723D96C70A6095B36A4C4EBF0D39DDAD694E2CE9279281114D5E4F04F5BE19C8C1A8151FB3E5A9"_sha512hash },
    { "891ee979"_crc32hash, "a2758bbea3f3c059a1850f71183149ec"_md5hash,
      "11b1b5fc585babc230d610b2ef6280b5901159d9"_sha1hash,
      "a9a9d1ebc66a56dde5a62242a2f16ecfbaa7bc6839edfce381a8517d"_sha224hash,
      "104a659a8b6338ca22861f230badd93af4ead8d9f4be6fd236cce00ed37a8f61"_sha256hash,
      "cbd5f1e25319b50859915efafb287dc8206e7f40dfe4d2ea96816fa2cac10c9accb2b0bc0881fc7fd1c2310091b75da9"_sha384hash,
      "5aced664bfc0912bdb3a410756a7649306348b606a5dff6b05e62fa602c40dea9c36d060f29997f88cf6e0e5d50a6b8e344f40efe4d649feb144d57e91ac130c"_sha512hash,
      "2144FB430FC9F97885C0CF26A2CEADA86F4CB36A0A3A8C9DCEB890A7"_sha224hash,
      "474CF87407030D5480F34FDB74C8FFD2B364CB46B2FC0C65894C273D539EE589"_sha256hash,
      "472F5613E4C63A178459DD12802C2340C41D71428A4B41B20D22A96290E54839AD7E810CB1A7732F0D740305942CB3BD"_sha384hash,
      "3DF3A73CA6EC0A4EE423440B2F4DD9FA0F241E7585713E94AB6FDA417335D98B8C50DDFCA612C8C37C5823676D76BB195BC08B174FFA0902489ACFBB078A4B0C"_sha512hash },
    { "f2abb80b"_crc32hash, "937eec3072ed7343acd44d9c281cd2d7"_md5hash,
      "4d1b997a2d8c36561cce21a3dd27ec273fddf29b"_sha1hash,
      "7bf59b2164c7e07e92f80e681a6f2480b23426ecb8f961c947cba4e5"_sha224hash,
      "00f780008a3e572f60dd26fe7cef23df638616ac0830af41d26a753d9932f9cb"_sha256hash,
      "b11450a85463d94336f29f5551bc17a736d8a4035bfff5cc22714289aec81bf434c2fd31e335b157b3c9de74f6e92745"_sha384hash,
      "499eafe8648d3d28ed3c830ba47c46295d1a04ac6b7e58f802eb5d1dcc14b0bf8aa04b75dbd4b1561e7058e248615c0506bc9ba375324f4a921ee454e5a990e9"_sha512hash,
      "7A174A2CEF4B47723F1C0CA7E3255BC36D9502CDB20B5E872C2F2725"_sha224hash,
      "A061FF0A6DF42324731F5920A6FFBA75D08E496C120BA5077BE414D28CCFE163"_sha256hash,
      "093F020D77DE4B74E01EF1B18E1A1B0E762732BC49413DFFBB2D9DBC4E293932213BDA73F4BAFC5C8FA0E3F12409D29B"_sha384hash,
      "0E1A815CD5BCAD928F4A3940F5349895774679EA3172BDE6669412AAC23CF7CCB7717249B102F3AAC0896B6E0F8BF66DC7F08876F20718C60BD20FB0F11245A8"_sha512hash },
    { "00fc6823"_crc32hash, "b5f60307b7898e4372c838a379f42733"_md5hash,
      "0d66982b0c81ebe0d0263d81391ebe8e9cf2b7d7"_sha1hash,
      "216ad707c2d9846945381da4fcac10adb48d9b29d82578e7b688f66c"_sha224hash,
      "fd8a4d58f629ca3b3dd2a603b37eee2178a09f17b29da8bf854c9ffac506c70a"_sha256hash,
      "7a94aea60018b3bf4fec18b5f62fc2d53394b1b52a7c126a906e7bb16d41fc3b62f5ff431a32766a9c45e781401acfa9"_sha384hash,
      "0d840064d817b91fd7c7dedb3deeb5b9c2f8a8b7b3717123d5354328e4b704007f87909f336727e63c8161d04996a8d3b3c832546f244223eb66671589ba5cf3"_sha512hash,
      "215AD19B109C047004C06E130C9C905B39913E50327ECCDBA72D7597"_sha224hash,
      "4D7A97CAB0B1276246EA93ED71865414B4ACD5BF6E1EA926724772B20DA8D036"_sha256hash,
      "34C238EE554CA6D9D74D10D02DA87CAE93FB5A83639D3BEBD0F77BF60C9AAA0BE3FE7D4D2B406D6C0ACD3DCD121268DE"_sha384hash,
      "DD142669665835AAD503ECE8DA58AA935E21F0283317A538A48EC42D5ACF6166E77A0B8066F466B765AFDC502C803E6D5A759D5ADE0243127415D307399CF884"_sha512hash },
    { "a73b3d70"_crc32hash, "3b11aee4f7272cebadbdd9c58aacae39"_md5hash,
      "7017b30060cc52213b80ad8948fd9c9a208356d1"_sha1hash,
      "473e1c654bb9f1e68e95074d3a817e6325937f756acba6db6820326c"_sha224hash,
      "374d22d9d844ceaa117c140f4fec81c917be7d0a242b494ec6f29e5ff42c4f16"_sha256hash,
      "57080c5d83eef1f2a2a126c82f0bd699207898e60e9495eadc37b1c4c3a060ba3e61719154ce9619568560e847979da6"_sha384hash,
      "555daf020420902dbe6d6f292988a8ca20c962f64639f43775d4aaf18819ca0645dc078e60b37a38223b19ccb84ef440fa3566e961961bf5d62b0d1a8e300352"_sha512hash,
      "061730000F26C77E648BEC05BFE7C62B56E0F929DE17423EB0C6EEED"_sha224hash,
      "687FD4350FC85D7D31E533EE868198F13C7C62782791C10FA9B252B0E1AD304B"_sha256hash,
      "63D54D57E8A531AD6D54FEF3E025D1FED9E52C0565B3C5A59E27360E6CD11FE448407E2F8889E78559D5A9767EF425D7"_sha384hash,
      "2470B1F01BA0ABA727DD1077A629433A0AF40847C6649231DBFC6239F9AF146BF744445933ABF8C0F53CE8388A80A0701A964BFE4354E70F66E96BA838CDF1C5"_sha512hash },
    { "caeedb83"_crc32hash, "0a38fa543233640eebbfcf5d535812de"_md5hash,
      "8b7db445e6e39dd4f7147b23c8bbed6914b79354"_sha1hash,
      "36ee668a4a6f909427264cae211d43b53fed17bd6f4a2895caf991b9"_sha224hash,
      "f53361f4222da4a930591b5685afc86267fee32c71c745644dc3971ffb0dfcdb"_sha256hash,
      "16150c525ac1a4521f57efe56aeaee88611d39e0c60293c20303a9dcd9ce1d605f02d44331318ebd555f36919d0bf4be"_sha384hash,
      "77b15ff26cca3c7e67480a406dff2c8cdfcdda9b75492c0ed5dc523467fa8ca45f19c2aa7f5d013a96e166b4529b08b4f8f27e18988464285dc9b3f7812f2f61"_sha512hash,
      "DC31035B1226F3C38677365D0DD84104BDC88126C766C47D815814A8"_sha224hash,
      "6B01C7B8F78B6A1E3D4533F93A2FB05BCC2024FE8F077D4C49B36AF5F3B54D41"_sha256hash,
      "3D4B44950F4A74F439E38EB5B9DCB627BEBAC4BCD3D8C749B21FFA212ABC9E967D3A06064C9FC1891FBE26F98A50DA40"_sha384hash,
      "BF4CD8900E5A5217DBA423EBD7AD80F6F1915A24BD0037331EA33F23AA33AFB77F1224672422761C4FECEC9A4BA9289D43D0FDCE5AB68BF46E3E46D645A67064"_sha512hash },
    { "eeaaa137"_crc32hash, "ca36a1163dade565cc017587589a4970"_md5hash,
      "a5d6f7e3bc753b5d1a9831e6206d095acffcb3ed"_sha1hash,
      "b95a05c916a26280f7103b745761ac86619df5bd7c0c8b6073e5fbbb"_sha224hash,
      "5a140fab9ce861041340ee61744c19346580ade8e4a05c67d21f5ec698bf7ad5"_sha256hash,
      "d99cec295c8ee8052366c66bdf45defad3e1b3eb0e6036cde9b0ca9afbd3e1aa9e9311c1aaa0df50853d5986f74228dc"_sha384hash,
      "1ec5e4cc9418e1ed23433d891398b16184a462c39829b032aceb479a23bf6b9fc61354e1d83d7deb308c5e7694dcfa78c67e1a59a8daa88edc1aa1bd9254533f"_sha512hash,
      "F85C683963FA1BFF82BA79F7AF0AB77059B1A8AC817E7712BE2B5438"_sha224hash,
      "D6843F0500D8D47BFE87BBCF5537BF09209D0FAC0EC8E6204C763E3837B73F8E"_sha256hash,
      "93A5FF9BD10BC33AEAC4B5B14ADF434E4F485B576D8FED8ED371E5F8AB799ADE3B10F20A251C2B3B49ABE82852D5D2E3"_sha384hash,
      "92C2EA9B7A183E3E920FD9593E018948AD656BEE46A95B2F5638B98841630F89F642FE15EBD93DA3BD313E566A3200C146EC2EDF0CF791F7E50DE30B6838DFB3"_sha512hash },
    { "b9af838f"_crc32hash, "2b7d7dc535b33b28b244e093bb9c0866"_md5hash,
      "fc1dbe30c36d1192b420f5a8303d14e8a5a04498"_sha1hash,
      "1ffa27a9bd5028a73a7c57fc3c40b7c9061a6ff5c739109952d3e416"_sha224hash,
      "44cc0067fc92a7f242ebbb5b74362e3bd86e9eb2230f5d09db7845af075b40fa"_sha256hash,
      "c5130d46c3b558a3875e5eaa0e1e81f3dae7e8a6afbd6764bd9f78c1ca504f4ce379431808c4abaaaa38878bd14a36b3"_sha384hash,
      "e24779f3975b7abf09453c84c83744fbc24d891ea0d1e361e2542f9141ee7ec4ee158f00811a6a4ba2ec989445a11d4b9ea5263dce9880b4fabe13681d0d9bf7"_sha512hash,
      "41A3D2922B7831F461A877B13A01792295CD7148E37E51337164DFC2"_sha224hash,
      "6027160A7EC0EC3334C4C04EFDAD66480B050E2962228F8A235D8853A40DD3CA"_sha256hash,
      "4987A2724E54E21B77FFD766374CE8CAF9D2D11554F28B2BB6BBD3FD6B703B0D5EC85278043A7C0341C0D58179B6F638"_sha384hash,
      "02E037416804AB028C602ADAA55D828E82CD452BA12F39CB0B702FDEADEDEB8EEEED5189F1BB06D6EE1F5EBABA9D77F3B676AC7990F75D579D21E1C44AF4A95A"_sha512hash },
    { "192f46e0"_crc32hash, "e91edefa3d755fdadbde18705ad07b87"_md5hash,
      "0c17ab0ecc5d097c6c325f7608794d46ff64133f"_sha1hash,
      "c184418cb3285e84dd71c8244cd50597d86cefaa168f782b127b20c5"_sha224hash,
      "c5d2edd7ac44758bc20c9457eb7d0a37e94c3027c568faba4abb73d58f346958"_sha256hash,
      "c6843a9108f00d71c8b4304bb5ad8fd81f7066ed0198f44341fd0208591ddb0ddabc493b39c019e19259478d2006e5ea"_sha384hash,
      "83075a77b6f52770b88cac2dc7d1cc1c16ea60bcaea8720b13288b32ce17e8f7e38f85ee966e44ec7124ebbfe46555f6a684909e39701322d91bc85a488a253e"_sha512hash,
      "A237E96215C4A24E7B549D8B412AF925CF91A568507919A62C4A147F"_sha224hash,
      "98328F5127BF2FC7AB4101DD9857BAFEE576545C9AA3F4B6F04531649007105B"_sha256hash,
      "DE89EFC4865B240F50C75F047B731E42547BCF6439D0BF97222F6C9FCE1A0E7A2ECD3D9671672289098C00F04DE85ED9"_sha384hash,
      "10490C3E3F2D1FCACC1D71D58DB9AD754B2D8A95E1979F214C5450EE203F7D8C05889EBCEBF994DC88B125FC390EF86BE1A2537FF54CF7D3F4D1944309355A9A"_sha512hash },
    { "cb57b7d6"_crc32hash, "976934a50bccb627855bd9739194bf55"_md5hash,
      "6da53b45b430ded24cd5c0200c6d4aad9b0317d1"_sha1hash,
      "af8da676cd2a3d127b947bab5768210843182bf29388e38f4d7091d5"_sha224hash,
      "3298f0dbc53df5027dadc941a0ca9311366597a5eea9826100f562ceba150385"_sha256hash,
      "0bebf1b9b87b34c3d65084c18cf49c5eaad81e186ef4fb5e94ea523b52ab541d89698f03173ed0f93fdad8495222baa4"_sha384hash,
      "97594c938e61395ca4ac6700fb4622fec759a866ece3fd415378004a20f39e1113c1b7ca55941060cb5490c344d1f89c98ac1c61836d9e2a0bf80607b88690c5"_sha512hash,
      "865B75C071AC8C2910BD80E1473C68B69F7BEBACE3B28B4DF5AC1A8E"_sha224hash,
      "D0B324A26A913D41F57760A7F6AAC4DCCBF748C5E0F7996BAA090C0B874E7B4B"_sha256hash,
      "79A1837A863D6376CF6E188313AF637FC15BC669C336795509FAD88DF17AD9914E6C31DFBC7B04639E9F32B7C8A28850"_sha384hash,
      "140593B0A160C21111A84AD55AD7C1E8D6EA40C1DC653B068914513EB06C0162B5F53E88CEF31AA7EEB8B10062C9E0E9CE1917AC4185F0E74D55B8C975251E60"_sha512hash },
    { "8c5b31af"_crc32hash, "1c3afcedc386f1149a1862cad16c8982"_md5hash,
      "f44f8e3caca876f2d434ba3860213a02a4c5044f"_sha1hash,
      "297fbab081bfd8ca9bdf80b8b3f130590e6d5fdbfe4d43face806eaf"_sha224hash,
      "25dc3825ca13a2941ca8e06c293ef689c844811d686ed7f229d792123efdaefd"_sha256hash,
      "3f6846bb5a39bef420be695f14af8af086c02d1ee0b49c13f390c1a0a63efb165f96d764e0271704b6e7429d04b46f6f"_sha384hash,
      "6d0c37bdd8192c3a50a963b4fdd65b223f7298a99461130d5a2fe4af3d6b5808cc620b99d5496de54418d167be54561bee47878d134b0137dd55e7b91255f359"_sha512hash,
      "25795C0FC5C1DDD796EF6F7F4B39171AADAFAD402104582B43A57BEF"_sha224hash,
      "A2A4AD1B9ED742306CB8BEAED71A1A7B8373ECCF1299AD35D4CA512265E67429"_sha256hash,
      "1BFD64E8189B1D838071D2865591FDBA407E9EAB4D25E0C485A85A71B4165E3CE9071133860988D60FA8A2B793714D33"_sha384hash,
      "6CA435043A9DDAE4FAEF874460040299A495B0291578C81E9AB52D55D1B80F86B8A900451596A0E1DBB7DF85574BE9EED578007A3D2E30FCE9390FF834BA6DC7"_sha512hash },
    { "3bd94026"_crc32hash, "569e1d7e974437beccc26605572ef43c"_md5hash,
      "3bc775351b8bb3cc0324a7f55c096decf8d06501"_sha1hash,
      "d6c5499fffd8c540089943febaaba924335acd101bc503e52211f9da"_sha224hash,
      "5dc30e52f13cc035030d442993120448fe89d3a9fe3460a64d8aeb3ead0ae2c1"_sha256hash,
      "8fd02001c6aed56f2e44b7bbb336490f231f8d6571b790bf682cf1511984ea72caabf23729c9b09ae6bda5fc6e1104bf"_sha384hash,
      "2f5ff31675cca7b38feb5ef02e76e22dfdd0c92cb58e70ff650823e454912ccc08002123f7d804dea339d5ceab05d9ecbd0c69a1bee8ba5e558c5f74f2389869"_sha512hash,
      "6C965BE157472A1B51EEBBA75B9F9127370C48DACC53F4109ED16F30"_sha224hash,
      "B4B85CC9ABACC0F3364FAE5C943E817D0D146DE795E81E2F8CCF26C18A0DB5D1"_sha256hash,
      "E2B81BF0709F972ED1EB17D4695E65844C1C0CED5EE0D0E12B67160112094CDA15E94151F8A2BAEE3BD2553675FAA848"_sha384hash,
      "2E43E6AF553F515B3CF5344C16C3ED880A54F747D322AA7CA9F2BC116E7EF96686276324D9FF3F557EF1AD14EC0E7EE43CAEFE266F2B634875D5AEEADA962E1C"_sha512hash },
    { "a5987a8a"_crc32hash, "3395cef3c8944b192a39de1c9b88285a"_md5hash,
      "9d1184ffea53fb49135bcdabcbbe0ca8928d2d4e"_sha1hash,
      "d6fa879190812a78e5ea1b21f0916d9995ad606b2cb5b9cf25545389"_sha224hash,
      "903ed14acb0cfd8045ed72e95894bcebd7a9be8e586c7799e9acfdeaa2a0c5b3"_sha256hash,
      "79573405507f48158dd2e5433f2a713f74e15867d8b2090dad347ab97e16b8e03e852a179b2adbe91a5622610185b493"_sha384hash,
      "e19cc0545a6942e4aa0d5db41a2d8fd70a280c72e66d7039c8caee5d04de9535f6794774956cd2bec70b34e6b345709b337deb644bfb9cb76110b0f18b659c7f"_sha512hash,
      "696B26045A6A7521DBC1C5A9CB3595950A4F997E7DBE99029C6784BD"_sha224hash,
      "DE747D7AA10CB92866C88F9E441A36A838F984AD3479AC4F1D72C19E9FD912B7"_sha256hash,
      "9DC1FECE211C77D3E8B5462A7DD1D2D086AB9154609E7D5CCBB0C70DE65B2C44FA6DF570D190D21DDEFABC3237E1C26C"_sha384hash,
      "089133511E4FD892737732A801B1750DB1F36B45B5E2AC636899C33794722453A9D020DCB0E9B5575C2184A27303C80A267482A6266825B04609E0FF6BC36008"_sha512hash },
    { "fbf15b09"_crc32hash, "a2a5904baec7762004e0b72f9a2fdfbf"_md5hash,
      "d99c724e1d197305ae15c9d09599ffd1a9d015f6"_sha1hash,
      "eb61d2d49ade214ce03628d537a5cda2dddc88b1b4379ccce0e43a03"_sha224hash,
      "98fffccf61a1ccbe73efbd3c0f11f3676043cbb85702405c544ef01e0276ca99"_sha256hash,
      "b91c252de1070dbd4072dc705fadf32efa210f935a5623b4fc4afc992964d333a8550b840c53c2a01a5f9034f814c8fb"_sha384hash,
      "1eaae1c9bfdbfc5c7cecaab5ddde82199965ba42968841e06bd393859dd66959db9dbcab6826ca96b9645a914e9238704ce51fcb3cc57419c8f359b76e8e367d"_sha512hash,
      "9E6B79DA18767E8AE696559E4F1A9F7A3193616A658536DC91C30392"_sha224hash,
      "428040EA667D2C776DB6ABE0DAFA8944ECF338EC9CA7931CEAE14719190022FB"_sha256hash,
      "F08D17CD4351E21D5B1405F7752364343ADACE907567F0B4D0B7CB5AEE85DCC67CD6E4C27169443AA52B9D805EF46A1C"_sha384hash,
      "60085A81F48A4CF0B1BE39E29D8E8D094FDA54455D4516727AB14372AD2E271457A3F8FDA72D3614D5AD236B00A017ACE91441CF3EE1C5D3CBBB4E9B06B03687"_sha512hash },
    { "72b46fba"_crc32hash, "3c15c0a45fa0ffc40657f7eed58d62cb"_md5hash,
      "dc196883e3d2e34ee9d11010f3d2424b822fa2c9"_sha1hash,
      "ebb74bc424815b357961262541b26c85ddfcc4df887d1aa6f35a2b6b"_sha224hash,
      "517ca17c0f324b1b2c33c78ce1e5155ad44a604bb7581f26dfc5c775884a3f31"_sha256hash,
      "fbe83dc69a3c372feaf3fbc511a9bd0ae13ee3d084692e3fd052af2a18bf47ed01c787b5a9734c92a7cda36cfcbb7e77"_sha384hash,
      "6751b8621ffdafd9d73e360816cbeb4ee2dc46c04abe806f1528be733945873b7e84f71b505c69d563e0fd136bb8b483bfad133df7d9114e0045bc086e9527b4"_sha512hash,
      "2B1F2BD626FBD33710E33E56D08C6B9F213625EF04550C53390F9C89"_sha224hash,
      "22ACE7548784EA714157F4362FEADF7C236A981C9DBE5F1B3017BD508800AC7C"_sha256hash,
      "CD366DF31997C28573874963CDFF6D88DAA02AE38C5B2E360E844E3D5F3D4A8F73902B01E8537F7D31AB8050D0CDCAF0"_sha384hash,
      "C95545E9917992608FC84EA083319F761D8B6859D1278713DAE7206592E3946DD695A87BF060E29B768891C35C87F0E756D42A758998631D04FCA811CE755925"_sha512hash },
    { "96697a63"_crc32hash, "0ae75fbe754bcc55d1c5b34d9da4aee2"_md5hash,
      "4048757bac0cd14e68ca495aa11c17d81d958892"_sha1hash,
      "d6a82dc7ad4c9b40c7766963d9e314259c35152bda1567830aa0a3f7"_sha224hash,
      "2e3a6a02eae0cd6ff5a5bba3cfb5cc12da41dcf227b6b20f8ab8ef0fdbafaaf5"_sha256hash,
      "4c17d3e44a191add2dc761a275175b579204a9b9efc0da78d5936aa487e99eb77a67dd1903f212276518723021e632fb"_sha384hash,
      "541b4c33a7caf4ddd2aea3928ac2295d8838ba71ff9ab772761593ca64dcb056e269a08c6287c7e127ef9c224d9226171b1f3a06f7d432804f650cbbef65e203"_sha512hash,
      "DBF60B224F7321534EDC489BC78336F957991A288C743D92E4938D8E"_sha224hash,
      "5DBE4912A2C0633F82D2F279B587AEC2F2FAC886E6BA009FDAEB3024CF0B2BAD"_sha256hash,
      "5C2C783861718E6C99CDE8A2FB71A4A316BC49FBBA3B283EA2316E52047190FA2F02C48BCED0AE7C4268E6B2D4B193E1"_sha384hash,
      "010C793C6CE4FA034432D6C29FAE91A6BDD372F4BB722893300EDA888B19B12E2EE1C109AC831E22F2E1490BB586C9795165681A0AB2B93550561A421024C16C"_sha512hash },
    { "be7ff1b9"_crc32hash, "c76d791ddb256ba72cecc47d57415517"_md5hash,
      "baa1ca69a90f0095f9450298315040f1650abeb6"_sha1hash,
      "ed761f3af88b54d6a9c4c6310904a75a9da91206f321e701651e4ee1"_sha224hash,
      "f7c374ad7641a5f07a918f6d3430cd38ae5a4628a7c4cc622929538c55f20364"_sha256hash,
      "5301ce3ec3b7b695d642d5744891c15c6c96bc1445448289ae79c5ef0a759317718b2a3fb3506db1ebb0a94eb122d3fa"_sha384hash,
      "71a7dd762c8533aab0eef4fdec4e27a1b9c5dafd9fbc23c78771e63378c61fa532da341c8004aff497c424485fde50edd07d4a90bee8af769c4b3f387b0944a6"_sha512hash,
      "6840B8352B3EFD5F413E024D36306FF0AD505339840F2596BCA423F2"_sha224hash,
      "5260E1BBBF12E6125DD627B195A5C68742B97BBAF32CA62B713D7CB7E9F41AB7"_sha256hash,
      "13B784E6361BF38EE8FF3669833641CCF603D6A9DDC9377C453BFDB9A054F5FC73F4F15E81125E82FE9FC701B45A8056"_sha384hash,
      "0A42FD1FF47D9C4F0F93A728C75D11653B76643A005679967F7D7F8C25B5839C1155A429EF4B11772568FFCA1A033D956766942B7051633D5AA6D1F145079000"_sha512hash },
    { "773a8c4f"_crc32hash, "023c3b711903e56bf823d64bb994aedc"_md5hash,
      "f158083117a2101498ad777506bd4acf589c77c3"_sha1hash,
      "50d55da0acefcd21de7ade169d73b46c9c9cf9e0f16442d341543250"_sha224hash,
      "ae9ae297e737c17e7101eb60cff791d8dde0a5b3dd7012fbc333c773da4053eb"_sha256hash,
      "ff9f53e4d306987520c8f5960b7806fb30a7fc789eefaf33bc68c25bea75d03c5e6c91a8d9b2b79b64124aaf59e0535d"_sha384hash,
      "991b944dedf16eec6d50309f87e0baa85356b3b85dfcee534789b352ca182a1e98e28432a3512a8cbb3e82855076953c03b2777827abee9901e6d073d24e1ea2"_sha512hash,
      "EFF80365D3E7DA9408AE00CC273F5203065510338498976F963AC191"_sha224hash,
      "697A820B46934BDF950CD40D3DD5A48DFC4BFAF4125D713A8965D9F6273DB2F4"_sha256hash,
      "C4E682FE5638C5D0725B4168B0781CC7F000AEC83A27A611BF8DB600AD440B17EF0647F5129AF786CD2375F693774616"_sha384hash,
      "F61B3A2AEDD6E469F1700F0434D3C4A60D1D9CBB141BE129A9971C4082649A9CD540EAF55188822D03E8B70D9613CFD76DD8236439EEE7E79FE6BB4317C81F30"_sha512hash },
    { "aa694fd6"_crc32hash, "939dbdabe253ef36a91191514fa1e035"_md5hash,
      "3640a63ec0a4d5ec83b7cba3bda77b8239522731"_sha1hash,
      "6376ca10562b197febf37ae8f2edd5db530cd000ed5279e1b0f68515"_sha224hash,
      "d6497b2577810a82e050344d977d8dc645b6f0a0ec2e497f12ccc3273cfb8b40"_sha256hash,
      "62db74cd6d18101ee6cbce71b16c83821343a9e348996b08b757fb1f9586f85770d180ddb9e110bb04f77a2da0ec33ed"_sha384hash,
      "06bc086c9ef56519834919a02aabb65bd14ee1f313fe569ea32cf10736f3f78e901311bb46b3cdd2aa04d81c6e19d869dc5ec7083eb18516dc3b7bd68c32729b"_sha512hash,
      "1288D77C83511847F16D4240688B70C0CFDF7538E65A14A7831D7241"_sha224hash,
      "D5BEA8104ED1EC85E282B800354672F8E8EDAC380E23F53E84E8C9287791CE1B"_sha256hash,
      "EF39E2460DC4369068ABCE85E696BD4204CBDB4786E6D39DEEFDFC53CFE6AF4FC1AF90354AE604708F14A459BF554F06"_sha384hash,
      "558DB8C075AE659DEEDCCAD8F7EBF225865FBEFB1492A858FD0AB7657AFE1EEF11FBE0F9BBE191322F73ECB4CA36C3583AD2CD88B8869F502BE3A884315C5A77"_sha512hash },
    { "2a5b5e82"_crc32hash, "4519692f6c47f6465336c54c29a6801c"_md5hash,
      "8345ec118b4677f6e502cb13b6876c9ca1efcee7"_sha1hash,
      "b0a33b029a5ec94b176f5eb11b0684a1d750c8a076e53076ba238a98"_sha224hash,
      "d8ec80b2f96dd3bdc46753158c1e14cc25e8527010975f72fbc96e2f3688f26c"_sha256hash,
      "c2d4934bd821a398030eb8ad9b503b92dc80d1e4e6fff8add3b6bf4b1370ce57c7babc2e1d2608fb8693160d7ec7824e"_sha384hash,
      "51e0ab9439c9e3684787f2d8228397f9c45a9239684b7c3d476ac85574fedfc57ad037182dd4053df4c1eebb0516fd96eb3b5fa1cbca16032f27762db9bfb351"_sha512hash,
      "2EAD12F35297ED175311A029FC536A5171AB3FF523E1C4091281E328"_sha224hash,
      "47C45AA65D59C3FA1EB25D17EDC6C0585269D5DFFAD848624185DB5512B23E1A"_sha256hash,
      "9690E47EB87BC3FF841163F920048E30F4774C470802DC69B4AD926725F8D7E97772EB583D7F743AC1DF646014F66471"_sha384hash,
      "CF994346046877393AB53DEE6B233E5F86C762671185B221DC7275837666F9A8970796763D69344EB56C13C25FAEF944C05B571134CB11AFC904DB5A965A12A9"_sha512hash },
};
#endif
