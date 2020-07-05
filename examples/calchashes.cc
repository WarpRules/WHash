#include "../WHash_crc32.hh"
#include "../WHash_md5.hh"
#include "../WHash_sha1.hh"
#include "../WHash_sha224.hh"
#include "../WHash_sha256.hh"
#include "../WHash_sha384.hh"
#include "../WHash_sha512.hh"
#include "../WHash_sha3.hh"
#include <cstdio>

static void printHash(const char* name, const unsigned char* hash, unsigned hashLength)
{
    std::printf("%s: ", name);
    for(unsigned i = 0; i < hashLength; ++i)
        std::printf("%02X", hash[i]);
    std::printf("\n");
}

int main(int argc, char** argv)
{
    const unsigned kBufferSize = 32768;

    unsigned char inputBuffer[kBufferSize];
    WHash::CRC32 hasher1;
    WHash::MD5 hasher2;
    WHash::SHA1 hasher3;
    WHash::SHA224 hasher4;
    WHash::SHA256 hasher5;
    WHash::SHA384 hasher6;
    WHash::SHA512 hasher7;
    WHash::SHA3_224 hasher8;
    WHash::SHA3_256 hasher9;
    WHash::SHA3_384 hasher10;
    WHash::SHA3_512 hasher11;

    std::FILE* inFile = argc < 2 ? stdin : std::fopen(argv[1], "rb");
    if(!inFile) { std::perror(argv[1]); return 1; }

    while(true)
    {
        const std::size_t amount = std::fread(inputBuffer, 1, kBufferSize, inFile);
        if(!amount) break;
        hasher1.update(inputBuffer, amount);
        hasher2.update(inputBuffer, amount);
        hasher3.update(inputBuffer, amount);
        hasher4.update(inputBuffer, amount);
        hasher5.update(inputBuffer, amount);
        hasher6.update(inputBuffer, amount);
        hasher7.update(inputBuffer, amount);
        hasher8.update(inputBuffer, amount);
        hasher9.update(inputBuffer, amount);
        hasher10.update(inputBuffer, amount);
        hasher11.update(inputBuffer, amount);
    }

    std::fclose(inFile);
    printHash("CRC32", hasher1.finish(), hasher1.kDigestBytes);
    printHash("MD5", hasher2.finish(), hasher2.kDigestBytes);
    printHash("SHA1", hasher3.finish(), hasher3.kDigestBytes);
    printHash("SHA224", hasher4.finish(), hasher4.kDigestBytes);
    printHash("SHA256", hasher5.finish(), hasher5.kDigestBytes);
    printHash("SHA384", hasher6.finish(), hasher6.kDigestBytes);
    printHash("SHA512", hasher7.finish(), hasher7.kDigestBytes);
    printHash("SHA3-224", hasher8.finish(), hasher8.kDigestBytes);
    printHash("SHA3-256", hasher9.finish(), hasher9.kDigestBytes);
    printHash("SHA3-384", hasher10.finish(), hasher10.kDigestBytes);
    printHash("SHA3-512", hasher11.finish(), hasher11.kDigestBytes);
}
