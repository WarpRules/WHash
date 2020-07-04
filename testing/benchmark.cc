#include "../WHash_crc32.hh"
#include "../WHash_md5.hh"
#include "../WHash_sha1.hh"
#include "../WHash_sha224.hh"
#include "../WHash_sha256.hh"
#include "../WHash_sha384.hh"
#include "../WHash_sha512.hh"
#include "../WHash_sha3.hh"
#include <cstdio>
#include <cstdint>
#include <chrono>

volatile unsigned char dataSink;

static void printHash(const unsigned char* hash, unsigned bytes)
{
    for(unsigned i = 0; i < bytes; ++i)
        std::printf("%02x", hash[i]);
}

template<typename HashCalculator_t>
void runBenchmark(const char* hashName)
{
    const std::size_t kDataSize = 1024;
    const std::size_t kTestIterations = 1024*1024;

    std::uint32_t data[kDataSize/4];
    std::uint32_t seed = 3363461597;
    for(unsigned i = 0; i < kDataSize/4; ++i)
        data[i] = (seed = seed * UINT32_C(3363461597) + UINT32_C(8346591));

    HashCalculator_t hasher;

    std::chrono::time_point<std::chrono::high_resolution_clock> startTime =
        std::chrono::high_resolution_clock::now();

    for(std::size_t i = 0; i < kTestIterations; ++i)
        hasher.update(data, kDataSize);

    const unsigned char* hash = hasher.finish();
    dataSink = hash[0] + hash[hasher.kDigestBytes - 1];

    const std::chrono::time_point<std::chrono::high_resolution_clock> endTime =
        std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> diff = endTime - startTime;
    const double seconds = diff.count();

    const std::size_t kTotalData = kDataSize * kTestIterations;
    std::printf("Calculated %s hash of %zu MB of data in %.2f seconds, %.1f MB/s\n%s has was: ",
                hashName, kTotalData / (1024*1024), seconds, kTotalData / (1024.0*1024.0) / seconds, hashName);
    printHash(hash, hasher.kDigestBytes);
    std::printf("\n");
}

int main()
{
    std::printf("Running benchmarks...\n");
    runBenchmark<WHash::CRC32>("CRC32");
    runBenchmark<WHash::MD5>("MD5");
    runBenchmark<WHash::SHA1>("SHA1");
    runBenchmark<WHash::SHA224>("SHA224");
    runBenchmark<WHash::SHA256>("SHA256");
    runBenchmark<WHash::SHA384>("SHA384");
    runBenchmark<WHash::SHA512>("SHA512");
    runBenchmark<WHash::SHA3_224>("SHA3_224");
    runBenchmark<WHash::SHA3_256>("SHA3_256");
    runBenchmark<WHash::SHA3_384>("SHA3_384");
    runBenchmark<WHash::SHA3_512>("SHA3_512");
}
