#include "../WHash_md5.hh"
#include <cstdio>
#include <cstdint>
#include <chrono>

volatile unsigned char dataSink;

static void printMD5Hash(const unsigned char* sum)
{
    for(unsigned i = 0; i < 16; ++i)
        std::printf("%02x", sum[i]);
}

int main()
{
    const std::size_t kDataSize = 1024;
    const std::size_t kTestIterations = 1024*1024;

    std::uint32_t data[kDataSize/4];
    std::uint32_t seed = 3363461597;
    for(unsigned i = 0; i < kDataSize/4; ++i)
        data[i] = (seed = seed * UINT32_C(3363461597) + UINT32_C(8346591));

    WHash::MD5 md5Hasher;

    std::chrono::time_point<std::chrono::high_resolution_clock> startTime =
        std::chrono::high_resolution_clock::now();

    for(std::size_t i = 0; i < kTestIterations; ++i)
        md5Hasher.update(data, kDataSize);

    const unsigned char* hash = md5Hasher.finish();
    dataSink = hash[0] + hash[15];

    const std::chrono::time_point endTime = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> diff = endTime - startTime;
    const double seconds = diff.count();

    const std::size_t kTotalData = kDataSize * kTestIterations;
    std::printf("Calculated MD5 hash of %zu MB of data in %.2f seconds, %.1f MB/s\nMD5 has was: ",
                kTotalData / (1024*1024), seconds, kTotalData / (1024.0*1024.0) / seconds);
    printMD5Hash(hash);
    std::printf("\n");
}
