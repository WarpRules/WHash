# WHash

This is a collection of cryptographic hash calculation classes for C++, using a header-file-only
design. Each hash type is implemented in its own header file and is as small, compact and efficient
as possible, and implemented in standard C++ and thus usable as-is, without requiring any configuration.

Currently supported hashes (more may be added in the future):

* CRC32: `"WHash_crc32.hh"`
* MD5: `"WHash_md5.hh"`
* SHA1: `"WHash_sha1.hh"`
* SHA224: `"WHash_sha224.hh"`
* SHA256: `"WHash_sha256.hh"`
* SHA384: `"WHash_sha384.hh"`
* SHA512: `"WHash_sha512.hh"`
* SHA3_224, SHA3_256, SHA3_384, SHA3_512: `"WHash_sha3.hh"`
* Extensive CRC collection: `"WHash_crc.hh"`. See [separate documentation.](https://github.com/WarpRules/WHash/blob/master/crc.md)

Additionally an implementation of the cryptographically strong ISAAC pseudorandom number generator
is provided. See [separate documentation.](https://github.com/WarpRules/WHash/blob/master/isaac.md)

## Benchmarks

The benchmarks were performed by using a 1 kB array initialized with random values, and feeding it
again and again to the hasher, a total of 1048576 times, before calling `finalize()`. (As such a small
array fits in the innermost cache of the CPU, this effectively measures raw computation speed of the
class without any latency caused by cache misses etc.)

The benchmarks were run on an i7-9700K, and compiled with `g++ -Ofast -march=skylake` using g++ 9.3.1.

Class | Total time | MB/s
--- | --- | ---
`WHash::MD5` | 1.26 s | 814
`WHash::SHA1` | 2.82 s | 363
`WHash::SHA224` | 3.31 s | 309
`WHash::SHA256` | 3.31 s | 309
`WHash::SHA384` | 2.96 s | 346
`WHash::SHA512` | 3.01 s | 340
`WHash::SHA3_224` | 1.92 s | 533
`WHash::SHA3_256` | 2.04 s | 501
`WHash::SHA3_384` | 2.65 s | 386
`WHash::SHA3_512` | 3.81 s | 269

## Public interface

Classes:

* CRC32: `"WHash_crc32.hh"`: `WHash::CRC32`
* MD5: `"WHash_md5.hh"`: `WHash::MD5`
* SHA1: `"WHash_sha1.hh"`: `WHash::SHA1`
* SHA224: `"WHash_sha224.hh"`: `WHash::SHA224`
* SHA256: `"WHash_sha256.hh"`: `WHash::SHA256`
* SHA384: `"WHash_sha384.hh"`: `WHash::SHA384`
* SHA512: `"WHash_sha512.hh"`: `WHash::SHA512`
* SHA3_224: `"WHash_sha3.hh"`: `WHash::SHA3_224`
* SHA3_256: `"WHash_sha3.hh"`: `WHash::SHA3_256`
* SHA3_384: `"WHash_sha3.hh"`: `WHash::SHA3_384`
* SHA3_512: `"WHash_sha3.hh"`: `WHash::SHA3_512`

All classes use the same public interface. Only the name of the class is different.

```c++
    // The length of the hash in bytes:
    static const unsigned kDigestBytes;

    void initialize();
    void update(const void* inputBytes, std::size_t inputBytesSize);
    const unsigned char* finish();
    const unsigned char* currentHash() const;
```

In addition, the `WHash::CRC32` class has the member function

```c++
    std::uint32_t crc32Value() const;
```

(which can be used to retrieve the CRC32 hash as an integer after having called `finish()`.)

## Usage

Instantiate the class, call its `update()` method with the input data, and then call the `finish()` method.
This method returns a pointer to the hash. The length of the hash (in bytes) is determined by the
`kDigestBytes` static const member variable. This same pointer can also be retrieved later with `currentHash()`.

The pointer returned by `finish()` and `currentHash()` points to an internal array, and thus it will
be valid only for as long as this object exists. Also calling any of the functions (such as `initialize()`)
will invalidate the data pointed to by the pointer.

Example:

```c++
WHash::MD5 md5hasher;

md5hasher.update(pointerToData, dataBytesAmount);
const unsigned char* md5hash = md5hasher.finish();
```

Note that it's not necessary to supply all the data to be hashed at once. The `update()` function can
be called multiple times, with partial data. For example like:

```c++
// Read and calculate the MD5 sum of an input file (fopen()'ed to inFile)
const std::size_t kBufferSize = 1024;
unsigned char dataBuffer[kBufferSize]; // 1 kB of data
WHash::MD5 md5hasher;

while(true)
{
    const std::size_t bytesAmount =
        std::fread(dataBuffer, 1, kBufferSize, inFile);
    if(bytesAmount == 0) break;
    md5hasher.update(dataBuffer, bytesAmount);
};

const unsigned char* md5hash = md5hasher.finish();
```

The `initialize()` method resets the internal data of the class. It needs to be called if this same
object is used for a new hash calculation. (If this object is used for only one calculation it doesn't
need to be called.)
