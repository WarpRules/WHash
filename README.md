# WHash

This is a collection of cryptographic hash calculation classes for C++, using a header-file-only
design. Each hash type is implemented in its own header file and is as small, compact and efficient
as possible, and implemented in standard C++ and thus usable as-is, without requiring any configuration.

Currently supported hashes (more may be added in the future):

* MD5: `WHash_md5.hh`
* SHA1: `WHash_sha1.hh`
* SHA256: `WHash_sha256.hh`
* SHA224: `WHash_sha224.hh`
* SHA512: `WHash_sha512.hh`

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
`WHash::SHA256` | 3.31 s | 309

## Public interface

Classes:

* MD5: `WHash_md5.hh`: `WHash::MD5`
* SHA1: `WHash_sha1.hh`: `WHash::SHA1`
* SHA256: `WHash_sha256.hh`: `WHash::SHA256`
* SHA224: `WHash_sha224.hh`: `WHash::SHA224`
* SHA512: `WHash_sha512.hh`: `WHash::SHA512`

All classes use the same public interface. Only the name of the class is different.

```c++
    // The length of the hash in bytes:
    static const unsigned kDigestBytes;

    void initialize();
    void update(const void* inputBytes, std::size_t inputBytesSize);
    const unsigned char* finish();
    const unsigned char* currentHash() const;
```

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
