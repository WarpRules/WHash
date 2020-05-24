# WHash

This is a collection of cryptographic hash calculation classes for C++, using a header-file-only
design. Each hash type is implemented in its own header file and is as small, compact and efficient
as possible, and implemented in standard C++ and thus usable as-is, without requiring any configuration.

Currently supported hashes (more may be added in the future):

* MD5: `WHash_md5.hh`

## MD5

Header file: `WHash_md5.hh`

Class: `WHash::MD5`

### Public interface:

```c++
    static const unsigned kDigestBytes = 16;

    void initialize();
    void update(const void* inputBytes, std::size_t inputBytesSize);
    const unsigned char* finish();
    const unsigned char* currentHash() const;
```

### Usage:

Instantiate the `WHash::MD5` class, call its `update()` method with the input data, and then call
the `finish()` method. This method returns a pointer to the 16-byte hash. This same pointer can also
be retrieved later with `currentHash()`.

The pointer returned by `finish()` and `currentHash()` points to an internal array, and thus it will
be valid only for as long as this object exists.

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
    md5Hasher.update(dataBuffer, bytesAmount);
};

const unsigned char* md5hash = md5hasher.finish();
```

The `initialize()` method resets the internal data of the class. It needs to be called if this same
object is used for a new hash calculation. (If this object is used for only one calculation it doesn't
need to be called.)
