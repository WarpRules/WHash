# WHash FAQ

**"Why yet another hashing library? There are already free hashing libraries, like Crypto++."**

Suppose that you need to calculate, let's say, SHA-256 hashes, and no others, in a small project that
you eg. intend to distribute. For the sake of example, let's take this minimalistic program that simply
calculates the hash of a given input file:

```c++
#include "cryptopp/sha.h"
#include <cstdio>

int main(int argc, char** argv)
{
    CryptoPP::SHA256 hasher;
    unsigned char hash[CryptoPP::SHA256::DIGESTSIZE];
    unsigned char inputBuffer[65536];

    if(argc < 2) return 1;
    std::FILE* inFile = std::fopen(argv[1], "rb");
    if(!inFile) { std::perror(argv[1]); return 1; }

    while(true)
    {
        const std::size_t amount =
            std::fread(inputBuffer, 1, 65536, inFile);
        if(!amount) break;
        hasher.Update(inputBuffer, amount);
    }

    std::fclose(inFile);
    hasher.TruncatedFinal(hash, CryptoPP::SHA256::DIGESTSIZE);

    for(unsigned char c: hash) std::printf("%02X", c);
    std::printf("\n");
}
```

The Crypto++ library (as of writing this) consists of 200 source files and 191 header files.
There's no easy way of separating just the SHA-256 part from the rest, no matter how much you
try. You essentially need to compile _the entire library_ into the project to use it (even
though something like 90% of it has nothing to do with SHA-256).

If you wanted to distribute this project of yours, you would need to include the entire Crypto++
library with it, or leave your project dependent on it, for other users to deal with.

Compiling the Crypto++ library into a `libcrypto.a` file takes 2 minutes and 15 seconds in my i7-9700K system.
The `libcrypto.a` file (compiled with the default options of the provided makefile) is a whopping 101 megabytes
in size.

With WHash you only need to include two header files in your project (`WHash_sha256.h` and `WHash_sha2_base.h`)
and even though they technically speaking need to be recompiled every time the source files that use them are,
eg. a version of the above program that uses `WHash::SHA256` takes 0.17 seconds to compile in my system.

What's worse, the difference in the resulting executable file sizes of the above example program is staggering.
These were compiled with the options `-Ofast -march=native -s` (where the `-s` strips all debug information
from the final executable, to make it as small as possible):

Executable file | bytes
--- | --:
sha256_cryptopp | 1494136
sha256_whash | 18608

Even the `calchashes.cc` example program in the examples directory, which uses all the hashes in this project
(except the ones in `WHash_crc.hh`) takes about 0.79 seconds to compile and is about 50 kB in size.

That's why.

**"Well, just compile Crypto++ into an .so file."**

You aren't really saving anything by doing that. You are simply making the executable binary smaller by
having a 59-megabyte .so file on the side, so you aren't really saving anything (but the exact opposite).

You could require Crypto++ to be installed in the system by anybody who wants to use your project, but
WHash has no such extra requirements.
