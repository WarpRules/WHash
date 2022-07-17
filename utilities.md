# WHash utilities

`WHash_utilities.hh` contains small utility functions related to cryptographic hashing and related operations.
(Currently only one function, but more may be added in the future.)

## `WHash::byteArraysEqual()`

```c++
namespace WHash
{
    bool byteArraysEqual(const void*, const void*, std::size_t bytesAmount);
}
```

Compares two given byte arrays for equality (mainly intended for comparing if two
hashes are equal). The main idea with this is that the function will always take
the same amount of time regardless of whether the two arrays are equal or not
(or where the first difference between them is). This is to minimize the possibility
of side-channel attacks based on how long an array/hash comparison takes.
