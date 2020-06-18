# ISAAC pseudorandom number generator

ISAAC is a cryptographically strong and efficient pseudorandom number generator by Bob Jenkins.
A C++ implementation is included in this project for its cryptographic uses alongside
the cryptographic hashing utilities (eg. for a stream cipher).

## Class definition

Header file: `"WRng_Isaac.hh"`

```c++
template<unsigned kRandSizeL>
class WRng::Isaac
{
 public:
    static const std::uint32_t kRandSize = (1<<kRandSizeL);

    Isaac(std::uint32_t seed = 0);
    Isaac(std::uint32_t seed1, std::uint32_t seed2);
    Isaac(const std::uint32_t* seeds, std::uint32_t seedsAmount);

    void setSeed(std::uint32_t seed);
    void setSeed(std::uint32_t seed1, std::uint32_t seed2);
    void setSeed(const std::uint32_t* seeds, std::uint32_t seedsAmount);

    std::uint32_t getNext();

    typedef std::uint32_t result_type;

    static constexpr std::uint32_t min() { return 0U; }
    static constexpr std::uint32_t max() { return ~0U; }
    std::uint32_t operator()();
};
```

Additionally, the following type aliases are provided for most common usage cases:

```c++
namespace WRng
{
    using Isaac_s = Isaac<4>; // Recommended for simulations
    using Isaac_c = Isaac<8>; // Recommended for cryptography
}
```

## Usage

The template parameter determines the size of the internal data arrays of the generator
(and thus its period length, and likewise cryptographic strength). The data arrays will
be of size 2 to the power of the parameter (so for example a parameter of 4 means an
array size of 2^4 = 16).

Recommended template parameters sizes are between 4 and 8. `WRng::Isaac_s` and `WRng::Isaac_c`
are type aliases for these two sizes, provided for convenience.

`WRng::Isaac` meets the requirements of _UniformRandomBitGenerator_ (and thus can be used anywhere
where a C++ standard library RNG can). It generates 32-bit unsigned integers. Example:

```c++
WRng::Isaac_s rng(1234); // Initial seed of 1234
std::uint32_t value = rng();
```

The `getNext()` member function simply does the same thing as `operator()`.

Initialization with seed values, in both the form of constructor parameters as well as the
`setSeed()` member function, are provided for 1, 2 and an array of any amount of seed values
up to `WRng::Isaac::kRandSize`.

Example:

```c++
WRng::Isaac_c rng1; // Default seed is 0
WRng::Isaac_c rng2(1);
WRng::Isaac_c rng3(10, 20);

std::uint32_t seeds[8] = { 10, 20, 30, 40, 50, 60, 70, 80 };
WRng::Isaac_c rng4(seeds, 8);
```
