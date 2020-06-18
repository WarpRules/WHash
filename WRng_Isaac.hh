#ifndef WRNG_ISAAC_HH__
#define WRNG_ISAAC_HH__
#include <cstdint>

#define WRNG_ISAAC_VERSION 0x010000
#define WRNG_ISAAC_VERSION_STRING "1.0.0"
#define WRNG_ISAAC_COPYRIGHT_STRING "WRng Isaac v" WRNG_ISAAC_VERSION_STRING " (C)2020 Juha Nieminen"

namespace WRng
{
    template<std::uint32_t> class Isaac;

    using Isaac_s = Isaac<4>;
    using Isaac_c = Isaac<8>;
}

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
    std::uint32_t operator()() { return getNext(); }

    const std::uint32_t* randValuesArray() const;
    void refill();

//------------------------------------------------------------------------
 protected:
    struct randctx
    {
        std::uint32_t randrsl[kRandSize];
        std::uint32_t randmem[kRandSize];
        std::uint32_t randcnt;
        std::uint32_t randa, randb, randc;
    };

    randctx data;

    static void randinit(randctx* ctx, bool flag);
    static void isaac(randctx* ctx);
};


template<std::uint32_t kRandSizeL>
inline const std::uint32_t* WRng::Isaac<kRandSizeL>::randValuesArray() const
{
    return data.randrsl;
}

template<std::uint32_t kRandSizeL>
inline unsigned WRng::Isaac<kRandSizeL>::getNext()
{
    if(!data.randcnt)
    {
        isaac(&data);
        data.randcnt = kRandSize-1;
    }
    else --data.randcnt;
    return data.randrsl[data.randcnt];
}

template<std::uint32_t kRandSizeL>
inline void WRng::Isaac<kRandSizeL>::refill()
{
    isaac(&data);
    data.randcnt = kRandSize-1;
}

#define WRNG_ISAAC_ind(mm,x)  (*(std::uint32_t *)((std::uint8_t*)(mm) + ((x) & ((kRandSize-1)<<2))))
#define WRNG_ISAAC_rngstep(mix,a,b,mm,m,m2,r,x) { \
  x = *m;  \
  a = (a^(mix)) + *(m2++); \
  *(m++) = y = WRNG_ISAAC_ind(mm,x) + a + b; \
  *(r++) = b = WRNG_ISAAC_ind(mm,y>>kRandSizeL) + x; }

template<std::uint32_t kRandSizeL>
inline void WRng::Isaac<kRandSizeL>::isaac(randctx* ctx)
{
    std::uint32_t a,b,x,y,*m,*mm,*m2,*r,*mend;
    mm=ctx->randmem; r=ctx->randrsl;
    a = ctx->randa; b = ctx->randb + (++ctx->randc);
    for (m = mm, mend = m2 = m+(kRandSize/2); m<mend; )
    {
        WRNG_ISAAC_rngstep( a<<13, a, b, mm, m, m2, r, x);
        WRNG_ISAAC_rngstep( a>>6 , a, b, mm, m, m2, r, x);
        WRNG_ISAAC_rngstep( a<<2 , a, b, mm, m, m2, r, x);
        WRNG_ISAAC_rngstep( a>>16, a, b, mm, m, m2, r, x);
    }
    for (m2 = mm; m2<mend; )
    {
        WRNG_ISAAC_rngstep( a<<13, a, b, mm, m, m2, r, x);
        WRNG_ISAAC_rngstep( a>>6 , a, b, mm, m, m2, r, x);
        WRNG_ISAAC_rngstep( a<<2 , a, b, mm, m, m2, r, x);
        WRNG_ISAAC_rngstep( a>>16, a, b, mm, m, m2, r, x);
    }
    ctx->randb = b; ctx->randa = a;
}

#undef WRNG_ISAAC_ind
#undef WRNG_ISAAC_rngstep

#define WRNG_ISAAC_mix(a,b,c,d,e,f,g,h) { \
   a^=b<<11; d+=a; b+=c; \
   b^=c>>2;  e+=b; c+=d; \
   c^=d<<8;  f+=c; d+=e; \
   d^=e>>16; g+=d; e+=f; \
   e^=f<<10; h+=e; f+=g; \
   f^=g>>4;  a+=f; g+=h; \
   g^=h<<8;  b+=g; h+=a; \
   h^=a>>9;  c+=h; a+=b; }

template<std::uint32_t kRandSizeL>
inline void WRng::Isaac<kRandSizeL>::randinit(randctx* ctx, bool flag)
{
   std::uint32_t a,b,c,d,e,f,g,h;
   std::uint32_t *m,*r;
   ctx->randa = ctx->randb = ctx->randc = 0;
   m=ctx->randmem;
   r=ctx->randrsl;
   a=b=c=d=e=f=g=h=0x9e3779b9;

   for (unsigned i=0; i<4; ++i)
   {
       WRNG_ISAAC_mix(a,b,c,d,e,f,g,h);
   }

   if (flag)
   {
       for (unsigned i=0; i<kRandSize; i+=8)
       {
           a+=r[i  ]; b+=r[i+1]; c+=r[i+2]; d+=r[i+3];
           e+=r[i+4]; f+=r[i+5]; g+=r[i+6]; h+=r[i+7];
           WRNG_ISAAC_mix(a,b,c,d,e,f,g,h);
           m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
           m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
       }
       for (unsigned i=0; i<kRandSize; i+=8)
       {
           a+=m[i  ]; b+=m[i+1]; c+=m[i+2]; d+=m[i+3];
           e+=m[i+4]; f+=m[i+5]; g+=m[i+6]; h+=m[i+7];
           WRNG_ISAAC_mix(a,b,c,d,e,f,g,h);
           m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
           m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
       }
   }
   else
   {
       for (unsigned i=0; i<kRandSize; i+=8)
       {
           WRNG_ISAAC_mix(a,b,c,d,e,f,g,h);
           m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
           m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
       }
   }

   isaac(ctx);
   ctx->randcnt=kRandSize;
}

#undef WRNG_ISAAC_mix

template<std::uint32_t kRandSizeL>
inline void WRng::Isaac<kRandSizeL>::setSeed(unsigned seed)
{
    for(std::uint32_t i = 0; i < kRandSize; ++i)
    {
        seed = seed * 2147001325U + 715136305U;
        data.randrsl[i] = seed ^ (seed>>14);
    }

    randinit(&data, true);
}

template<std::uint32_t kRandSizeL>
inline void WRng::Isaac<kRandSizeL>::setSeed(unsigned seed1, unsigned seed2)
{
    for(std::uint32_t i = 0; i < kRandSize; i += 2)
    {
        seed1 = seed1 * 2147001325U + 715136305U;
        seed2 = seed2 * 1812433253U + 12345U;
        data.randrsl[i] = seed1 ^ (seed1>>13);
        data.randrsl[i+1] = seed2 ^ (seed2>>15);
    }

    randinit(&data, true);
}

template<std::uint32_t kRandSizeL>
inline void WRng::Isaac<kRandSizeL>::setSeed(const unsigned* seeds, unsigned seedsAmount)
{
    if(seedsAmount == 0) setSeed(0);
    else
    {
        if(seedsAmount > kRandSize) seedsAmount = kRandSize;
        for(unsigned i = 0; i < seedsAmount; ++i)
            data.randrsl[i] = seeds[i];

        unsigned seed = *seeds;
        for(unsigned i = seedsAmount; i < kRandSize; ++i)
        {
            seed = seed * 2147001325U + 715136305U;
            data.randrsl[i] = seed ^ (seed>>15);
        }

        randinit(&data, true);
    }
}

template<std::uint32_t kRandSizeL>
inline WRng::Isaac<kRandSizeL>::Isaac(unsigned seed)
{
    setSeed(seed);
}

template<std::uint32_t kRandSizeL>
inline WRng::Isaac<kRandSizeL>::Isaac(unsigned seed1, unsigned seed2)
{
    setSeed(seed1, seed2);
}

template<std::uint32_t kRandSizeL>
inline WRng::Isaac<kRandSizeL>::Isaac(const unsigned* seeds, unsigned seedsAmount)
{
    setSeed(seeds, seedsAmount);
}
#endif
