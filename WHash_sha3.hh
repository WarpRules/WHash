#ifndef WHASH_SHA3_HH__
#define WHASH_SHA3_HH__

#include <cstring>
#include <cstdint>

#define WHASH_SHA3_VERSION 0x010000
#define WHASH_SHA3_VERSION_STRING "1.0.0"
#define WHASH_SHA3_COPYRIGHT_STRING "WHash SHA3 v" WHASH_SHA3_VERSION_STRING " (C)2020 Juha Nieminen"

namespace WHash
{
    template<unsigned> class SHA3_base;
    void keccakF1600(std::uint64_t*);
}

template<unsigned kDBytes>
class WHash::SHA3_base
{
 public:
    static const unsigned kDigestBytes = kDBytes;

    SHA3_base();

    void initialize();
    void update(const void* inputBytes, std::size_t inputBytesSize);
    const unsigned char* finish();
    const unsigned char* currentHash() const;


 private:
    static const unsigned kBlockSize = 200 - 2 * kDBytes;
    static_assert(kBlockSize < 200, "kDigestBytes is too large");

    std::uint64_t mState[25];
    unsigned mCounter;
};

namespace WHash
{
    using SHA3_224 = SHA3_base<28>;
    using SHA3_256 = SHA3_base<32>;
    using SHA3_384 = SHA3_base<48>;
    using SHA3_512 = SHA3_base<64>;
}


template<unsigned kDBytes>
WHash::SHA3_base<kDBytes>::SHA3_base()
{
    initialize();
}

template<unsigned kDBytes>
void WHash::SHA3_base<kDBytes>::initialize()
{
    for(unsigned i = 0; i < 25; ++i) mState[i] = 0;
    mCounter = 0;
}

template<unsigned kDBytes>
void WHash::SHA3_base<kDBytes>::update(const void* inputBytes, std::size_t inputBytesSize)
{
    const unsigned char* input = static_cast<const unsigned char*>(inputBytes);
    unsigned char* stateBytes = reinterpret_cast<unsigned char*>(mState);

    if(mCounter > 0)
    {
        const unsigned spaceLeft = kBlockSize - mCounter;

        if(spaceLeft <= inputBytesSize)
        {
            unsigned char* dest = stateBytes + mCounter;
            for(unsigned i = 0; i < spaceLeft; ++i)
                dest[i] ^= input[i];
            keccakF1600(mState);
            input += spaceLeft;
            inputBytesSize -= spaceLeft;
            mCounter = 0;
        }
    }

    // If inputBytes is aligned to 64-bit words, we can use faster xorring
    if(reinterpret_cast<std::uintptr_t>(input) % 8 == 0)
    {
        while(kBlockSize <= inputBytesSize)
        {
            const std::uint64_t* const input64 = reinterpret_cast<const std::uint64_t*>(input);
            for(unsigned i = 0; i < kBlockSize/8; ++i)
                mState[i] ^= input64[i];
            keccakF1600(mState);
            input += kBlockSize;
            inputBytesSize -= kBlockSize;
        }
    }
    else
    {
        while(kBlockSize <= inputBytesSize)
        {
            for(unsigned i = 0; i < kBlockSize; ++i)
                stateBytes[i] ^= input[i];
            keccakF1600(mState);
            input += kBlockSize;
            inputBytesSize -= kBlockSize;
        }
    }

    unsigned char* dest = stateBytes + mCounter;
    for(unsigned i = 0; i < inputBytesSize; ++i)
        dest[i] ^= input[i];

    mCounter += static_cast<unsigned>(inputBytesSize);
}

template<unsigned kDBytes>
const unsigned char* WHash::SHA3_base<kDBytes>::finish()
{
    unsigned char* stateBytes = reinterpret_cast<unsigned char*>(mState);
    stateBytes[mCounter] ^= 0x06;
    stateBytes[kBlockSize - 1] ^= 0x80;
    keccakF1600(mState);
    return stateBytes;
}

template<unsigned kDBytes>
const unsigned char* WHash::SHA3_base<kDBytes>::currentHash() const
{
    return reinterpret_cast<const unsigned char*>(mState);
}

namespace WHash
{
    const std::uint64_t kKeccakF1600Constants[24] =
    {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };

    template<unsigned kAmount>
    inline std::uint64_t rotl(std::uint64_t value)
    {
        return (value << kAmount) | (value >> (64 - kAmount));
    }
}

inline void WHash::keccakF1600(std::uint64_t* state)
{
    std::uint64_t Aba = state[0], Abe = state[1], Abi = state[2], Abo = state[3], Abu = state[4];
    std::uint64_t Aga = state[5], Age = state[6], Agi = state[7], Ago = state[8], Agu = state[9];
    std::uint64_t Aka = state[10], Ake = state[11], Aki = state[12], Ako = state[13], Aku = state[14];
    std::uint64_t Ama = state[15], Ame = state[16], Ami = state[17], Amo = state[18], Amu = state[19];
    std::uint64_t Asa = state[20], Ase = state[21], Asi = state[22], Aso = state[23], Asu = state[24];

    for( unsigned int round = 0; round < 24; round += 2 )
    {
        //    prepareTheta
        std::uint64_t BCa = Aba^Aga^Aka^Ama^Asa;
        std::uint64_t BCe = Abe^Age^Ake^Ame^Ase;
        std::uint64_t BCi = Abi^Agi^Aki^Ami^Asi;
        std::uint64_t BCo = Abo^Ago^Ako^Amo^Aso;
        std::uint64_t BCu = Abu^Agu^Aku^Amu^Asu;

        //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        std::uint64_t Da = BCu^WHash::rotl<1>(BCe);
        std::uint64_t De = BCa^WHash::rotl<1>(BCi);
        std::uint64_t Di = BCe^WHash::rotl<1>(BCo);
        std::uint64_t Do = BCi^WHash::rotl<1>(BCu);
        std::uint64_t Du = BCo^WHash::rotl<1>(BCa);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = WHash::rotl<44>(Age);
        Aki ^= Di;
        BCi = WHash::rotl<43>(Aki);
        Amo ^= Do;
        BCo = WHash::rotl<21>(Amo);
        Asu ^= Du;
        BCu = WHash::rotl<14>(Asu);
        std::uint64_t Eba = BCa ^((~BCe)&  BCi );
        Eba ^= WHash::kKeccakF1600Constants[round];
        std::uint64_t Ebe = BCe ^((~BCi)&  BCo );
        std::uint64_t Ebi = BCi ^((~BCo)&  BCu );
        std::uint64_t Ebo = BCo ^((~BCu)&  BCa );
        std::uint64_t Ebu = BCu ^((~BCa)&  BCe );

        Abo ^= Do;
        BCa = WHash::rotl<28>(Abo);
        Agu ^= Du;
        BCe = WHash::rotl<20>(Agu);
        Aka ^= Da;
        BCi = WHash::rotl<3>(Aka);
        Ame ^= De;
        BCo = WHash::rotl<45>(Ame);
        Asi ^= Di;
        BCu = WHash::rotl<61>(Asi);
        std::uint64_t Ega = BCa ^((~BCe)&  BCi );
        std::uint64_t Ege = BCe ^((~BCi)&  BCo );
        std::uint64_t Egi = BCi ^((~BCo)&  BCu );
        std::uint64_t Ego = BCo ^((~BCu)&  BCa );
        std::uint64_t Egu = BCu ^((~BCa)&  BCe );

        Abe ^= De;
        BCa = WHash::rotl<1>(Abe);
        Agi ^= Di;
        BCe = WHash::rotl<6>(Agi);
        Ako ^= Do;
        BCi = WHash::rotl<25>(Ako);
        Amu ^= Du;
        BCo = WHash::rotl<8>(Amu);
        Asa ^= Da;
        BCu = WHash::rotl<18>(Asa);
        std::uint64_t Eka = BCa ^((~BCe)&  BCi );
        std::uint64_t Eke = BCe ^((~BCi)&  BCo );
        std::uint64_t Eki = BCi ^((~BCo)&  BCu );
        std::uint64_t Eko = BCo ^((~BCu)&  BCa );
        std::uint64_t Eku = BCu ^((~BCa)&  BCe );

        Abu ^= Du;
        BCa = WHash::rotl<27>(Abu);
        Aga ^= Da;
        BCe = WHash::rotl<36>(Aga);
        Ake ^= De;
        BCi = WHash::rotl<10>(Ake);
        Ami ^= Di;
        BCo = WHash::rotl<15>(Ami);
        Aso ^= Do;
        BCu = WHash::rotl<56>(Aso);
        std::uint64_t Ema = BCa ^((~BCe)&  BCi );
        std::uint64_t Eme = BCe ^((~BCi)&  BCo );
        std::uint64_t Emi = BCi ^((~BCo)&  BCu );
        std::uint64_t Emo = BCo ^((~BCu)&  BCa );
        std::uint64_t Emu = BCu ^((~BCa)&  BCe );

        Abi ^= Di;
        BCa = WHash::rotl<62>(Abi);
        Ago ^= Do;
        BCe = WHash::rotl<55>(Ago);
        Aku ^= Du;
        BCi = WHash::rotl<39>(Aku);
        Ama ^= Da;
        BCo = WHash::rotl<41>(Ama);
        Ase ^= De;
        BCu = WHash::rotl<2>(Ase);
        std::uint64_t Esa = BCa ^((~BCe)&  BCi );
        std::uint64_t Ese = BCe ^((~BCi)&  BCo );
        std::uint64_t Esi = BCi ^((~BCo)&  BCu );
        std::uint64_t Eso = BCo ^((~BCu)&  BCa );
        std::uint64_t Esu = BCu ^((~BCa)&  BCe );

        //    prepareTheta
        BCa = Eba^Ega^Eka^Ema^Esa;
        BCe = Ebe^Ege^Eke^Eme^Ese;
        BCi = Ebi^Egi^Eki^Emi^Esi;
        BCo = Ebo^Ego^Eko^Emo^Eso;
        BCu = Ebu^Egu^Eku^Emu^Esu;

        //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu^WHash::rotl<1>(BCe);
        De = BCa^WHash::rotl<1>(BCi);
        Di = BCe^WHash::rotl<1>(BCo);
        Do = BCi^WHash::rotl<1>(BCu);
        Du = BCo^WHash::rotl<1>(BCa);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = WHash::rotl<44>(Ege);
        Eki ^= Di;
        BCi = WHash::rotl<43>(Eki);
        Emo ^= Do;
        BCo = WHash::rotl<21>(Emo);
        Esu ^= Du;
        BCu = WHash::rotl<14>(Esu);
        Aba = BCa ^((~BCe)&  BCi );
        Aba ^= WHash::kKeccakF1600Constants[round+1];
        Abe = BCe ^((~BCi)&  BCo );
        Abi = BCi ^((~BCo)&  BCu );
        Abo = BCo ^((~BCu)&  BCa );
        Abu = BCu ^((~BCa)&  BCe );

        Ebo ^= Do;
        BCa = WHash::rotl<28>(Ebo);
        Egu ^= Du;
        BCe = WHash::rotl<20>(Egu);
        Eka ^= Da;
        BCi = WHash::rotl<3>(Eka);
        Eme ^= De;
        BCo = WHash::rotl<45>(Eme);
        Esi ^= Di;
        BCu = WHash::rotl<61>(Esi);
        Aga = BCa ^((~BCe)&  BCi );
        Age = BCe ^((~BCi)&  BCo );
        Agi = BCi ^((~BCo)&  BCu );
        Ago = BCo ^((~BCu)&  BCa );
        Agu = BCu ^((~BCa)&  BCe );

        Ebe ^= De;
        BCa = WHash::rotl<1>(Ebe);
        Egi ^= Di;
        BCe = WHash::rotl<6>(Egi);
        Eko ^= Do;
        BCi = WHash::rotl<25>(Eko);
        Emu ^= Du;
        BCo = WHash::rotl<8>(Emu);
        Esa ^= Da;
        BCu = WHash::rotl<18>(Esa);
        Aka = BCa ^((~BCe)&  BCi );
        Ake = BCe ^((~BCi)&  BCo );
        Aki = BCi ^((~BCo)&  BCu );
        Ako = BCo ^((~BCu)&  BCa );
        Aku = BCu ^((~BCa)&  BCe );

        Ebu ^= Du;
        BCa = WHash::rotl<27>(Ebu);
        Ega ^= Da;
        BCe = WHash::rotl<36>(Ega);
        Eke ^= De;
        BCi = WHash::rotl<10>(Eke);
        Emi ^= Di;
        BCo = WHash::rotl<15>(Emi);
        Eso ^= Do;
        BCu = WHash::rotl<56>(Eso);
        Ama = BCa ^((~BCe)&  BCi );
        Ame = BCe ^((~BCi)&  BCo );
        Ami = BCi ^((~BCo)&  BCu );
        Amo = BCo ^((~BCu)&  BCa );
        Amu = BCu ^((~BCa)&  BCe );

        Ebi ^= Di;
        BCa = WHash::rotl<62>(Ebi);
        Ego ^= Do;
        BCe = WHash::rotl<55>(Ego);
        Eku ^= Du;
        BCi = WHash::rotl<39>(Eku);
        Ema ^= Da;
        BCo = WHash::rotl<41>(Ema);
        Ese ^= De;
        BCu = WHash::rotl<2>(Ese);
        Asa = BCa ^((~BCe)&  BCi );
        Ase = BCe ^((~BCi)&  BCo );
        Asi = BCi ^((~BCo)&  BCu );
        Aso = BCo ^((~BCu)&  BCa );
        Asu = BCu ^((~BCa)&  BCe );
    }

    state[0] = Aba; state[1] = Abe; state[2] = Abi; state[3] = Abo; state[4] = Abu;
    state[5] = Aga; state[6] = Age; state[7] = Agi; state[8] = Ago; state[9] = Agu;
    state[10] = Aka; state[11] = Ake; state[12] = Aki; state[13] = Ako; state[14] = Aku;
    state[15] = Ama; state[16] = Ame; state[17] = Ami; state[18] = Amo; state[19] = Amu;
    state[20] = Asa; state[21] = Ase; state[22] = Asi; state[23] = Aso; state[24] = Asu;
}
#endif
