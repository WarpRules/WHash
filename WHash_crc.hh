#ifndef WHASH_CRC_HH__
#define WHASH_CRC_HH__

#include <cstdint>

#define WHASH_CRC_VERSION 0x010000
#define WHASH_CRC_VERSION_STRING "1.0.0"
#define WHASH_CRC_COPYRIGHT_STRING "WHash CRC v" WHASH_CRC_VERSION_STRING " (C)2020 Juha Nieminen"

namespace WHash::CRC
{
    template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial,
             CRCvalue_t kInitialValue, CRCvalue_t kXorOut,
             bool kReflectedInput, bool kReflectedOutput = kReflectedInput>
    class CRC
    {
        static_assert(kBits >= 8 || kReflectedInput == true,
                      "kBits < 8 and kReflectedInput == false currently not supported");

     public:
        static const unsigned kDigestBits = kBits;
        static const unsigned kDigestBytes = (kBits + 7) / 8;
        using Value_t = CRCvalue_t;

        void initialize();
        void update(const void* inputBytes, std::size_t inputBytesSize);
        const unsigned char* finish();
        const unsigned char* currentHash() const { return mHash; }

        CRCvalue_t crcValue() const { return mCRC; }


     private:
        CRCvalue_t mCRC = kInitialValue;
        unsigned char mHash[kDigestBytes];
    };


    using CRC3_gsm = CRC<std::uint8_t, 3, 0x3, 0x0, 0x7, false>;
    using CRC3_rohc = CRC<std::uint8_t, 3, 0x3, 0x7, 0x0, true>;
    using CRC4_g704 = CRC<std::uint8_t, 4, 0x3, 0x0, 0x0, true>;
    using CRC5_g704 = CRC<std::uint8_t, 5, 0x15, 0x00, 0x00, true>;
    using CRC5_usb = CRC<std::uint8_t, 5, 0x05, 0x1F, 0x1F, true>;
    using CRC6_darc = CRC<std::uint8_t, 6, 0x19, 0x00, 0x00, true>;
    using CRC6_g704 = CRC<std::uint8_t, 6, 0x03, 0x00, 0x00, true>;
    using CRC7_rohc = CRC<std::uint8_t, 7, 0x4F, 0x7F, 0x0, true>;
    using CRC8_aes = CRC<std::uint8_t, 8, 0x1D, 0xFF, 0x00, true>;
    using CRC8_autosar = CRC<std::uint8_t, 8, 0x2F, 0xFF, 0xFF, false>;
    using CRC8_bluetooth = CRC<std::uint8_t, 8, 0xA7, 0x00, 0x00, true>;
    using CRC8_cdma2000 = CRC<std::uint8_t, 8, 0x9B, 0xFF, 0x00, false>;
    using CRC8_darc = CRC<std::uint8_t, 8, 0x39, 0x00, 0x00, true>;
    using CRC8_dvbs2 = CRC<std::uint8_t, 8, 0xD5, 0x00, 0x00, false>;
    using CRC8_gsma = CRC<std::uint8_t, 8, 0x1D, 0x00, 0x00, false>;
    using CRC8_gsmb = CRC<std::uint8_t, 8, 0x49, 0x00, 0xFF, false>;
    using CRC8_icode = CRC<std::uint8_t, 8, 0x1D, 0xFD, 0x00, false>;
    using CRC8_itu = CRC<std::uint8_t, 8, 0x07, 0x00, 0x55, false>;
    using CRC8_lte = CRC<std::uint8_t, 8, 0x9B, 0x00, 0x00, false>;
    using CRC8_maxim = CRC<std::uint8_t, 8, 0x31, 0x00, 0x00, true>;
    using CRC8_mifare = CRC<std::uint8_t, 8, 0x1D, 0xC7, 0x00, false>;
    using CRC8_nrsc5 = CRC<std::uint8_t, 8, 0x31, 0xFF, 0x00, false>;
    using CRC8_opensafety = CRC<std::uint8_t, 8, 0x2F, 0x00, 0x00, false>;
    using CRC8_rohc = CRC<std::uint8_t, 8, 0x07, 0xFF, 0x00, true>;
    using CRC8_saej1850 = CRC<std::uint8_t, 8, 0x1D, 0xFF, 0xFF, false>;
    using CRC8_smbus = CRC<std::uint8_t, 8, 0x07, 0x00, 0x00, false>;
    using CRC8_wcdma = CRC<std::uint8_t, 8, 0x9B, 0x00, 0x00, true>;
    using CRC10_atm = CRC<std::uint16_t, 10, 0x233, 0x000, 0x000, false>;
    using CRC10_cdma2000 = CRC<std::uint16_t, 10, 0x3D9, 0x3FF, 0x000, false>;
    using CRC10_gsm = CRC<std::uint16_t, 10, 0x175, 0x000, 0x3FF, false>;
    using CRC11_flexray = CRC<std::uint16_t, 11, 0x385, 0x01A, 0x000, false>;
    using CRC11_umts = CRC<std::uint16_t, 11, 0x307, 0x000, 0x000, false>;
    using CRC12_cdma2000 = CRC<std::uint16_t, 12, 0xF13, 0xFFF, 0x000, false>;
    using CRC12_dect = CRC<std::uint16_t, 12, 0x80F, 0x000, 0x000, false>;
    using CRC12_gsm = CRC<std::uint16_t, 12, 0xD31, 0x000, 0xFFF, false>;
    using CRC12_umts = CRC<std::uint16_t, 12, 0x80F, 0x000, 0x000, false, true>;
    using CRC13_bbc = CRC<std::uint16_t, 13, 0x1CF5, 0x0000, 0x0000, false>;
    using CRC14_darc = CRC<std::uint16_t, 14, 0x0805, 0x0000, 0x0000, true>;
    using CRC16_arc = CRC<std::uint16_t, 16, 0x8005, 0x0000, 0x0000, true>;
    using CRC16_cdma2000 = CRC<std::uint16_t, 16, 0xC867, 0xFFFF, 0x0000, false>;
    using CRC17_canfd = CRC<std::uint32_t, 17, 0x1685B, 0x00000, 0x00000, false>;
    using CRC21_canfd = CRC<std::uint32_t, 21, 0x102899, 0x00000, 0x00000, false>;
    using CRC32_iso = CRC<std::uint32_t, 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true>;
}




namespace WHash::CRC
{
    template<typename Value_t, unsigned kBits>
    constexpr Value_t reflectedValue(Value_t value)
    {
        Value_t retval = 0;
        for(unsigned bitIndex = kBits - 1; bitIndex > 0; --bitIndex, value >>= 1)
            retval |= (value & 1) << bitIndex;
        retval |= (value & 1);
        return retval;
    }

    template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial, bool kReflectedInput>
    constexpr CRCvalue_t crcTableEntry(std::uint8_t inputByte)
    {
        if constexpr(kReflectedInput)
        {
            constexpr CRCvalue_t kReflectedPolynomial = reflectedValue<CRCvalue_t, kBits>(kPolynomial);
            CRCvalue_t crc = inputByte;
            for(unsigned i = 0; i < 8; ++i)
                crc = (crc >> 1) ^ (((~(crc & 1)) + 1) & kReflectedPolynomial);
            return crc;
        }
        else
        {
            CRCvalue_t crc = inputByte << (kBits - 8);
            for(unsigned i = 0; i < 8; ++i)
                crc = (crc << 1) ^ (((~((crc >> (kBits-1)) & 1)) + 1) & kPolynomial);
            return crc;
        }
    }

    template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial, bool kReflectedInput>
    struct LookupTable
    {
        CRCvalue_t entries[256];
        constexpr LookupTable(): entries{}
        {
            std::uint8_t byteValue = 0;
            do
            {
                entries[byteValue] = crcTableEntry<CRCvalue_t, kBits, kPolynomial, kReflectedInput>(byteValue);
                ++byteValue;
            } while(byteValue);
        }
    };
}


template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial,
         CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput, bool kReflectedOutput>
inline void WHash::CRC::CRC
<CRCvalue_t, kBits, kPolynomial, kInitialValue, kXorOut, kReflectedInput, kReflectedOutput>::initialize()
{
    mCRC = kInitialValue;
}

template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial,
         CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput, bool kReflectedOutput>
inline void WHash::CRC::CRC
<CRCvalue_t, kBits, kPolynomial, kInitialValue, kXorOut, kReflectedInput, kReflectedOutput>::update
(const void* inputBytes, std::size_t inputBytesSize)
{
    static constexpr LookupTable<CRCvalue_t, kBits, kPolynomial, kReflectedInput> kLookupTable;

    const unsigned char* data = static_cast<const unsigned char*>(inputBytes);
    CRCvalue_t crc = mCRC;

    if constexpr(kReflectedInput)
    {
        while(inputBytesSize--)
            crc = (crc >> 8) ^ kLookupTable.entries[(crc & 0xFF) ^ *data++];
    }
    else
    {
        while(inputBytesSize--)
            crc = (crc << 8) ^ kLookupTable.entries[((crc >> (kBits - 8)) & 0xFF) ^ *data++];
    }

    mCRC = crc;
}

template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial,
         CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput, bool kReflectedOutput>
inline const unsigned char* WHash::CRC::CRC
<CRCvalue_t, kBits, kPolynomial, kInitialValue, kXorOut, kReflectedInput, kReflectedOutput>::finish()
{
    if constexpr(kBits < 8*sizeof(CRCvalue_t)) mCRC &= (1 << kBits) - 1;

    mCRC ^= kXorOut;

    if constexpr(kReflectedInput != kReflectedOutput)
        mCRC = reflectedValue<CRCvalue_t, kBits>(mCRC);

    CRCvalue_t crc = mCRC;
    for(unsigned i = kDigestBytes; i-- > 0; crc >>= 8)
        mHash[i] = static_cast<unsigned char>(crc);
    return mHash;
}
#endif
