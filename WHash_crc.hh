#ifndef WHASH_CRC_HH__
#define WHASH_CRC_HH__

#include <cstdint>

#define WHASH_CRC_VERSION 0x010000
#define WHASH_CRC_VERSION_STRING "1.0.0"
#define WHASH_CRC_COPYRIGHT_STRING "WHash CRC v" WHASH_CRC_VERSION_STRING " (C)2020 Juha Nieminen"

namespace WHash::CRC
{
    template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial,
             CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput>
    class CRC
    {
     public:
        static const unsigned kDigestBits = kBits;
        static const unsigned kDigestBytes = (kBits + 7) / 8;

        void initialize();
        void update(const void* inputBytes, std::size_t inputBytesSize);
        const unsigned char* finish();
        const unsigned char* currentHash() const { return mHash; }

        CRCvalue_t crcValue() const { return mCRC; }


     private:
        CRCvalue_t mCRC = kInitialValue;
        unsigned char mHash[kDigestBytes];
    };


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
    using CRC16_arc = CRC<std::uint16_t, 16, 0x8005, 0x0000, 0x0000, true>;
    using CRC16_cdma2000 = CRC<std::uint16_t, 16, 0xC867, 0xFFFF, 0x0000, false>;
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
        CRCvalue_t crc = inputByte;

        if constexpr(kReflectedInput)
        {
            constexpr CRCvalue_t kReflectedPolynomial = reflectedValue<CRCvalue_t, kBits>(kPolynomial);
            for(unsigned i = 0; i < 8; ++i)
                crc = (crc >> 1) ^ (((~(crc & 1)) + 1) & kReflectedPolynomial);
        }
        else
        {
            for(unsigned i = 0; i < 8; ++i)
                crc = (crc << 1) ^ (((~((crc >> (kBits-1)) & 1)) + 1) & kPolynomial);
        }

        return crc;
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
         CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput>
inline void WHash::CRC::CRC
<CRCvalue_t, kBits, kPolynomial, kInitialValue, kXorOut, kReflectedInput>::initialize()
{
    mCRC = kInitialValue;
}

template<typename CRCvalue_t, unsigned kBits, CRCvalue_t kPolynomial,
         CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput>
inline void WHash::CRC::CRC
<CRCvalue_t, kBits, kPolynomial, kInitialValue, kXorOut, kReflectedInput>::update
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
         CRCvalue_t kInitialValue, CRCvalue_t kXorOut, bool kReflectedInput>
inline const unsigned char* WHash::CRC::CRC
<CRCvalue_t, kBits, kPolynomial, kInitialValue, kXorOut, kReflectedInput>::finish()
{
    CRCvalue_t crc = mCRC = mCRC ^ kXorOut;
    for(unsigned i = kDigestBytes; i-- > 0; crc >>= 8)
        mHash[i] = static_cast<unsigned char>(crc);
    return mHash;
}
#endif
