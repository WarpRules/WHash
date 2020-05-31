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
    using CRC14_gsm = CRC<std::uint16_t, 14, 0x202d, 0x0000, 0x3FFF, false>;
    using CRC15_can = CRC<std::uint16_t, 15, 0x4599, 0x0000, 0x0000, false>;
    using CRC15_mpt1327 = CRC<std::uint16_t, 15, 0x6815, 0x0000, 0x0001, false>;

    using CRC16_arc = CRC<std::uint16_t, 16, 0x8005, 0x0000, 0x0000, true>;
    using CRC16_cdma2000 = CRC<std::uint16_t, 16, 0xC867, 0xFFFF, 0x0000, false>;
    using CRC16_cms = CRC<std::uint16_t, 16, 0x8005, 0xFFFF, 0x0000, false>;
    using CRC16_dds110 = CRC<std::uint16_t, 16, 0x8005, 0x800D, 0x0000, false>;
    using CRC16_dectr = CRC<std::uint16_t, 16, 0x0589, 0x0000, 0x0001, false>;
    using CRC16_dectx = CRC<std::uint16_t, 16, 0x0589, 0x0000, 0x0000, false>;
    using CRC16_dnp = CRC<std::uint16_t, 16, 0x3D65, 0x0000, 0xFFFF, true>;
    using CRC16_en13757 = CRC<std::uint16_t, 16, 0x3D65, 0x0000, 0xFFFF, false>;
    using CRC16_genibus = CRC<std::uint16_t, 16, 0x1021, 0xFFFF, 0xFFFF, false>;
    using CRC16_gsm = CRC<std::uint16_t, 16, 0x1021, 0x0000, 0xFFFF, false>;
    using CRC16_ibm3740 = CRC<std::uint16_t, 16, 0x1021, 0xFFFF, 0x0000, false>;
    using CRC16_ibmsdlc = CRC<std::uint16_t, 16, 0x1021, 0xFFFF, 0xFFFF, true>;
    using CRC16_iso = CRC<std::uint16_t, 16, 0x1021, 0x6363, 0x0000, true>;
    using CRC16_kermit = CRC<std::uint16_t, 16, 0x1021, 0x0000, 0x0000, true>;
    using CRC16_lj1200 = CRC<std::uint16_t, 16, 0x6F63, 0x0000, 0x0000, false>;
    using CRC16_maxim = CRC<std::uint16_t, 16, 0x8005, 0x0000, 0xFFFF, true>;
    using CRC16_mcrf4xx = CRC<std::uint16_t, 16, 0x1021, 0xFFFF, 0x0000, true>;
    using CRC16_modbus = CRC<std::uint16_t, 16, 0x8005, 0xFFFF, 0x0000, true>;
    using CRC16_nrsc5 = CRC<std::uint16_t, 16, 0x080B, 0xFFFF, 0x0000, true>;
    using CRC16_opensafetya = CRC<std::uint16_t, 16, 0x5935, 0x0000, 0x0000, false>;
    using CRC16_opensafetyb = CRC<std::uint16_t, 16, 0x755B, 0x0000, 0x0000, false>;
    using CRC16_profibus = CRC<std::uint16_t, 16, 0x1DCF, 0xFFFF, 0xFFFF, false>;
    using CRC16_riello = CRC<std::uint16_t, 16, 0x1021, 0x554D, 0x0000, true>;
    using CRC16_spifujitsu = CRC<std::uint16_t, 16, 0x1021, 0x1D0F, 0x0000, false>;
    using CRC16_t10dif = CRC<std::uint16_t, 16, 0x8BB7, 0x0000, 0x0000, false>;
    using CRC16_teledisk = CRC<std::uint16_t, 16, 0xA097, 0x0000, 0x0000, false>;
    using CRC16_tms37157 = CRC<std::uint16_t, 16, 0x1021, 0x3791, 0x0000, true>;
    using CRC16_umts = CRC<std::uint16_t, 16, 0x8005, 0x0000, 0x0000, false>;
    using CRC16_usb = CRC<std::uint16_t, 16, 0x8005, 0xFFFF, 0xFFFF, true>;
    using CRC16_xmodem = CRC<std::uint16_t, 16, 0x1021, 0x0000, 0x0000, false>;

    using CRC17_canfd = CRC<std::uint32_t, 17, 0x1685B, 0x00000, 0x00000, false>;
    using CRC21_canfd = CRC<std::uint32_t, 21, 0x102899, 0x00000, 0x00000, false>;
    using CRC24_ble = CRC<std::uint32_t, 24, 0x00065B, 0x555555, 0x00000, true>;
    using CRC24_flexraya = CRC<std::uint32_t, 24, 0x5D6DCB, 0xFEDCBA, 0x00000, false>;
    using CRC24_flexrayb = CRC<std::uint32_t, 24, 0x5D6DCB, 0xABCDEF, 0x00000, false>;
    using CRC24_interlaken = CRC<std::uint32_t, 24, 0x328B63, 0xFFFFFF, 0xFFFFFF, false>;
    using CRC24_ltea = CRC<std::uint32_t, 24, 0x864CFB, 0x000000, 0x000000, false>;
    using CRC24_lteb = CRC<std::uint32_t, 24, 0x800063, 0x000000, 0x000000, false>;
    using CRC24_openpgp = CRC<std::uint32_t, 24, 0x864CFB, 0xB704CE, 0x000000, false>;
    using CRC24_os9 = CRC<std::uint32_t, 24, 0x800063, 0xFFFFFF, 0xFFFFFF, false>;
    using CRC30_cdma = CRC<std::uint32_t, 30, 0x2030B9C7, 0x3FFFFFFF, 0x3FFFFFFF, false>;
    using CRC31_philips = CRC<std::uint32_t, 31, 0x04c11db7, 0x7fffffff, 0x7fffffff, false>;

    using CRC32_aixm = CRC<std::uint32_t, 32, 0x814141ab, 0x0, 0x0, false>;
    using CRC32_autosar = CRC<std::uint32_t, 32, 0xf4acfb13, 0xFFFFFFFF, 0xFFFFFFFF, true>;
    using CRC32_base91d = CRC<std::uint32_t, 32, 0xa833982b, 0xFFFFFFFF, 0xFFFFFFFF, true>;
    using CRC32_bzip2 = CRC<std::uint32_t, 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, false>;
    using CRC32_cdromedc = CRC<std::uint32_t, 32, 0x8001801b, 0x0, 0x0, true>;
    using CRC32_cksum = CRC<std::uint32_t, 32, 0x04C11DB7, 0x0, 0xFFFFFFFF, false>;
    using CRC32_iscsi = CRC<std::uint32_t, 32, 0x1edc6f41, 0xFFFFFFFF, 0xFFFFFFFF, true>;
    using CRC32_isohdlc = CRC<std::uint32_t, 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true>;
    using CRC32_jamcrc = CRC<std::uint32_t, 32, 0x04c11db7, 0xFFFFFFFF, 0x0, true>;
    using CRC32_mpeg2 = CRC<std::uint32_t, 32, 0x04c11db7, 0xFFFFFFFF, 0x0, false>;
    using CRC32_xfer = CRC<std::uint32_t, 32, 0x000000af, 0x0, 0x0, false>;

    using CRC40_gsm = CRC<std::uint64_t, 40, 0x0004820009, 0x0, 0xffffffffff, false>;
    using CRC64_ecma182 = CRC<std::uint64_t, 64, 0x42f0e1eba9ea3693, 0x0, 0x0, false>;
    using CRC64_goiso = CRC<std::uint64_t, 64, 0x1B, 0xffffffffffffffff, 0xffffffffffffffff, true>;
    using CRC64_we = CRC<std::uint64_t, 64, 0x42f0e1eba9ea3693, 0xffffffffffffffff, 0xffffffffffffffff, false>;
    using CRC64_xz = CRC<std::uint64_t, 64, 0x42f0e1eba9ea3693, 0xffffffffffffffff, 0xffffffffffffffff, true>;
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
            CRCvalue_t crc = static_cast<CRCvalue_t>(inputByte) << (kBits - 8);
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
    if constexpr(kBits < 8*sizeof(CRCvalue_t)) mCRC &= (CRCvalue_t(1) << kBits) - 1;

    mCRC ^= kXorOut;

    if constexpr(kReflectedInput != kReflectedOutput)
        mCRC = reflectedValue<CRCvalue_t, kBits>(mCRC);

    CRCvalue_t crc = mCRC;
    for(unsigned i = kDigestBytes; i-- > 0; crc >>= 8)
        mHash[i] = static_cast<unsigned char>(crc);
    return mHash;
}
#endif
