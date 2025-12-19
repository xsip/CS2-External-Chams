#pragma once
#include <cstdint>

namespace CS2 {

    struct KV3ID_t
    {
        const char* szName;
        std::uint64_t unk0;
        std::uint64_t unk1;

    };

    class CKeyValues3 {
    private:
        char padd[0x100];
    public:
        std::uint64_t uKey;
        void* pValue;
    private:
        char pad[0x8];
    };

}