#pragma once
#include <GlobalData/Include.h>
#include <array>
#include <thread> 
#include <atomic>

namespace CS2 {

    namespace client {
        class C_CSPlayerPawn;
        class CCSPlayerController;
    }

    class Entity {
    public:
        bool m_bIsValid{};
        bool m_bIsAlive{};
        CS2::client::C_CSPlayerPawn* m_pPawn{};
        CS2::client::CCSPlayerController* m_pController{};
        bool m_bIsLocalPlayer{};
        bool m_bIsVisible{};
        float flAimbotFov{};
        int headBoneIdx{};
        int ankleBoneIdx{};
        int m_iBoneCount{};
        int m_iPawnIndex{};
    };

    class CGameEntitySystem
    {
    public:
        inline static Entity vEntityList[65]{};

        template< typename T = void>
        T* GetEntityByIndex(int entityIdx)
        {
            if (entityIdx < 0 || entityIdx > 0x7FFE)
                return nullptr;

            uintptr_t bucketsBase = reinterpret_cast<uintptr_t>(this) + 16;

            int bucketIndex = entityIdx >> 9;
            if (bucketIndex > 0x3F)
                return nullptr;

            uintptr_t bucketPtr = ::Globals::proc.ReadDirect<uintptr_t>(bucketsBase + sizeof(uintptr_t) * bucketIndex);
            if (!bucketPtr)
                return nullptr;

            int slotIndex = entityIdx & 0x1FF;
            uintptr_t entry = bucketPtr + 112ull * slotIndex;
            if (!entry)
                return nullptr;

            int storedIndex = ::Globals::proc.ReadDirect<int>(entry + 16);
            if ((storedIndex & 0x7FFF) != entityIdx)
                return nullptr;

            uintptr_t entityPtr = ::Globals::proc.ReadDirect<uintptr_t>(entry);
            return reinterpret_cast<T*>(entityPtr);
        }

    };

}
