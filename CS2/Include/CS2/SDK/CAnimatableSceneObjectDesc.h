#pragma once
#include <cstdint>

struct VTableFunctionInfo;

namespace CS2 {
    
    template <typename T>
    class CStrongHandle;
    
    using CMaterial2 = void;
    class CBaseSceneData;

    struct CAnimatableSceneObjectDescRenderHookData
    {
        uint64_t originalFunc;
        CStrongHandle<CMaterial2>* hMaterialToUse;
        bool bChamsEnabled;
        uint8_t r;
        uint8_t g;
        uint8_t b;
        uint8_t a;
        char weaponStr[8];
        uintptr_t pStrstr;
    };

    class CAnimatableSceneObjectDesc
    {
    private:
        inline static bool m_bIsHooked = false;
        inline static void* m_pDataRemote = nullptr;
        inline static void* m_pShellcodeRemote = nullptr;
        inline static uintptr_t m_pTargetFunction = 0;

        static void* __fastcall RenderObjects_Hook_Shellcode(
            uint64_t a1, uint64_t a2, CBaseSceneData* a3, int32_t a4,
            uint64_t a5, uint64_t a6, uint64_t a7);
        static void RenderObjects_Hook_Shellcode_End();

        static uintptr_t FindRendererFn();

        static VTableFunctionInfo FindVTableDataForRendererFunction();
    public:

        static bool InstallRendererHook(CStrongHandle<CMaterial2>* hMaterialToUse);

        static bool UninstallRendererHook();

        static CAnimatableSceneObjectDescRenderHookData GetExecutionData();
        static void SetChamsEnabled(bool bActive);
        static void SetChamsMaterial(CStrongHandle<CMaterial2>* mat);
        static void SetChamsColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a, bool bLog = false);

        static bool IsHooked() { return m_bIsHooked; }
    };

}