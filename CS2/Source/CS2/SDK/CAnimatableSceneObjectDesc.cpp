#include <CS2/SDK/CAnimatableSceneObjectDesc.h>
#include <CS2/SDK/CBaseSceneData.h>
#include <CS2/SDK/CStrongHandle.h>
#include <GlobalData/Include.h>
#include <string>

using namespace Globals;

#define CANIMATABLE_SCENE_OBJECT_DESC_RENDER_FN_PATTERN "48 8B C4 53 57 41 54 48 81 EC ?? ?? ?? ?? 49 63 F9 49"

namespace CS2 {

    static void* g_pOriginalRenderObjects = nullptr;
    static CAnimatableSceneObjectDescRenderHookData* g_pHookData = nullptr;

#pragma code_seg(".CAnimatableSceneObjectDescRenderHookSection")
#pragma optimize("", off)

    void* __fastcall CAnimatableSceneObjectDesc::RenderObjects_Hook_Shellcode(
        uint64_t a1, uint64_t a2, CBaseSceneData* a3, int32_t a4,
        uint64_t a5, uint64_t a6, uint64_t a7)
    {
        CAnimatableSceneObjectDescRenderHookData* data = g_pHookData;

        typedef void* (__fastcall* RenderObjectsFn)(uint64_t, uint64_t, CBaseSceneData*, int32_t, uint64_t, uint64_t, uint64_t);
        RenderObjectsFn original = (RenderObjectsFn)g_pOriginalRenderObjects;

        if (!data) {
            return original(a1, a2, a3, a4, a5, a6, a7);
        }


        auto pModelImpl = *reinterpret_cast<uintptr_t*>(
            *reinterpret_cast<uintptr_t*>(
                *reinterpret_cast<uintptr_t*>(
                    reinterpret_cast<uintptr_t>(a3)
                    ) + 0x8
                ));

        auto pModelStr = *reinterpret_cast<const char**>(pModelImpl + 0x8);

        typedef char* (__cdecl* StrstrFn)(const char*, const char*);
        StrstrFn strstr_fn = (StrstrFn)data->pStrstr;

        if (strstr_fn(pModelStr, data->weaponStr)) {
            return original(a1, a2, a3, a4, a5, a6, a7);
        }


        if (data->bChamsEnabled) {

            for (int i = 0; i < a4; ++i)
            {
                auto scene = &a3[i];
                if (scene) {
                    scene->r = data->r;
                    scene->g = data->g;
                    scene->b = data->b;
                    scene->a = data->a;
                    if (data->hMaterialToUse) {
                        scene->material = data->hMaterialToUse->pData;
                        scene->material2 = data->hMaterialToUse->pData;
                    }
                }
            }
        }

        return original(a1, a2, a3, a4, a5, a6, a7);
    }

    void CAnimatableSceneObjectDesc::RenderObjects_Hook_Shellcode_End() {}

#pragma optimize("", on)
#pragma code_seg()

    uintptr_t CAnimatableSceneObjectDesc::FindRendererFn()
    {
        auto sceneSystemDll = proc.GetRemoteModule("scenesystem.dll");
        if (!sceneSystemDll || !sceneSystemDll->IsValid()) {
            printf("[!] Failed to get scenesystem.dll\n");
            return 0;
        }


        uint8_t* addr = sceneSystemDll->ScanMemory(CANIMATABLE_SCENE_OBJECT_DESC_RENDER_FN_PATTERN);
        if (!addr) {
            printf("Failed to find CAnimatableSceneObjectDesc::Render pattern\n");
            return 0;
        }

        uintptr_t renderObjectsAddr = reinterpret_cast<uintptr_t>(addr);
        return renderObjectsAddr;
    }

    VTableFunctionInfo CAnimatableSceneObjectDesc::FindVTableDataForRendererFunction()
    {

        uintptr_t renderObjectsPtr = FindRendererFn();
        if (!renderObjectsPtr) {
            return { -1, 0 };
        }

        return proc.FindVTableContainingFunction(renderObjectsPtr, "scenesystem.dll");

    }

    bool CAnimatableSceneObjectDesc::InstallRendererHook(CStrongHandle<CMaterial2>* hMaterialToUse)
    {
        if (m_bIsHooked) {
            printf("CAnimatableSceneObjectDesc::Render Hook already installed\n");
            return false;
        }

        printf("[+] Trying to hook CAnimatableSceneObjectDesc::Render\n");

        VTableFunctionInfo vtableInfo = FindVTableDataForRendererFunction();
        if (vtableInfo.vTableAddr == 0 || vtableInfo.index < 0) {
            printf("Couldn't find render function VTable Pointer!");
            return false;
        }

        m_pTargetFunction = vtableInfo.vTableAddr + (vtableInfo.index * 8);

        uint64_t originalFunc = proc.ReadDirect<uint64_t>(m_pTargetFunction);
        g_pOriginalRenderObjects = reinterpret_cast<void*>(originalFunc);
        printf("OriginalFunc: 0x%p\n", originalFunc);

        m_pDataRemote = proc.Alloc(sizeof(CAnimatableSceneObjectDescRenderHookData));
        if (!m_pDataRemote) {
            printf("Failed to allocate CAnimatableSceneObjectDescRenderHookData\n");
            return false;
        }

        CAnimatableSceneObjectDescRenderHookData data{};
        data.originalFunc = originalFunc;

        data.hMaterialToUse = hMaterialToUse;
        data.bChamsEnabled = false;

        data.r = 255;
        data.g = 255;
        data.b = 255;
        data.a = 25;

        data.pStrstr = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ucrtbase.dll"), "strstr"));

        strcpy_s(data.weaponStr, sizeof(data.weaponStr), "weapon");


        if (!proc.Write<CAnimatableSceneObjectDescRenderHookData>(reinterpret_cast<uintptr_t>(m_pDataRemote), data)) {
            printf("Failed to write CAnimatableSceneObjectDescRenderHookData\n");
            return false;
        }

        m_pShellcodeRemote = proc.AllocAndWriteShellcode(
            RenderObjects_Hook_Shellcode,
            RenderObjects_Hook_Shellcode_End
        );
        if (!m_pShellcodeRemote) {
            printf("Failed to write hook shellcode\n");
            return false;
        }

        uintptr_t localShellcodeStart = reinterpret_cast<uintptr_t>(RenderObjects_Hook_Shellcode);
        uintptr_t localShellcodeEnd = reinterpret_cast<uintptr_t>(RenderObjects_Hook_Shellcode_End);
        size_t shellcodeSize = localShellcodeEnd - localShellcodeStart;
        uint8_t* localCode = reinterpret_cast<uint8_t*>(localShellcodeStart);
        uintptr_t localDataPtr = reinterpret_cast<uintptr_t>(&g_pHookData);

        bool foundDataPtr = false;

        void* pDataPtrStorage = proc.Alloc(8);
        if (!pDataPtrStorage) {
            printf("Failed to allocate data pointer storage\n");
            return false;
        }

        if (!proc.Write<uint64_t>(reinterpret_cast<uintptr_t>(pDataPtrStorage),
            reinterpret_cast<uint64_t>(m_pDataRemote))) {
            printf("Failed to write data pointer\n");
            return false;
        }

        for (size_t i = 0; i < shellcodeSize - 7; i++) {
            if (localCode[i] == 0x48 && localCode[i + 1] == 0x8B && localCode[i + 2] == 0x05) {
                uintptr_t instructionAddr = reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i;
                uintptr_t targetAddr = reinterpret_cast<uintptr_t>(pDataPtrStorage);
                int32_t newOffset = static_cast<int32_t>(targetAddr - (instructionAddr + 7));

                if (!proc.Write<int32_t>(instructionAddr + 3, newOffset)) {
                    printf("Failed to patch RIP offset for m_pDataRemote\n");
                    return false;
                }

                foundDataPtr = true;
                break;
            }
        }


        uintptr_t localOrigPtr = reinterpret_cast<uintptr_t>(&g_pOriginalRenderObjects);
        bool foundOrigPtr = false;


        void* pOrigPtrStorage = proc.Alloc(8);
        if (!pOrigPtrStorage) {
            printf("Failed to allocate orig pointer storage\n");
            return false;
        }

        if (!proc.Write<uint64_t>(reinterpret_cast<uintptr_t>(pOrigPtrStorage), originalFunc)) {
            printf("Failed to write original pointer\n");
            return false;
        }

        int ripLoadCount = 0;
        int patchedOrigCount = 0;

        for (size_t i = 0; i < shellcodeSize - 7; i++) {
            if (localCode[i] == 0x48 && localCode[i + 1] == 0x8B && localCode[i + 2] == 0x05) {
                ripLoadCount++;

                if (ripLoadCount == 1) continue;

                uintptr_t instructionAddr = reinterpret_cast<uintptr_t>(m_pShellcodeRemote) + i;
                uintptr_t targetAddr = reinterpret_cast<uintptr_t>(pOrigPtrStorage);
                int32_t newOffset = static_cast<int32_t>(targetAddr - (instructionAddr + 7));

                if (!proc.Write<int32_t>(instructionAddr + 3, newOffset)) {
                    printf("Failed to patch RIP offset for g_pOriginalRenderObjects at 0x%zX\n", i);
                    return false;
                }

                patchedOrigCount++;
                foundOrigPtr = true;
            }
        }

        if (patchedOrigCount == 0) {
            printf("Could not find any g_pOriginalRenderObjects references!\n");
            return false;
        }

        DWORD oldProtect;
        if (!VirtualProtectEx(proc.m_hProc, reinterpret_cast<void*>(m_pTargetFunction),
            8, PAGE_READWRITE, &oldProtect)) {
            printf("VirtualProtectEx failed: %d\n", GetLastError());
            return false;
        }

        if (!proc.Write<uint64_t>(m_pTargetFunction, reinterpret_cast<uint64_t>(m_pShellcodeRemote))) {
            printf("Failed to write hook to VTable\n");
            VirtualProtectEx(proc.m_hProc, reinterpret_cast<void*>(m_pTargetFunction),
                8, oldProtect, &oldProtect);
            return false;
        }

        VirtualProtectEx(proc.m_hProc, reinterpret_cast<void*>(m_pTargetFunction),
            8, oldProtect, &oldProtect);

        m_bIsHooked = true;
        printf("[+] CAnimatableSceneObjectDesc::Render Hooked\n");
        return true;
    }

    bool CAnimatableSceneObjectDesc::UninstallRendererHook()
    {
        if (!m_bIsHooked) {
            printf("Hook not installed\n");
            return false;
        }

        printf("[+] Trying to unhook CAnimatableSceneObjectDesc::Render\n");

        uint64_t originalFunc = reinterpret_cast<uint64_t>(g_pOriginalRenderObjects);

        DWORD oldProtect;
        if (!VirtualProtectEx(proc.m_hProc, reinterpret_cast<void*>(m_pTargetFunction),
            8, PAGE_READWRITE, &oldProtect)) {
            printf("VirtualProtectEx failed: %d\n", GetLastError());
            return false;
        }

        if (!proc.Write<uint64_t>(m_pTargetFunction, originalFunc)) {
            printf("Failed to restore VTable entry\n");
            VirtualProtectEx(proc.m_hProc, reinterpret_cast<void*>(m_pTargetFunction),
                8, oldProtect, &oldProtect);
            return false;
        }

        VirtualProtectEx(proc.m_hProc, reinterpret_cast<void*>(m_pTargetFunction),
            8, oldProtect, &oldProtect);

        printf("[+] CAnimatableSceneObjectDesc::Render hook uninstalled\n");

        m_bIsHooked = false;

        return true;
    }

    CAnimatableSceneObjectDescRenderHookData CAnimatableSceneObjectDesc::GetExecutionData()
    {
        CAnimatableSceneObjectDescRenderHookData data{};
        if (m_pDataRemote) {
            proc.Read(reinterpret_cast<uintptr_t>(m_pDataRemote), &data, sizeof(CAnimatableSceneObjectDescRenderHookData));
        }
        return data;
    }

    void CAnimatableSceneObjectDesc::SetChamsEnabled(bool bActive) {
        if (!m_pDataRemote) return;

        proc.Write<bool>(
            reinterpret_cast<uintptr_t>(m_pDataRemote) + offsetof(CAnimatableSceneObjectDescRenderHookData, bChamsEnabled),
            bActive
        );

        printf("[+] Chams %s\n", bActive ? "enabled" : "disabled");

    }

    void CAnimatableSceneObjectDesc::SetChamsColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a, bool bLog) {
        if (!m_pDataRemote) return;

        proc.Write<uint8_t>(
            reinterpret_cast<uintptr_t>(m_pDataRemote) + offsetof(CAnimatableSceneObjectDescRenderHookData, r),
            r
        );

        proc.Write<uint8_t>(
            reinterpret_cast<uintptr_t>(m_pDataRemote) + offsetof(CAnimatableSceneObjectDescRenderHookData, g),
            g
        );

        proc.Write<uint8_t>(
            reinterpret_cast<uintptr_t>(m_pDataRemote) + offsetof(CAnimatableSceneObjectDescRenderHookData, b),
            b
        );

        proc.Write<uint8_t>(
            reinterpret_cast<uintptr_t>(m_pDataRemote) + offsetof(CAnimatableSceneObjectDescRenderHookData, a),
            a
        );
        if(bLog)
            printf("[+] Chams Color override: %i %i %i %i\n", r, g, b, a);

    }

    void CAnimatableSceneObjectDesc::SetChamsMaterial(CStrongHandle<CMaterial2>* mat) {
        if (!m_pDataRemote) return;

        proc.Write<CStrongHandle<CMaterial2>*>(
            reinterpret_cast<uintptr_t>(m_pDataRemote) + offsetof(CAnimatableSceneObjectDescRenderHookData, hMaterialToUse),
            mat
        );

        printf("[+] Setting Chams Material: 0x%p\n", mat);

    }


}