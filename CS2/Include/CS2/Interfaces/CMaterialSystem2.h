#pragma once
#include <Windows.h>
#include <string>
namespace CS2 {

    template <typename T>
    class CStrongHandle;

    class CKeyValues3;
    
    using CMaterial2 = void;
    class CMaterialSystem2;

    struct CreateMaterialCtx {
        CKeyValues3* kv;
        void* loadKv3;
        void* createMaterial;
        CStrongHandle<CMaterial2>* pCreatedMaterial;
        CMaterialSystem2* pMaterialSystem;
        const char* szMat;
        const char* szMatName;
        const char* szKvIdName;
        bool bHadErrors;
        bool bFinished;
    };

    class CMaterialSystem2 {
    public:


        inline static std::string GetLatexChams() {
            return R"(<!-- kv3 encoding:text:version{e21c7f3c-8a33-41c5-9977-a76d3a32aa0d}
			format:generic:version{7412167c-06e9-4698-aff2-e63eb59037e7} -->
			{
                shader = "csgo_character.vfx"
                F_DISABLE_Z_BUFFERING = 1
                F_DISABLE_Z_PREPASS = 1
                F_DISABLE_Z_WRITE = 1
                F_BLEND_MODE = 1
                g_vColorTint = [1.0, 1.0, 1.0, 1.0]
                g_bFogEnabled = 0
                g_flMetalness = 0.000
                g_tColor = resource:"materials/dev/primary_white_color_tga_21186c76.vtex"
                g_tAmbientOcclusion = resource:"materials/default/default_ao_tga_79a2e0d0.vtex"
                g_tNormal = resource:"materials/default/default_normal_tga_1b833b2a.vtex"
                g_tMetalness = resource:"materials/default/default_metal_tga_8fbc2820.vtex"
			})";
        }

        CStrongHandle<CMaterial2>* CreateMaterial(std::string szMaterial, std::string szMatName);
    };
}