#pragma once
#include <cstdint>

namespace CS2 {

    class CSceneObject
    {
    private:
        char pad_0000[0xB8];
    public:
        uint8_t r;
        uint8_t g;
        uint8_t b;
        uint8_t a;
    private:
        char pad_00BC[0xC4];
    };

    class CBaseSceneData
    {
    private:
        char pad_0000[0x18];
    public:
        CSceneObject* sceneObject;
        void* material;
        void* material2;
    private:
        char pad[0x20];
    public:
        uint8_t r;
        uint8_t g;
        uint8_t b;
        uint8_t a;
    private:
        char pad_0044[0x14];
    };
    static_assert(sizeof(CBaseSceneData) == 0x68);
}