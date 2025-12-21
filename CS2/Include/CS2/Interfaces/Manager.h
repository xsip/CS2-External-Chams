#pragma once
#include <GlobalData/Include.h>
#include <string>
namespace CS2 {

	class CMaterialSystem2;
	class CInterfaceManager {
	private:
		template <typename T>
		using CreateInterfaceFn = T * (__thiscall*)(const char* interfaceName, int unknown);

	public:
		inline static CMaterialSystem2* pMaterialSystem = nullptr;
		template <typename T>
		inline static T* CreateInterface(std::string module, std::string interfaceName) {
			auto m = ::Globals::proc.GetRemoteModule(module);
			auto fn = (CInterfaceManager::CreateInterfaceFn<T>)m->GetProcAddress("CreateInterface");
			return (T*)fn(interfaceName.c_str(), NULL);
		}

		inline static void Initialize() {
			pMaterialSystem = CreateInterface<CMaterialSystem2>("materialsystem2.dll", "VMaterialSystem2_001");
			LogAll();
		}

		inline static void LogAll() {
			printf("[+] Interfaces\n");
			printf("[+] CMaterialSystem2: 0x%p\n\n", pMaterialSystem);
		}
	};

	using I = CInterfaceManager;

}