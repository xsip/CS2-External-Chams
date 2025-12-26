#include <CS2/Interfaces/Manager.h>
#include <CS2/Interfaces/CGameResourceService.h>

namespace CS2 {
	void CInterfaceManager::LogAll() {
		printf("[+] Interfaces\n");
		printf("[+] CMaterialSystem2: 0x%p\n", pMaterialSystem);
		printf("[+] CGameResourceService: 0x%p\n", pGameResourceService);
		printf("[+] CGameEntitySystem: 0x%p\n\n", pGameResourceService->GetGameEntitySystem());
	}
}