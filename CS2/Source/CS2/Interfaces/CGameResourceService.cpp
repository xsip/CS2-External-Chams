#include <CS2/Interfaces/CGameResourceService.h>
#include <cstddef>
namespace CS2 {
	CGameEntitySystem* CGameResourceService::GetGameEntitySystem() {
		return  *reinterpret_cast<CGameEntitySystem**>(reinterpret_cast<uintptr_t>(this) + 0x58);
	}
}