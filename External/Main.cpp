#include <External/Include.h>

#include <CS2/Interfaces/Manager.h>
#include <CS2/SDK/CAnimatableSceneObjectDesc.h>
#include <CS2/Interfaces/CMaterialSystem2.h>
#include <CS2/Interfaces/CGameEntitySystem.h>
#include <CS2/Interfaces/CGameResourceService.h>
#include <CS2/SDK/CBaseHandle.h>
#include <cmath>

namespace Globals {
	Process proc{ "cs2.exe" };
}

using namespace Globals;
using namespace CS2;

int main(int argc, char* argv[]) {
	SetConsoleTitle("xsip's external cs2 chams");
	I::Initialize();
	
	auto hLatexChamsMaterial = I::pMaterialSystem->CreateMaterial(CMaterialSystem2::GetLatexChams(), "LatexChamsMaterial");

	if (!hLatexChamsMaterial) {
		printf("Couldn't create Material!!\n");
		return 0;
	}

	if (!CAnimatableSceneObjectDesc::InstallRendererHook(nullptr)) {
		printf("Error Installing CAnimatableSceneObjectDesc hook!!\n");
		return 0;
	}

	CAnimatableSceneObjectDesc::SetChamsColor(0, 35, 255, 255);
	CAnimatableSceneObjectDesc::SetChamsMaterial(hLatexChamsMaterial);
	
	bool bShouldShowChams = false;
	float hue = 0.0f;

	while (!GetAsyncKeyState(VK_DELETE)) {

		if (GetAsyncKeyState(VK_LSHIFT) & 1) {
			bShouldShowChams = !bShouldShowChams;
			CAnimatableSceneObjectDesc::SetChamsEnabled(bShouldShowChams);
			Sleep(100);
		} else if (GetAsyncKeyState(VK_RSHIFT) & 1) {
			while (!GetAsyncKeyState(VK_UP) && !GetAsyncKeyState(VK_DELETE)) {
				float r = std::abs(std::sin(hue) * 255.0f);
				float g = std::abs(std::sin(hue + 2.09f) * 255.0f);
				float b = std::abs(std::sin(hue + 4.18f) * 255.0f);

				CAnimatableSceneObjectDesc::SetChamsColor(
					(uint8_t)r, (uint8_t)g, (uint8_t)b, 255
				);

				hue += 0.01f;
				if (hue > 6.28f) hue = 0.0f;
				Sleep(16);
			}
			Sleep(100);
		}
		else if (GetAsyncKeyState(VK_LEFT) & 1) {
			CAnimatableSceneObjectDesc::SetChamsColor(0, 35, 255, 255);
			Sleep(100);
		}
		else if (GetAsyncKeyState(VK_RIGHT) & 1) {
			CAnimatableSceneObjectDesc::SetChamsColor(255, 35, 0, 255);

			Sleep(100);
		}

	}

	if (!CAnimatableSceneObjectDesc::UninstallRendererHook()) {
		printf("Error uninstalling draw CAnimatableSceneObjectDesc hook!!\n");
		return 0;
	}

	return 0;
}