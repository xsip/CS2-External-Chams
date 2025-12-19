# CS2 External Chams

**External chams implementation for Counter-Strike 2 using External VTable hooking and material system manipulation**

---

## Preview ( YouTube )

[![CS2 Chams Demo](https://img.youtube.com/vi/7CccI0PBaG4/maxres1.jpg)](https://www.youtube.com/watch?v=7CccI0PBaG4)

---

## Overview

CS2 External Chams is a Reverse engineering project that implements material-based chams (colored player highlighting) for Counter-Strike 2 without DLL injection. The project demonstrates:

- **External VTable Hooking** - Hook rendering functions from outside the game process
- **Source 2 Material System Integration** - Create custom materials using CS2's material system
- **Remote Code Execution** - Execute complex functions in the target process via shellcode injection

---

## Features

✨ **Full Material-Based Chams** - True material replacement using CS2's material system, not just glow effects  
🎯 **External Operation** - No DLL injection required, operates entirely from external process  
🔧 **Dynamic Hook Management** - Install/uninstall hooks at runtime without game restart  
🎨 **Real-time Color Control** - Change chams colors on the fly with keyboard controls  
🛡️ **Weapon Filtering** - Automatically excludes weapon models from highlighting  
🔃 **Auto Update** - Pattern Scan instead of hardcoded offsets  

---


---

## Usage Example

```c++
int main(int argc, char* argv[]) {

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

```

--- 

## Information

Compile in Release mode

---

## Credits

Unknowncheats for structures like ```CBaseSceneData``` or information on how ```CAnimatableSceneObjectDesc::Render``` works.

