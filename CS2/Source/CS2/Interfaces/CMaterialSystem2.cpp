#include <CS2/Interfaces/CMaterialSystem2.h>
#include <CS2/SDK/CKeyValues3.h>
#include <CS2/Interfaces/Manager.h>
#include <CS2/SDK/CStrongHandle.h>

#include <GlobalData/Include.h>
using namespace Globals;

#define CREATE_MATERIAL_FN_PATTERN "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 81 EC ?? ?? ?? ?? 48 8B 05"
#define LOAD_KV3_PROC_ADDRESS "?LoadKV3@@YA_NPEAVKeyValues3@@PEAVCUtlString@@PEBDAEBUKV3ID_t@@2I@Z"
namespace CS2 {
#pragma code_seg(".CreateMaterialSeg")
#pragma optimize("", off)
#pragma runtime_checks("", off)
#pragma check_stack(off)  
	__declspec(safebuffers)
		DWORD WINAPI CreateMaterialThread(LPVOID lpParam) {
		using CMaterial2 = void;

		CreateMaterialCtx* ctx = reinterpret_cast<CreateMaterialCtx*>(lpParam);

		CKeyValues3* kv = (CKeyValues3*)(reinterpret_cast<uint8_t*>(ctx->kv));

		for (int i = 0; i < sizeof(CKeyValues3); i++) {
			reinterpret_cast<uint8_t*>(kv)[i] = 0;
		}

		KV3ID_t kvId;

		kvId.szName = ctx->szKvIdName;
		kvId.unk0 = 0x469806E97412167CULL;
		kvId.unk1 = 0xE73790B53EE6F2AFULL;

		typedef bool(__fastcall* LoadKV3Fn)(CKeyValues3*, void*, const char*, void*, void*);
		LoadKV3Fn LoadKV3 = reinterpret_cast<LoadKV3Fn>(ctx->loadKv3);

		bool result = LoadKV3(kv, 0, ctx->szMat, &kvId, 0);

		if (!result) {
			ctx->bHadErrors = 1;
			ctx->bFinished = 1;
			return 0;
		}


		using CreateMaterialFn = void (*)(void*, CMaterial2**, const char*, CKeyValues3*, int, int);
		CreateMaterialFn CreateMaterial = reinterpret_cast<CreateMaterialFn>(ctx->createMaterial);

		CMaterial2* mat = nullptr;

		CreateMaterial(nullptr, &mat, ctx->szMatName, kv, 0, 1);
		if (mat) {
			ctx->pCreatedMaterial = reinterpret_cast<CStrongHandle<CMaterial2>*>(mat);
			ctx->bHadErrors = 0;
			ctx->bFinished = 1;
			return 1;
		}
		ctx->bHadErrors = 1;
		ctx->bFinished = 1;
		return 1;
	}

	DWORD WINAPI CreateMaterialThreadEnd() { return 0; }
#pragma check_stack()  
#pragma runtime_checks("", restore) 
#pragma optimize("", on)
#pragma code_seg()


	CStrongHandle<CMaterial2>* CMaterialSystem2::CreateMaterial(std::string materialKv3Str, std::string szMatName) {
		printf("[+] Trying to create material \"%s\"\n", szMatName.c_str());
		auto pTier0 = proc.GetRemoteModule("tier0.dll");
		if (!pTier0) {
			printf("Error Finding tier0.dll!!\n");
			return nullptr;
		}


		auto pMaterialSystem2 = proc.GetRemoteModule("materialsystem2.dll");
		if (!pMaterialSystem2) {
			printf("Error Finding materialsystem2.dll!!\n");
			return nullptr;
		}

		auto pLoadKv3 = reinterpret_cast<void*>(pTier0->GetProcAddress(LOAD_KV3_PROC_ADDRESS));
		if (!pLoadKv3) {
			printf("Error Finding LoadKv3!!\n");
			return nullptr;
		}

		auto pCreateMaterialFn = reinterpret_cast<void*>(pMaterialSystem2->ScanMemory(CREATE_MATERIAL_FN_PATTERN));
		if (!pCreateMaterialFn) {
			printf("Error Finding CreateMaterial!!\n");
			return nullptr;
		}

		auto pRemoteMaterialKv3Str = proc.AllocateAndWriteString(materialKv3Str);
		if (!pRemoteMaterialKv3Str) {
			printf("Failed to write remote string for Material Creation!\n");
			return nullptr;
		}

		void* pRemoteKvIdName = proc.AllocateAndWriteString("generic");
		if (!pRemoteKvIdName) {
			printf("Failed to write remote string for KV3 ID name!\n");
			return nullptr;
		}

		void* pRemoteMatName = proc.AllocateAndWriteString(szMatName);
		if (!pRemoteMatName) {
			printf("Failed to write remote string for Material name!\n");
			return nullptr;
		}

		auto pKv3Remote = proc.Alloc(0x100 + sizeof(CKeyValues3));
		if (!pKv3Remote) {
			printf("Error Creating kv3 buffer!\n");
			return nullptr;
		}


		CreateMaterialCtx ctx;

		ctx.bFinished = false;
		ctx.bHadErrors = false;
		ctx.pCreatedMaterial = nullptr;


		ctx.kv = reinterpret_cast<CKeyValues3*>(reinterpret_cast<uintptr_t>(pKv3Remote) + 0x100);
		ctx.loadKv3 = pLoadKv3;


		ctx.createMaterial = pCreateMaterialFn;
		ctx.pMaterialSystem = this;

		ctx.szMat = reinterpret_cast<const char*>(pRemoteMaterialKv3Str);
		ctx.szKvIdName = reinterpret_cast<const char*>(pRemoteKvIdName);
		ctx.szMatName = reinterpret_cast<const char*>(pRemoteMatName);


		void* pRemoteCtx = proc.Alloc(sizeof(CreateMaterialCtx));
		if (!pRemoteCtx) {
			printf("Failed to allocate remote context!\n");
			return nullptr;
		}

		if (!proc.Write<CreateMaterialCtx>(reinterpret_cast<uintptr_t>(pRemoteCtx), ctx)) {
			printf("Failed to write remote context!\n");
			return nullptr;
		}

		void* shellcode = proc.AllocAndWriteShellcode(CreateMaterialThread, CreateMaterialThreadEnd);
		if (!shellcode) {
			printf("Failed to allocate shellcode!\n");
			proc.FreeRemote(pRemoteCtx);
			return nullptr;
		}

		HANDLE hThread = proc.CreateRemoteThreadEx(
			reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
			pRemoteCtx
		);

		if (!hThread) {
			printf("Failed to create remote thread!\n");
			proc.FreeRemote(shellcode);
			proc.FreeRemote(pRemoteCtx);
			return nullptr;
		}

		DWORD waitResult = WaitForSingleObject(hThread, 10000);

		if (waitResult != WAIT_OBJECT_0) {
			printf("Thread wait failed or timed out! Result: %d\n", waitResult);
			CloseHandle(hThread);
			proc.FreeRemote(shellcode);
			proc.FreeRemote(pRemoteCtx);
			return nullptr;
		}

		DWORD exitCode = 0;
		GetExitCodeThread(hThread, &exitCode);
		CloseHandle(hThread);

		CreateMaterialCtx resultCtx;
		if (!proc.Read(reinterpret_cast<uintptr_t>(pRemoteCtx), &resultCtx, sizeof(CreateMaterialCtx))) {
			printf("Failed to read result context!\n");
			proc.FreeRemote(shellcode);
			proc.FreeRemote(pRemoteCtx);
			return nullptr;
		}

		proc.FreeRemote(shellcode);
		proc.FreeRemote(pRemoteCtx);

		if (resultCtx.bHadErrors) {
			printf("[!] Material creation encountered errors!\n");
			return nullptr;
		}

		if (!resultCtx.kv) {
			printf("[!] KeyValues3 pointer is null!\n");
			return nullptr;
		}

		printf("[+] Material creation successful!\n");

		return resultCtx.pCreatedMaterial;
	}
}