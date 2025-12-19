#include <Memory/Process.h>
#include <Utils/Memory/Memory.h>

#include <vector>
#include <stdexcept>
#include <TlHelp32.h>
#include <psapi.h>

RemoteModule::RemoteModule(uintptr_t pBase, uintptr_t pSize, Process* pProc, std::string szDll) :
	m_pSize(pSize),
	m_pBase(pBase),
	m_pProc(pProc),
	m_szDll(szDll),
	m_bIsValid(true) {
}

RemoteModule::RemoteModule() :
	m_pSize(0x0),
	m_pBase(0x0),
	m_pProc(nullptr),
	m_szDll("Invalid"),
	m_bIsValid(false) {
}

bool RemoteModule::Sync() {
	uint8_t* _ModuleBytes = new uint8_t[m_pSize];
	if (!this->m_pProc->Read(m_pBase, _ModuleBytes, m_pSize)) {
		delete[] _ModuleBytes;
		return false;
	}

	if (!m_bAllocated) {
		DWORD oldprotect;
		auto lpvResult = VirtualAlloc(reinterpret_cast<void*>(m_pBase), m_pSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpvResult == NULL) {
			delete[] _ModuleBytes;
			return false;
		}
		VirtualProtect(reinterpret_cast<void*>(m_pBase), m_pSize, PAGE_EXECUTE_READWRITE, &oldprotect);
		m_bAllocated = true;
	}

	memcpy(reinterpret_cast<void*>(m_pBase), reinterpret_cast<void*>(_ModuleBytes), static_cast<size_t>(m_pSize));
	delete[] _ModuleBytes;
	return true;
}

std::vector<RemoteModule::Section> RemoteModule::GetSections()
{
	std::vector<Section> sections;

	if (!m_pBase || !m_pSize) {
		return sections;
	}


	IMAGE_DOS_HEADER dosHeader{};
	if (!m_pProc->Read(m_pBase, &dosHeader, sizeof(IMAGE_DOS_HEADER))) {
		return sections;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		return sections;
	}

	IMAGE_NT_HEADERS ntHeaders{};
	if (!m_pProc->Read(m_pBase + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
		return sections;
	}

	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		return sections;
	}

	uintptr_t sectionHeaderAddr = m_pBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);

	for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
		IMAGE_SECTION_HEADER sectionHeader{};

		if (!m_pProc->Read(sectionHeaderAddr + (i * sizeof(IMAGE_SECTION_HEADER)),
			&sectionHeader, sizeof(IMAGE_SECTION_HEADER))) {
			continue;
		}

		Section section;
		section.name = std::string(reinterpret_cast<char*>(sectionHeader.Name),
			strnlen(reinterpret_cast<char*>(sectionHeader.Name), 8));
		section.addr = m_pBase + sectionHeader.VirtualAddress;
		section.size = sectionHeader.Misc.VirtualSize;

		sections.push_back(section);
	}

	return sections;
}




uint32_t RemoteModule::ResolveDisp32(uint8_t* instr, uint32_t dwSkipBytes)
{
	uint8_t* p = instr + dwSkipBytes;

	uint8_t modrm = p[0];
	uint8_t mod = (modrm >> 6) & 3;

	if (mod != 2) 
		return 0;

	return *reinterpret_cast<const uint32_t*>(p + 1);
}

uint8_t* RemoteModule::ScanMemory(const char* signature) {
	return Memory::ScanMemory(m_pBase, m_pSize, signature);
}

uintptr_t RemoteModule::ResolveRIP(uint8_t* pAddr, DWORD dwRip, DWORD dwSize) {
	return ResolveRIP(reinterpret_cast<uintptr_t>(pAddr), dwRip, dwSize);
}

uintptr_t RemoteModule::ResolveRIP(uintptr_t pAddr, DWORD dwRip, DWORD dwSize) {
	int32_t displacement = *reinterpret_cast<int32_t*>(pAddr + dwRip);
	uintptr_t nextInstr = pAddr + dwSize;
	uintptr_t target = nextInstr + displacement;
	return target;
}

uintptr_t RemoteModule::GetProcAddress(std::string szFnName) {
	auto DTE = m_pBase;
	if (!DTE)
		return 0x0;

	PIMAGE_DOS_HEADER DOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(DTE);
	if (!DOSHeader)
		return 0x0;

	auto NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)DTE + DOSHeader->e_lfanew);
	if (!NTHeaders)
		return 0x0;

	auto ExportsDataDirectory = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!ExportsDataDirectory->Size || !ExportsDataDirectory->VirtualAddress)
		return 0x0;

	auto ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((uint8_t*)DTE + ExportsDataDirectory->VirtualAddress);
	if (!ExportDirectory)
		return 0x0;

	auto AddrFunctions = reinterpret_cast<uint32_t*>((uint8_t*)DTE + ExportDirectory->AddressOfFunctions);
	auto AddrNames = reinterpret_cast<uint32_t*>((uint8_t*)DTE + ExportDirectory->AddressOfNames);
	auto AddrOrdinals = reinterpret_cast<uint16_t*>((uint8_t*)DTE + ExportDirectory->AddressOfNameOrdinals);

	for (uint32_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		auto FnName = reinterpret_cast<const char*>((uint8_t*)DTE + AddrNames[i]);
		if (szFnName == FnName)
		{
			return (uintptr_t)reinterpret_cast<uint32_t*>((uint8_t*)DTE + AddrFunctions[AddrOrdinals[i]]);
		}
	}

	return 0x0;
}


Process::Process(std::string szProcName) {
	new (&remoteModuleList) std::map<std::string, RemoteModule*>{};
	m_szProcName = szProcName;
	GetProcHandle();

#ifdef USE_SYSCALL_MODE
	printf("[+] Syscall mode enabled for process %s (PID: %d)\n\n", szProcName.c_str(), pProcId);
#endif
}

PVOID Process::Alloc(size_t size, DWORD fFLags, DWORD fAccess) {
#ifdef USE_SYSCALL_MODE
	void* pRemote = SyscallManager::AllocateMemoryDirect(m_hProc, size, fAccess);
#else
	void* pRemote = ::VirtualAllocEx(m_hProc, NULL, size, fFLags, fAccess);
#endif

	if (pRemote) {
		TrackAllocation(pRemote);
	}

	return pRemote;
}

void* Process::AllocateAndWriteString(std::string str) {

	size_t strLength = str.length() + 1;
	void* pRemoteStr = Alloc(strLength);
	
	if (!pRemoteStr) {
		printf("Failed to allocate remote string for Material Creation!\n");
		return nullptr;
	}

	if (!WriteString(reinterpret_cast<uintptr_t>(pRemoteStr), str, strLength)) {
		return nullptr;
	}

	return pRemoteStr;
}

VTableFunctionInfo RemoteModule::FindVTableContainingFunction(uintptr_t fn)
{
	if (!IsValid()) {
		return { -1, 0 };
	}

	auto sections = GetSections();

	for (const auto& section : sections) {
		if (section.name == ".rdata") {
			size_t sectionSize = section.size;
			std::vector<uint8_t> sectionData(sectionSize);

			if (!m_pProc->Read(section.addr, sectionData.data(), sectionSize)) {
				continue;
			}

			for (size_t i = 0; i < sectionSize - 8; i += 8) {
				uint64_t* ptrInSection = reinterpret_cast<uint64_t*>(&sectionData[i]);

				if (*ptrInSection == fn) {
					uintptr_t vtableStart = 0;
					int functionIndex = 0;

					size_t backScan = i;
					while (backScan >= 8) {
						backScan -= 8;
						uint64_t* candidatePtr = reinterpret_cast<uint64_t*>(&sectionData[backScan]);

						if (*candidatePtr > GetAddr() &&
							*candidatePtr < GetAddr() + GetSize()) {
							functionIndex++;
						}
						else {
							vtableStart = section.addr + backScan + 8;
							break;
						}
					}

					if (vtableStart == 0) {
						vtableStart = section.addr + (i - (functionIndex * 8));
					}

					if (vtableStart > 0 && functionIndex >= 0) {
						return { functionIndex, vtableStart };
					}
				}
			}
		}
	}

	return { -1, 0 };
}


VTableFunctionInfo Process::FindVTableContainingFunction(uintptr_t fn, std::string szMod)
{
	auto module = GetRemoteModule(szMod);
	if (!module || !module->IsValid()) {
		printf("[!] Failed to get module: %s\n", szMod.c_str());
		return { -1, 0 };
	}
	return module->FindVTableContainingFunction(fn);

}

bool Process::FreeRemote(void* pRemote) {
	if (!pRemote) return false;

#ifdef USE_SYSCALL_MODE
	BOOL result = SyscallManager::FreeMemoryDirect(m_hProc, pRemote);
#else
	BOOL result = ::VirtualFreeEx(m_hProc, pRemote, 0, MEM_RELEASE);
#endif

	if (result) {
		auto it = std::find(m_remoteAllocations.begin(), m_remoteAllocations.end(), pRemote);
		if (it != m_remoteAllocations.end()) {
			m_remoteAllocations.erase(it);
		}
		return true;
	}

	return false;
}

void Process::FreeAllRemote() {
	printf("Cleaning up %zu remote allocations...\n", m_remoteAllocations.size());

	size_t freed = 0;
	for (void* pRemote : m_remoteAllocations) {
#ifdef USE_SYSCALL_MODE
		if (SyscallManager::FreeMemoryDirect(m_hProc, pRemote)) {
#else
		if (::VirtualFreeEx(m_hProc, pRemote, 0, MEM_RELEASE)) {
#endif
			freed++;
		}
		else {
			printf("WARNING: Failed to free allocation at 0x%p (Error: %d)\n",
				pRemote, GetLastError());
		}
		}

	m_remoteAllocations.clear();
		}

RemoteModule* Process::GetRemoteModule(std::string szModuleName) {
	if (remoteModuleList.contains(szModuleName)) {
		return remoteModuleList[szModuleName];
	}

	auto moduleInfo = GetModuleInfoEx(szModuleName);

	if (!moduleInfo.lpBaseOfDll)
		return {};

	auto mod = new RemoteModule((uintptr_t)moduleInfo.lpBaseOfDll, (uintptr_t)moduleInfo.SizeOfImage, this, szModuleName);
	remoteModuleList.insert({ szModuleName , mod });
	if (!remoteModuleList[szModuleName]->Sync()) {
		return {};
	}

	return remoteModuleList[szModuleName];
}

DWORD Process::ExecuteAndCleanup(void* shellcode, void* context, DWORD timeoutMs) {
	HANDLE hThread = CreateRemoteThreadEx(
		reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
		context
	);

	if (!hThread) {
		printf("ERROR: Failed to create remote thread\n");
		FreeRemote(context);
		FreeRemote(shellcode);
		return (DWORD)-1;
	}

	DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);

	if (waitResult == WAIT_TIMEOUT) {
		printf("WARNING: Remote thread timed out after %dms\n", timeoutMs);
		CloseHandle(hThread);
		FreeRemote(context);
		FreeRemote(shellcode);
		return (DWORD)-1;
	}

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	CloseHandle(hThread);

	FreeRemote(context);
	FreeRemote(shellcode);

	return exitCode;
}

HWND Process::GetHwnd() {
	if (m_hWnd)
		return m_hWnd;

	struct EnumData {
		DWORD pid;
		HWND hwnd;
	} data{ pProcId, nullptr };

	auto enumProc = [](HWND hWnd, LPARAM lParam) -> BOOL {
		EnumData* pData = reinterpret_cast<EnumData*>(lParam);
		DWORD wndPid = 0;
		GetWindowThreadProcessId(hWnd, &wndPid);

		if (wndPid == pData->pid && GetWindow(hWnd, GW_OWNER) == nullptr && IsWindowVisible(hWnd)) {
			pData->hwnd = hWnd;
			return FALSE;
		}
		return TRUE;
		};

	EnumWindows(enumProc, reinterpret_cast<LPARAM>(&data));
	m_hWnd = data.hwnd;
	return m_hWnd;
}


bool Process::InitializeSysCalls() {
#ifdef USE_SYSCALL_MODE
	if (!SyscallManager::Initialize()) {
		printf("Failed to initialize syscalls!\n");
		return false;
	}
#endif
	return true;
}

void Process::GetProcHandle() {
#ifdef USE_SYSCALL_MODE
	if (!InitializeSysCalls())
		return;
#endif

	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry)) {
		if (!m_szProcName.compare(entry.szExeFile)) {
			pProcId = entry.th32ProcessID;

#ifdef USE_SYSCALL_MODE
			m_hProc = SyscallManager::OpenProcessDirect(
				pProcId,
				PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
				PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD
			);
#else
			m_hProc = OpenProcess(
				PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
				PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
				FALSE, pProcId
			);
#endif

			break;
		}
	}

	CloseHandle(snapshot);

	if (!m_hProc) {
		printf("Couldn't find Process %s\n", m_szProcName.c_str());
		exit(1);
	}
}

MODULEINFO Process::GetModuleInfoEx(std::string m_Name)
{
	HMODULE m_Modules[1337];
	DWORD m_Needed = 0x0;

	if (!K32EnumProcessModules(m_hProc, m_Modules, sizeof(m_Modules), &m_Needed)) {
		printf("Error: 0x%x\n", GetLastError());
		return {};
	}

	DWORD m_Count = (m_Needed / sizeof(HMODULE));
	for (DWORD i = 0; m_Count > i; ++i)
	{
		char m_ModuleFileName[MAX_PATH] = { 0 };
		if (!K32GetModuleFileNameExA(m_hProc, m_Modules[i], m_ModuleFileName, sizeof(m_ModuleFileName)))
			continue;

		if (strstr(m_ModuleFileName, ("\\" + m_Name).c_str()))
		{
			MODULEINFO m_ModuleInfo = { 0 };
			if (!K32GetModuleInformation(m_hProc, m_Modules[i], &m_ModuleInfo, sizeof(MODULEINFO)))
				return {};
			return m_ModuleInfo;
		}
	}

	return {};
}

uintptr_t MemoryApi::ResolveRIP(uint8_t * pAddr, DWORD dwRip, DWORD dwSize) {
	return MemoryApi::ResolveRIP(reinterpret_cast<uintptr_t>(pAddr), dwRip, dwSize);
}

uintptr_t MemoryApi::ResolveRIP(uintptr_t pAddr, DWORD dwRip, DWORD dwSize) {
	int32_t displacement = *reinterpret_cast<int32_t*>(pAddr + dwRip);
	uintptr_t nextInstr = pAddr + dwSize;
	uintptr_t target = nextInstr + displacement;
	return target;
}

uint8_t* MemoryApi::ScanMemoryIntern(std::string szDllName, const char* signature) {
	auto hModule = GetModuleHandle(szDllName.c_str());
	if (!hModule) return 0;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

	if (!ntHeaders->OptionalHeader.SizeOfImage)
		return nullptr;

	return Memory::ScanMemory(reinterpret_cast<uintptr_t>(hModule), ntHeaders->OptionalHeader.SizeOfImage, signature);
}

void* Process::AllocAndWriteShellcode(void* funcStart, void* funcEnd) {
	SIZE_T size = reinterpret_cast<BYTE*>(funcEnd) - reinterpret_cast<BYTE*>(funcStart);
	void* remoteAddr = Alloc(size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!remoteAddr)
		return nullptr;

	std::vector<uint8_t> bytes(
		reinterpret_cast<uint8_t*>(funcStart),
		reinterpret_cast<uint8_t*>(funcStart) + size
	);

	if (!WriteArray(reinterpret_cast<uintptr_t>(remoteAddr), bytes)) {
		return nullptr;
	}

	return remoteAddr;
}

void Process::TrackAllocation(void* pRemote) {
	if (pRemote) {
		m_remoteAllocations.push_back(pRemote);
	}
}

HANDLE Process::CreateRemoteThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter) {
#ifdef USE_SYSCALL_MODE
	// Need a real handle for CreateRemoteThread
	HANDLE hProc = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
		FALSE, pProcId
	);

	if (!hProc) {
		return NULL;
	}

	HANDLE hThread = CreateRemoteThread(
		hProc,
		NULL,
		0,
		lpStartAddress,
		lpParameter,
		0,
		NULL
	);

	CloseHandle(hProc);
	return hThread;
#else
	// Normal mode - use existing handle
	return CreateRemoteThread(
		m_hProc,
		NULL,
		0,
		lpStartAddress,
		lpParameter,
		0,
		NULL
	);
#endif
}

uintptr_t Process::GetVTable(uintptr_t pThis) noexcept
{
	if (!pThis) return 0;

	uintptr_t vtablePtr = ReadDirect<uintptr_t>(pThis);
	return vtablePtr;
}

std::vector<uintptr_t> Process::ReadVTable(uintptr_t pThis, size_t count) noexcept
{
	std::vector<uintptr_t> vtable;

	if (!pThis) return vtable;

	uintptr_t vtablePtr = ReadDirect<uintptr_t>(pThis);
	if (!vtablePtr) return vtable;

	vtable = ReadArray<uintptr_t>(vtablePtr, count);
	return vtable;
}

void Process::DumpVTable(uintptr_t pThis, size_t count, const char* name) noexcept
{
	printf("=== %s Dump ===\n", name);
	printf("Object: 0x%llX\n", pThis);

	uintptr_t vtablePtr = GetVTable(pThis);
	printf("VTable: 0x%llX\n", vtablePtr);

	if (!vtablePtr) {
		printf("ERROR: VTable pointer is null!\n");
		return;
	}

	auto vtable = ReadVTable(pThis, count);

	for (size_t i = 0; i < vtable.size(); i++) {
		if (vtable[i] == 0) {
			printf("[%2zu] 0x%016llX (null)\n", i, vtable[i]);
		}
		else {
			printf("[%2zu] 0x%016llX\n", i, vtable[i]);
		}
	}
	printf("==================\n");
}