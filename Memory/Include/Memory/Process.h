#pragma once
#include <Windows.h>
#include <map>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>
#include <vector>
#include <Memory/Definitions.h>
#define USE_SYSCALL_MODE
#ifdef USE_SYSCALL_MODE
#include <Memory/SysCall/SyscallManager.h>
#endif
#undef min
#include <algorithm>

class Process;



struct VTableFunctionInfo {
	int index;
	uintptr_t vTableAddr;
};

class MEMORY_API RemoteModule {
private:
	uintptr_t m_pSize{};
	uintptr_t m_pBase{};
	Process* m_pProc{};
	std::string m_szDll{};
	bool m_bIsValid{};
	bool m_bAllocated{};
public:


	struct Section {
		std::string name;
		uintptr_t addr;
		size_t size;
	};

	RemoteModule(uintptr_t pBase, uintptr_t pSize, Process* pProc, std::string szDll = "");
	RemoteModule();
	bool Sync();
	bool IsValid() { return m_bIsValid; };
	uintptr_t GetAddr() { return m_pBase; };
	uintptr_t GetSize() { return m_pSize; };


	std::vector<Section> GetSections();
	VTableFunctionInfo FindVTableContainingFunction(uintptr_t fn);
	uint8_t* ScanMemory(const char* signature);
	uint32_t ResolveDisp32(uint8_t* instruction, uint32_t dwSkipBytes = 0);
	uintptr_t ResolveRIP(uint8_t* pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
	uintptr_t ResolveRIP(uintptr_t pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
	uintptr_t GetProcAddress(std::string szFnName);
};

class MEMORY_API Process {
public:
	HANDLE m_hProc{};
private:
	DWORD pProcId{};
	HWND m_hWnd;
	std::string m_szProcName{};
	std::map<std::string, RemoteModule*> remoteModuleList{};
	std::vector<void*> m_remoteAllocations;

private:
	bool InitializeSysCalls();
	void GetProcHandle();
	MODULEINFO GetModuleInfoEx(std::string m_Name);

public:
	HWND GetHwnd();
	Process(std::string szProcName);
	PVOID Alloc(size_t size, DWORD fFLags = MEM_COMMIT | MEM_RESERVE, DWORD fAccess = PAGE_READWRITE);

	template <typename T>
	inline bool Read(uintptr_t m_Address, T* m_Buffer, SIZE_T m_Size)
	{
		SIZE_T bytesRead;
#ifdef USE_SYSCALL_MODE
		auto res = SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(m_Address), m_Buffer, m_Size);
#else
		auto res = ::ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(m_Address), m_Buffer, m_Size, &bytesRead);
#endif
		return res;
	}

	void* AllocateAndWriteString(std::string str);
	VTableFunctionInfo FindVTableContainingFunction(uintptr_t fn, std::string szMod);


	template <typename T>
	inline bool Read(uintptr_t m_Address, T* m_Buffer)
	{
		return Read(m_Address, m_Buffer, sizeof(T));
	}

	template <typename T>
	inline T ReadDirect(uintptr_t m_Address)
	{
		T m_Buffer{};
		Read(m_Address, &m_Buffer, sizeof(T));
		return m_Buffer;
	}

	template <typename T>
	inline T ReadDirect(uintptr_t m_Address, int size)
	{
		T m_Buffer{};
		Read(m_Address, &m_Buffer, size);
		return m_Buffer;
	}

	template <typename T>
	std::vector<T> ReadArray(uintptr_t address, size_t count)
	{
		SIZE_T bytesRead = 0;

		if constexpr (std::is_same_v<T, bool>)
		{
			std::vector<uint8_t> temp(count);
#ifdef USE_SYSCALL_MODE
			if (!SyscallManager::ReadMemoryDirect(
				m_hProc,
				reinterpret_cast<PVOID>(address),
				temp.data(),
				count * sizeof(uint8_t)))
#else
			if (!::ReadProcessMemory(
				m_hProc,
				reinterpret_cast<LPCVOID>(address),
				temp.data(),
				count * sizeof(uint8_t),
				&bytesRead))
#endif
			{
				return {};
			}

			std::vector<bool> result;
			result.reserve(count);
			for (auto byte : temp)
				result.push_back(byte != 0);

			return result;
		}
		else
		{
			std::vector<T> buffer(count);
#ifdef USE_SYSCALL_MODE
			if (!SyscallManager::ReadMemoryDirect(
				m_hProc,
				reinterpret_cast<PVOID>(address),
				buffer.data(),
				count * sizeof(T)))
#else
			if (!::ReadProcessMemory(
				m_hProc,
				reinterpret_cast<LPCVOID>(address),
				buffer.data(),
				count * sizeof(T),
				&bytesRead))
#endif
			{
				buffer.clear();
			}
			return buffer;
		}
	}

	template <typename T>
	bool WriteArray(uintptr_t address, const std::vector<T>& data)
	{
		SIZE_T bytesWritten = 0;

		if constexpr (std::is_same_v<T, bool>)
		{
			std::vector<uint8_t> temp;
			temp.reserve(data.size());
			for (bool b : data)
				temp.push_back(b ? 1 : 0);

#ifdef USE_SYSCALL_MODE
			return SyscallManager::WriteMemoryDirect(
				m_hProc,
				reinterpret_cast<PVOID>(address),
				temp.data(),
				temp.size() * sizeof(uint8_t));
#else
			return ::WriteProcessMemory(
				m_hProc,
				reinterpret_cast<LPVOID>(address),
				temp.data(),
				temp.size() * sizeof(uint8_t),
				&bytesWritten) != 0;
#endif
		}
		else
		{
#ifdef USE_SYSCALL_MODE
			return SyscallManager::WriteMemoryDirect(
				m_hProc,
				reinterpret_cast<PVOID>(address),
				const_cast<T*>(data.data()),
				data.size() * sizeof(T));
#else
			return ::WriteProcessMemory(
				m_hProc,
				reinterpret_cast<LPVOID>(address),
				data.data(),
				data.size() * sizeof(T),
				&bytesWritten) != 0;
#endif
		}
	}

	inline std::vector<uint8_t> ReadBytes(uintptr_t address, size_t size) {
		std::vector<uint8_t> buffer(size);
		SIZE_T bytesRead{};
#ifdef USE_SYSCALL_MODE
		if (!SyscallManager::ReadMemoryDirect(m_hProc, reinterpret_cast<PVOID>(address),
			buffer.data(), size)) {
			buffer.clear();
		}
#else
		if (!::ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(address),
			buffer.data(), size, &bytesRead)) {
			buffer.clear();
		}
#endif
		return buffer;
	}

	template <typename T, typename T2>
	inline T2 ReadDirect(uintptr_t m_Address)
	{
		T m_Buffer{};
		Read(m_Address, &m_Buffer, sizeof(T));
		return reinterpret_cast<T2>(m_Buffer);
	}

	template <typename T>
	inline bool Write(uintptr_t m_Address, T m_Buffer)
	{
		SIZE_T bytesWritten;
#ifdef USE_SYSCALL_MODE
		auto res = SyscallManager::WriteMemoryDirect(m_hProc, (PVOID)m_Address, (PVOID)&m_Buffer, sizeof(T));
#else
		auto res = ::WriteProcessMemory(m_hProc, (LPVOID)m_Address, (LPCVOID)&m_Buffer, sizeof(T), &bytesWritten);
#endif
		return res;
	}

	bool WriteString(uintptr_t address, const std::string& str, SIZE_T maxLength = 256)
	{
		SIZE_T writeLength = std::min(str.size(), maxLength - 1);
		std::vector<char> buffer(maxLength, 0);
		memcpy(buffer.data(), str.c_str(), writeLength);
		buffer[writeLength] = '\0';

		SIZE_T bytesWritten = 0;
#ifdef USE_SYSCALL_MODE
		BOOL res = SyscallManager::WriteMemoryDirect(m_hProc, (PVOID)address, buffer.data(), maxLength);
		return res;
#else
		BOOL res = ::WriteProcessMemory(m_hProc, (LPVOID)address, buffer.data(), maxLength, &bytesWritten);
#endif
		return res && bytesWritten == maxLength;
	}

	std::string ReadString(uintptr_t address, SIZE_T maxLength = 256)
	{
		std::vector<char> buffer(maxLength, 0);
		if (!Read(address, buffer.data(), maxLength - 1))
			return std::string();

		buffer[maxLength - 1] = '\0';
		return std::string(buffer.data());
	}

	RemoteModule* GetRemoteModule(std::string szModuleName);

	void TrackAllocation(void* pRemote);
	bool FreeRemote(void* pRemote);
	void FreeAllRemote();
	size_t GetAllocationCount() const { return m_remoteAllocations.size(); }

	// Remote thread injection helpers
	void* AllocAndWriteShellcode(void* funcStart, void* funcEnd);
	HANDLE CreateRemoteThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
	DWORD ExecuteAndCleanup(void* shellcode, void* context, DWORD timeoutMs = 5000);

	template<typename ContextType>
	DWORD ExecuteRemoteWrapper(void* wrapperFunc, void* wrapperEnd,
		const ContextType& context, DWORD timeoutMs = 5000) {
		void* ctxRemote = Alloc(sizeof(ContextType));
		if (!ctxRemote) {
			printf("ERROR: Failed to allocate context\n");
			return (DWORD)-1;
		}

		Write(reinterpret_cast<uintptr_t>(ctxRemote), context);

		void* shellcode = AllocAndWriteShellcode(wrapperFunc, wrapperEnd);
		if (!shellcode) {
			printf("ERROR: Failed to allocate shellcode\n");
			FreeRemote(ctxRemote);
			return (DWORD)-1;
		}

		return ExecuteAndCleanup(shellcode, ctxRemote, timeoutMs);
	}

	template<typename ContextType, typename ReturnType>
	bool ExecuteRemoteWrapper(void* wrapperFunc, void* wrapperEnd,
		const ContextType& context, ReturnType& outResult,
		DWORD timeoutMs = 5000) {
		void* ctxRemote = Alloc(sizeof(ContextType));
		if (!ctxRemote) {
			printf("ERROR: Failed to allocate context\n");
			return false;
		}

		Write(reinterpret_cast<uintptr_t>(ctxRemote), context);

		void* shellcode = AllocAndWriteShellcode(wrapperFunc, wrapperEnd);
		if (!shellcode) {
			printf("ERROR: Failed to allocate shellcode\n");
			FreeRemote(ctxRemote);
			return false;
		}

		return ExecuteAndCleanup(shellcode, ctxRemote, outResult, timeoutMs);
	}

	template<typename T>
	bool ExecuteAndCleanup(void* shellcode, void* context, T& outResult, DWORD timeoutMs = 5000) {
		HANDLE hThread = CreateRemoteThreadEx(
			reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
			context
		);

		if (!hThread) {
			printf("ERROR: Failed to create remote thread\n");
			FreeRemote(context);
			FreeRemote(shellcode);
			return false;
		}

		DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);

		if (waitResult == WAIT_TIMEOUT) {
			printf("WARNING: Remote thread timed out after %dms\n", timeoutMs);
			CloseHandle(hThread);
			FreeRemote(context);
			FreeRemote(shellcode);
			return false;
		}

		DWORD exitCode = 0;
		GetExitCodeThread(hThread, &exitCode);
		CloseHandle(hThread);

		outResult = static_cast<T>(exitCode);

		FreeRemote(context);
		FreeRemote(shellcode);

		return true;
	}

	// VTable
	uintptr_t GetVTable(uintptr_t pThis) noexcept;

	template <int index>
	uintptr_t GetVTableFunction(uintptr_t pThis) noexcept {
		if (!pThis) return 0;

		uintptr_t vtablePtr = ReadDirect<uintptr_t>(pThis);
		if (!vtablePtr) return 0;

		uintptr_t funcPtr = ReadDirect<uintptr_t>(vtablePtr + (index * sizeof(void*)));
		return funcPtr;
	}

	template <int index>
	uintptr_t GetVTableFunctionFromVTable(uintptr_t vtableAddr) noexcept {
		if (!vtableAddr) return 0;

		uintptr_t funcPtr = ReadDirect<uintptr_t>(vtableAddr + (index * sizeof(void*)));
		return funcPtr;
	}

	std::vector<uintptr_t> ReadVTable(uintptr_t pThis, size_t count = 64) noexcept;
	void DumpVTable(uintptr_t pThis, size_t count = 32, const char* name = "VTable") noexcept;
};

namespace MemoryApi {
	extern MEMORY_API uint8_t* ScanMemoryIntern(std::string szDllName, const char* signature);
	extern MEMORY_API uintptr_t ResolveRIP(uint8_t* pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
	extern MEMORY_API uintptr_t ResolveRIP(uintptr_t pAddr, DWORD dwRip = 0x3, DWORD dwSize = 0x7);
}