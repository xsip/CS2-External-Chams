#include <Memory/SysCall/SyscallManager.h>

#include <iostream>

extern "C" {
    DWORD g_syscall_NtOpenProcess = 0;
    DWORD g_syscall_NtReadVirtualMemory = 0;
    DWORD g_syscall_NtWriteVirtualMemory = 0;
    DWORD g_syscall_NtAllocateVirtualMemory = 0;
    DWORD g_syscall_NtFreeVirtualMemory = 0;
    DWORD g_syscall_NtProtectVirtualMemory = 0;
    DWORD g_syscall_NtQueryVirtualMemory = 0;
    DWORD g_syscall_NtCreateThreadEx = 0;
}

SyscallManager::SyscallInfo SyscallManager::s_NtOpenProcess = { 0, "NtOpenProcess", false };
SyscallManager::SyscallInfo SyscallManager::s_NtReadVirtualMemory = { 0, "NtReadVirtualMemory", false };
SyscallManager::SyscallInfo SyscallManager::s_NtWriteVirtualMemory = { 0, "NtWriteVirtualMemory", false };
SyscallManager::SyscallInfo SyscallManager::s_NtAllocateVirtualMemory = { 0, "NtAllocateVirtualMemory", false };
SyscallManager::SyscallInfo SyscallManager::s_NtFreeVirtualMemory = { 0, "NtFreeVirtualMemory", false };
SyscallManager::SyscallInfo SyscallManager::s_NtProtectVirtualMemory = { 0, "NtProtectVirtualMemory", false };
SyscallManager::SyscallInfo SyscallManager::s_NtQueryVirtualMemory = { 0, "NtQueryVirtualMemory", false };
SyscallManager::SyscallInfo SyscallManager::s_NtCreateThreadEx = { 0, "NtCreateThreadEx", false };

DWORD SyscallManager::ExtractSyscallNumber(const char* functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cerr << "[!] Failed to get ntdll.dll" << std::endl;
        return 0;
    }

    BYTE* funcAddress = (BYTE*)GetProcAddress(ntdll, functionName);
    if (!funcAddress) {
        std::cerr << "[!] Failed to find " << functionName << std::endl;
        return 0;
    }
     
    if (funcAddress[0] == 0x4C && funcAddress[1] == 0x8B && funcAddress[2] == 0xD1 && funcAddress[3] == 0xB8) {
        DWORD syscallNumber = *(DWORD*)(funcAddress + 4);
        std::cout << "[+] " << functionName << " syscall: 0x"
            << std::hex << syscallNumber << std::dec << std::endl;
        return syscallNumber;
    }

    if (funcAddress[0] == 0xB8) {
        DWORD syscallNumber = *(DWORD*)(funcAddress + 1);
        std::cout << "[+] " << functionName << " syscall (alt pattern): 0x"
            << std::hex << syscallNumber << std::dec << std::endl;
        return syscallNumber;
    }

    std::cerr << "[!] Unknown prologue for " << functionName << ": ";
    for (int i = 0; i < 10; i++) {
        printf("%02X ", funcAddress[i]);
    }
    std::cout << std::endl;

    return 0;
}

bool SyscallManager::InitializeSyscall(SyscallInfo& info) {
    if (info.initialized) {
        return true;
    }

    info.number = ExtractSyscallNumber(info.name);
    if (info.number == 0) {
        return false;
    }

    info.initialized = true;
    return true;
}

bool SyscallManager::Initialize() {
    std::cout << "[*] Initializing Syscall Manager..." << std::endl;

    bool success = true;

    success &= InitializeSyscall(s_NtOpenProcess);
    g_syscall_NtOpenProcess = s_NtOpenProcess.number;

    success &= InitializeSyscall(s_NtReadVirtualMemory);
    g_syscall_NtReadVirtualMemory = s_NtReadVirtualMemory.number;

    success &= InitializeSyscall(s_NtWriteVirtualMemory);
    g_syscall_NtWriteVirtualMemory = s_NtWriteVirtualMemory.number;

    success &= InitializeSyscall(s_NtAllocateVirtualMemory);
    g_syscall_NtAllocateVirtualMemory = s_NtAllocateVirtualMemory.number;

    success &= InitializeSyscall(s_NtFreeVirtualMemory);
    g_syscall_NtFreeVirtualMemory = s_NtFreeVirtualMemory.number;

    success &= InitializeSyscall(s_NtProtectVirtualMemory);
    g_syscall_NtProtectVirtualMemory = s_NtProtectVirtualMemory.number;

    success &= InitializeSyscall(s_NtQueryVirtualMemory);
    g_syscall_NtQueryVirtualMemory = s_NtQueryVirtualMemory.number;

    success &= InitializeSyscall(s_NtCreateThreadEx);
    g_syscall_NtCreateThreadEx = s_NtCreateThreadEx.number;

    if (success) {
        std::cout << "[+] Syscall Manager initialized successfully" << std::endl << std::endl;
    }
    else {
        std::cerr << "[!] Some syscalls failed to initialize" << std::endl;
    }

    return success;
}

NTSTATUS SyscallManager::SyscallNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    if (!s_NtOpenProcess.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SyscallManager::SyscallNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
) {
    if (!s_NtReadVirtualMemory.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS SyscallManager::SyscallNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    if (!s_NtWriteVirtualMemory.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS SyscallManager::SyscallNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!s_NtAllocateVirtualMemory.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS SyscallManager::SyscallNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {
    if (!s_NtFreeVirtualMemory.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS SyscallManager::SyscallNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {
    if (!s_NtProtectVirtualMemory.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS SyscallManager::SyscallNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    if (!s_NtCreateThreadEx.initialized) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return Syscall_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList);
}

// Helper functions
HANDLE SyscallManager::OpenProcessDirect(DWORD processId, ACCESS_MASK desiredAccess) {
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)processId;
    clientId.UniqueThread = nullptr;

    NTSTATUS status = SyscallNtOpenProcess(&hProcess, desiredAccess, &objAttr, &clientId);

    if (status != STATUS_SUCCESS) {
        std::cerr << "[!] NtOpenProcess failed: 0x" << std::hex << status << std::dec << std::endl;
        return nullptr;
    }

    return hProcess;
}

bool SyscallManager::ReadMemoryDirect(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    NTSTATUS status = SyscallNtReadVirtualMemory(hProcess, address, buffer, size, &bytesRead);
    return (status == STATUS_SUCCESS && bytesRead == size);
}

bool SyscallManager::WriteMemoryDirect(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size) {
    SIZE_T bytesWritten = 0;
    NTSTATUS status = SyscallNtWriteVirtualMemory(hProcess, address, buffer, size, &bytesWritten);
    return (status == STATUS_SUCCESS && bytesWritten == size);
}

PVOID SyscallManager::AllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect) {
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = size;

    NTSTATUS status = SyscallNtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        protect
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "[!] NtAllocateVirtualMemory failed: 0x" << std::hex << status << std::dec << std::endl;
        return nullptr;
    }

    return baseAddress;
}

bool SyscallManager::FreeMemoryDirect(HANDLE hProcess, PVOID address) {
    SIZE_T regionSize = 0;
    NTSTATUS status = SyscallNtFreeVirtualMemory(hProcess, &address, &regionSize, MEM_RELEASE);
    return (status == STATUS_SUCCESS);
}

HANDLE SyscallManager::CreateRemoteThreadDirect(HANDLE hProcess, PVOID startAddress, PVOID parameter) {
    HANDLE hThread = nullptr;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

    NTSTATUS status = SyscallNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        &objAttr,
        hProcess,
        startAddress,
        parameter,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "[!] NtCreateThreadEx failed: 0x" << std::hex << status << std::dec << std::endl;
        return nullptr;
    }

    return hThread;
}