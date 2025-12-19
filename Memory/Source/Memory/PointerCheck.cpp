#include <Memory/PointerCheck.h>

bool PointerCheck::IsBadReadPtr(void* p)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (::VirtualQuery(p, &mbi, sizeof(mbi)))
	{
		DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		bool b = !(mbi.Protect & mask);
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

		return b;
	}
	return true;
}

bool PointerCheck::PtrIsInvalid(uintptr_t pPtr) {
	return (pPtr == 0x0 || !pPtr || pPtr == NULL || (pPtr != 0x0 && PointerCheck::IsBadReadPtr((void*)pPtr)));
}

bool PointerCheck::IsValidCString(const char* ptr, size_t maxLen) {
	if (!ptr || PointerCheck::PtrIsInvalid((uintptr_t)ptr)) return false;

	__try {
		for (size_t i = 0; i < maxLen; ++i) {
			volatile char c = ptr[i];
			if (c == '\0') break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}

	return true;
}

bool PointerCheck::IsBadReadPtrEx(HANDLE h, void* p)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (::VirtualQueryEx(h, p, &mbi, sizeof(mbi)))
	{
		DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		bool b = !(mbi.Protect & mask);
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

		return b;
	}
	return true;
}

bool PointerCheck::PtrIsInvalidEx(HANDLE h, uintptr_t pPtr) {
	return (pPtr == 0x0 || !pPtr || pPtr == NULL || (pPtr != 0x0 && PointerCheck::IsBadReadPtrEx(h, (void*)pPtr)));
}