#pragma once
#include <Windows.h>
#include <Memory/Definitions.h>
class MEMORY_API PointerCheck {
public:
	static bool IsBadReadPtr(void* p);
	static bool PtrIsInvalid(uintptr_t pPtr);
	static bool IsValidCString(const char* ptr, size_t maxLen = 256);
	static bool IsBadReadPtrEx(HANDLE h, void* p);
	static bool PtrIsInvalidEx(HANDLE h, uintptr_t pPtr);
};