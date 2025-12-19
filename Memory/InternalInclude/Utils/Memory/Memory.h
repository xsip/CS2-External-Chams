#pragma once
#include <cstdint>
class Memory {
public:
	static uint8_t* ScanMemory(uintptr_t pStart, uintptr_t pSize, const char* signature);
};