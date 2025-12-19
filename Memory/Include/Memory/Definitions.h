#pragma once
#include <Windows.h>

#ifdef MEMORY_DEFINITION
#define MEMORY_API __declspec(dllexport)
#else
#define MEMORY_API __declspec(dllexport)
#endif