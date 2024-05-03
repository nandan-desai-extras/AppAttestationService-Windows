#pragma once
#include <ntifs.h>
#include <ntddk.h>

PVOID AllocateSharedMemory(SIZE_T size);

VOID FreeSharedMemory(PVOID memory);

PUNICODE_STRING GetProcessNameFromEPROCESS(PEPROCESS process);

UINT64 GetProcessIDFromEPROCESS(PEPROCESS process);

