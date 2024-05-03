#include "Utils.h"

#define MY_DRIVER_TAG "1gaT"

// Function to allocate shared memory
PVOID AllocateSharedMemory(SIZE_T size) {
    PVOID memory = ExAllocatePool2(NonPagedPool, size, MY_DRIVER_TAG);

    if (memory == NULL)
    {
        // Handle allocation failure
        DbgPrintEx(0, 0, ("Failed to allocate shared memory\n"));
    }

    return memory;
}

// Function to free shared memory
VOID FreeSharedMemory(PVOID memory) {
    if (memory != NULL)
    {
        ExFreePool2(memory, MY_DRIVER_TAG, NULL, NULL);
    }
}

PUNICODE_STRING GetProcessNameFromEPROCESS(PEPROCESS process) {
    if (process != NULL) {
        int IMAGE_FILE_PTR_OFFSET = 0x5a0;
        FILE_OBJECT* imageFileObj = (FILE_OBJECT*)*(UINT64*)(((UINT64)process) + IMAGE_FILE_PTR_OFFSET);
        if (imageFileObj == NULL) {
            return NULL;
        }
        return (PUNICODE_STRING)&imageFileObj->FileName;
    }
    return NULL;
}

UINT64 GetProcessIDFromEPROCESS(PEPROCESS process) {
    if (process != NULL) {
        int UniqueProcessId_Offset = 0x440;
        UINT64 processId = *(UINT64*)(((UINT64)process) + UniqueProcessId_Offset);
        return processId;
    }
    return -1;
}

