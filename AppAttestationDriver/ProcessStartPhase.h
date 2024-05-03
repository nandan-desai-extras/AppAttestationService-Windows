#pragma once

#include "ImageHeaders.h"
#include <ntddk.h>

// Define the section name you are looking for
#define TARGET_SECTION_NAME ".attest"

// Function to check for the presence of a specific section in the PE file
BOOLEAN CheckForSection(_In_ PVOID ImageBase);

// Callback function that will be called when a PE image is loaded or unloaded
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
); 

NTSTATUS GetImageNtHeaders(PVOID ImageBase, PIMAGE_NT_HEADERS* NtHeaders);

VOID ProcessNotifyRoutine(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
);
