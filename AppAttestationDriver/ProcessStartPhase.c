#include "ProcessStartPhase.h"
#include "Utils.h"
#include "AppEventLogStorage.h"
#include <ntstrsafe.h>

BOOLEAN CheckForSection(_In_ PVOID ImageBase);

// Callback function that will be called when a PE image is loaded or unloaded
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{

    if (ImageInfo->SystemModeImage) {
        // Ignore system mode images
        return;
    }

    // Check if the loaded image has the desired section
    BOOLEAN hasSection = CheckForSection(ImageInfo->ImageBase);

    if (hasSection) {
        char appEvent[MAX_EVENT_MSG_LEN];
        NTSTATUS status;
        ANSI_STRING ansiString;
        status = RtlUnicodeStringToAnsiString(&ansiString, FullImageName, TRUE);
        if (NT_SUCCESS(status))
        {
            status = RtlStringCbPrintfA(appEvent, sizeof(appEvent), "IMG_LOAD: target with attestation section is being loaded %s", ansiString.Buffer);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(0, 0, "RtlStringCbPrintfA failed with status 0x%x\n", status);
                return;
            }
            RtlFreeAnsiString(&ansiString);
            AddAppEventLog(ProcessId, appEvent, sizeof(appEvent));
            DbgPrintEx(0, 0, "[AppAttestationDriver] target with attestation section is being loaded and has been added to applogs: %wZ\n", FullImageName);
        }
    }
}

NTSTATUS GetImageNtHeaders(PVOID ImageBase, PIMAGE_NT_HEADERS* NtHeaders)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;

    dosHeader = (PIMAGE_DOS_HEADER)ImageBase;

    // Check if the image has a valid DOS signature
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Calculate the address of the NT headers
    ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + dosHeader->e_lfanew);

    // Check if the image has a valid NT signature
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *NtHeaders = ntHeader;
    return STATUS_SUCCESS;
}

// Function to check for the presence of a specific section in the PE file
BOOLEAN CheckForSection(_In_ PVOID ImageBase)
{
    PIMAGE_NT_HEADERS64 ntHeaders;
    GetImageNtHeaders(ImageBase, &ntHeaders);
    if (ntHeaders) {
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            if (strcmp(sectionHeader->Name, TARGET_SECTION_NAME) == 0) {
                // Section found
                return TRUE;
            }
        }
    }

    // Section not found
    return FALSE;
}

VOID GetImageFileNameFromPid() //HANDLE processId
{
    PEPROCESS process = PsGetCurrentProcess();
    PUNICODE_STRING processName = GetProcessNameFromEPROCESS(process);
    unsigned long processId = (unsigned long)GetProcessIDFromEPROCESS(process);
    DbgPrintEx(0, 0, "Image Name: %ws, Process ID: %u\n", processName->Buffer, processId);
}

// Callback routine for process creation and termination notifications
VOID ProcessNotifyRoutine(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (Create) {
        // Process creation
        if (IsPIDPresentInAppLogs(ProcessId)) {
            DbgPrintEx(0, 0, "[AppAttestationDriver] Process Created with PID: %u\n", (ULONG)ProcessId);
            GetImageFileNameFromPid(); //ProcessId
            char appEvent[MAX_EVENT_MSG_LEN];
            NTSTATUS status;
            status = RtlStringCbPrintfA(appEvent, sizeof(appEvent), "PROCESS_LAUNCH: Attestation target process has launched");
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(0, 0, "RtlStringCbPrintfA failed with status 0x%x\n", status);
                return;
            }
            AddAppEventLog(ProcessId, appEvent, sizeof(appEvent));
        }
    }
    else {
        if (IsPIDPresentInAppLogs(ProcessId)) {
            // Process termination
            DbgPrintEx(0, 0, "[AppAttestationDriver] Process with PID %u Terminated.\n", (ULONG)ProcessId);
            GetImageFileNameFromPid();
            char appEvent[MAX_EVENT_MSG_LEN];
            NTSTATUS status;
            status = RtlStringCbPrintfA(appEvent, sizeof(appEvent), "PROCESS_TERMINATE: Attestation target process has been terminated");
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(0, 0, "RtlStringCbPrintfA failed with status 0x%x\n", status);
                return;
            }
            AddAppEventLog(ProcessId, appEvent, sizeof(appEvent));
            DisplayAppEventLogs();
        }
    }
}

