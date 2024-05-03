#pragma once
#include <ntddk.h>

NTSTATUS DeviceIoControlRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS SetupUsermodeComm(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
);

NTSTATUS CleanupUsermodeComm(
    _In_ PDRIVER_OBJECT   DriverObject
);
