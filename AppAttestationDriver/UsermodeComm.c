#include "AppEventLogStorage.h"
#include "UsermodeComm.h"

#define SEND_APP_LOGS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING DeviceName, SymbolicLinkName;
PDEVICE_OBJECT g_DeviceObject;

NTSTATUS DeviceIoControlRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack;
    PVOID ioBuffer;
    ULONG inputBufferLength, outputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case SEND_APP_LOGS:
    {
        // Process the received message from user mode
        //DbgPrintEx(0, 0, "Received message from user mode: %ws\n", (PWSTR)ioBuffer);
        DbgPrintEx(0, 0, "[AppAttestationDriver] Usermode request received\n");
        // Send a message back to user mode
        if (outputBufferLength >= sizeof(APP_LOGS))
        {
            // Copy the message to the output buffer
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, (unsigned char*)APP_LOGS, sizeof(APP_LOGS));

            Irp->IoStatus.Information = sizeof(APP_LOGS);

            DbgPrintEx(0, 0, "[AppAttestationDriver] Successfully filled in the buffer for usermode\n");

            // Clear the kernel-mode app log buffer
            RtlSecureZeroMemory((unsigned char*)APP_LOGS, sizeof(APP_LOGS));
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
            DbgPrintEx(0, 0, "[AppAttestationDriver] Usermode request buffer too small\n");
        }
    }
    break;

    default:
        //status = STATUS_INVALID_DEVICE_REQUEST;
        /*
            Not recommended to do this way, but no time to fix this...
        */
        DbgPrintEx(0, 0, "[AppAttestationDriver] Some non-message usermode request received\n");
        status = STATUS_SUCCESS;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


NTSTATUS SetupUsermodeComm(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING driverName;

    RtlInitUnicodeString(&driverName, L"\\Device\\MyAttestationDriver");

    status = IoCreateDevice(
        DriverObject,
        0,
        &driverName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[AppAttestationDriver] Failed to create device, status: 0x%X\n", status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlRoutine;

    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\MyAttestationDriver");
    IoCreateSymbolicLink(&SymbolicLinkName, &driverName);

    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    DbgPrintEx(0, 0, "[AppAttestationDriver] Driver device registered successfully!\n");

    return STATUS_SUCCESS;
}


NTSTATUS CleanupUsermodeComm(
    _In_ PDRIVER_OBJECT   DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    IoDeleteSymbolicLink(&SymbolicLinkName);
    IoDeleteDevice(g_DeviceObject);

    DbgPrintEx(0, 0, "Driver device deleted successfully!\n");

    return STATUS_SUCCESS;
}

