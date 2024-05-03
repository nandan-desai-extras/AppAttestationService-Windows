#include "ProcessStartPhase.h"
#include "ProcessInteraction.h"
#include "Utils.h"
#include "AppEventLogStorage.h"
#include "UsermodeComm.h"

DRIVER_UNLOAD DriverUnload;

// DriverEntry function
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    
    NTSTATUS status;

    status = SetupUsermodeComm(DriverObject, RegistryPath);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "AppAttestationDriver loaded!\n");
    }
    else {
        DbgPrintEx(0, 0, "AppAttestationDriver failed load!\n");
        return STATUS_UNSUCCESSFUL;
    }

    obOperationRegistration.ObjectType = PsProcessType;
    obOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE;
    obOperationRegistration.PreOperation = MyPreOperationCallback;

    RtlInitUnicodeString(&altitude, L"1000");

    obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    obCallbackRegistration.OperationRegistrationCount = 1;
    obCallbackRegistration.OperationRegistration = &obOperationRegistration;
    obCallbackRegistration.Altitude = altitude;
    status = ObRegisterCallbacks(&obCallbackRegistration, &registrationHandle);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "Callback registered successfully\n");
    }
    else {
        DbgPrintEx(0, 0, "Callback registration failed with status 0x%x\n", status);
    }

    // Register the image load callback
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    // Register the process creation and termination callback
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[AppAttestationDriver] PsSetCreateProcessNotifyRoutineEx registration failed. Error: 0x%X\n", status);
    }

    // Add your other driver initialization code here

    // Driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

// DriverUnload function
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    CleanupUsermodeComm(DriverObject);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, TRUE);
    if (registrationHandle) {
        ObUnRegisterCallbacks(registrationHandle);
    }

    DbgPrintEx(0, 0, "AppAttestationDriver unloaded successfully!\n");
}
