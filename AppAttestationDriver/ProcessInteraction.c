#include "ProcessInteraction.h"
#include "Utils.h"
#include "AppEventLogStorage.h"
#include <ntstrsafe.h>

PVOID registrationHandle = NULL;
UNICODE_STRING altitude;
OB_OPERATION_REGISTRATION obOperationRegistration = { 0 };
OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };

OB_PREOP_CALLBACK_STATUS MyPreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreOperationInfo) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (PreOperationInfo->ObjectType == *PsProcessType) {
        PUNICODE_STRING targetProcName = GetProcessNameFromEPROCESS((PEPROCESS)PreOperationInfo->Object);
        PUNICODE_STRING clientProcName = GetProcessNameFromEPROCESS(PsGetCurrentProcess());
        if (targetProcName == NULL) {
            //DbgPrintEx(0, 0, "[KMDFTest ProcessInteraction] Could not get target proc image filename\n");
        }
        if (clientProcName == NULL) {
            //DbgPrintEx(0, 0, "[KMDFTest ProcessInteraction] Could not get client proc image filename\n");
        }
        if (targetProcName == NULL && clientProcName == NULL) {
            //DbgPrintEx(0, 0, "[KMDFTest ProcessInteraction] Could not get both client and target proc image filename\n");
        }
        if (targetProcName != NULL && clientProcName != NULL) {
            if (targetProcName->Buffer != NULL && clientProcName->Buffer != NULL) {
                ULONG clientPID = GetProcessIDFromEPROCESS(PsGetCurrentProcess());
                ULONG targetPID = GetProcessIDFromEPROCESS((PEPROCESS)PreOperationInfo->Object);
                BOOLEAN clientProcPresent = IsPIDPresentInAppLogs((HANDLE)clientPID);
                BOOLEAN targetProcPresent = IsPIDPresentInAppLogs((HANDLE)targetPID);
                if (clientProcPresent || targetProcPresent) {
                    char appEvent[MAX_EVENT_MSG_LEN];
                    NTSTATUS status1, status2;
                    ANSI_STRING clientAnsiString, targetAnsiString;
                    status1 = RtlUnicodeStringToAnsiString(&clientAnsiString, clientProcName, TRUE);
                    status2 = RtlUnicodeStringToAnsiString(&targetAnsiString, targetProcName, TRUE);
                    if (NT_SUCCESS(status1) && NT_SUCCESS(status2))
                    {
                        status1 = RtlStringCbPrintfA(appEvent, sizeof(appEvent), "PROCESS_HANDLE: %s obtained a handle to %s", clientAnsiString.Buffer, targetAnsiString.Buffer);
                        if (!NT_SUCCESS(status1)) {
                            DbgPrintEx(0, 0, "RtlStringCbPrintfA failed with status 0x%x\n", status1);
                            return;
                        }
                        RtlFreeAnsiString(&targetAnsiString);
                        RtlFreeAnsiString(&clientAnsiString);
                        if (targetProcPresent) {
                            AddAppEventLog((HANDLE)targetPID, appEvent, sizeof(appEvent));
                        }
                        if (clientProcPresent) {
                            AddAppEventLog((HANDLE)clientPID, appEvent, sizeof(appEvent));
                        }
                    }
                    else if (NT_SUCCESS(status1)) {
                        RtlFreeAnsiString(&clientAnsiString);
                    }
                    else if (NT_SUCCESS(status2)) {
                        RtlFreeAnsiString(&targetAnsiString);
                    }
                    //DbgPrintEx(0, 0, "[KMDFTest ProcessInteraction] Process [PID: %u] %ws accessed -> Process [PID: %u] %ws\n", clientPID, clientProcName->Buffer, targetPID, targetProcName->Buffer);
                }
            }
        }
    }
    return OB_PREOP_SUCCESS;
}

