#include <iostream>
#include "../RPCDefinitions/RPCDefinitions.h"
#include "../AttestationLibrary/ClientAikGeneration.h"
#include "../AttestationLibrary/ClientPlatformAtt.h"
#include "../AttestationLibrary/ServerOperations.h"
#include "../AttestationLibrary/Utils.h"
#include "../AttestationLibrary/AppAttestationApi.h"
#include "../AttestationLibrary/ClientAppAtt.h"
// Import the AppEventLog structs and size definitions from the driver project
#include "../AppAttestationDriver/AppEventLogDefinitions.h"

const unsigned char EMPTY_BUF[MAX_EVENT_MSG_LEN] = { 0x0 };

// Function prototype for the thread
DWORD WINAPI GetAndProcessAppEventLogs(LPVOID lpParam);

#define RECEIVE_APP_LOGS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

error_status_t RPC_GetEK_CreateAIK(
    /* [string][in] */ wchar_t* AIKname,
    /* [string][in] */ wchar_t* serverNonce,
    /* [out] */ unsigned long* EKsize,
    /* [size_is][size_is][out] */ unsigned char** EK,
    /* [out] */ unsigned long* idBindingSize,
    /* [size_is][size_is][out] */ unsigned char** idBinding)
{
    printf("GetEK_CreateAIK called on the RPC server\n");
    // ORing the return code of both functions so that if there an error, the final value will be some error value
    unsigned long retval1 = GetEKCert(EK, EKsize);
    unsigned long retval2 = CreateAIK(AIKname, serverNonce, idBinding, idBindingSize);
    return retval1 | retval2;
}

error_status_t RPC_VerifyActivationBlob(
    /* [string][in] */ wchar_t* AIKname,
    /* [in] */ unsigned long serverActivationBlobSize,
    /* [size_is][in] */ unsigned char* serverActivationBlob,
    /* [out] */ unsigned long* serverSecretSize,
    /* [size_is][size_is][out] */ unsigned char** serverSecret)
{
    printf("VerifyActivationBlob called on the RPC server\n");
    return ActivateAIK(AIKname, serverActivationBlob, serverActivationBlobSize, serverSecretSize, serverSecret);
}

error_status_t RPC_RegisterAIK(
    /* [string][in] */ wchar_t* AIKname) 
{
    printf("RegisterAIK called on the RPC server\n");
    return RegisterAIK(AIKname);
}

error_status_t RPC_GetAppAttestation(
    /* [in] */ handle_t Binding,
    /* [string][in] */ wchar_t* AIKname,
    /* [string][in] */ wchar_t* serverNonce,
    /* [out] */ unsigned long* platformAttestationBlobSize,
    /* [out] */ unsigned long* appAttestationBlobSize,
    /* [out] */ unsigned long* attestationBlobTotalSize,
    /* [size_is][size_is][out] */ unsigned char** attestationBlob)
{
    HRESULT hr;
    unsigned long clientPID;
    I_RpcBindingInqLocalClientPID(Binding, &clientPID);
    printf("Client PID: %lu\n", clientPID);
    unsigned char* platformAttBlob = NULL;
    unsigned long platformAttBlobSize = 0;
    if (FAILED(hr = GetPlatformAttestation(AIKname, serverNonce, &platformAttBlob, &platformAttBlobSize))) {
        if (platformAttBlob != NULL) {
            free(platformAttBlob);
        }
        return hr;
    }
    unsigned char* appAttBlob = NULL;
    unsigned long appAttBlobSize = 0;
    if (FAILED(hr = ClientGetAppAttestation(AIKname, serverNonce, &appAttBlob, &appAttBlobSize))) {
        if (platformAttBlob != NULL) {
            free(platformAttBlob);
        }
        if (appAttBlob != NULL) {
            free(appAttBlob);
        }
        return hr;
    }
    unsigned long totalSize = platformAttBlobSize + appAttBlobSize;
    *attestationBlob = (unsigned char*)midl_user_allocate(totalSize);
    if (*attestationBlob == NULL) {
        return E_OUTOFMEMORY;
    }
    memcpy(*attestationBlob, platformAttBlob, platformAttBlobSize);
    memcpy((*attestationBlob) + platformAttBlobSize, appAttBlob, appAttBlobSize);
    *platformAttestationBlobSize = platformAttBlobSize;
    *appAttestationBlobSize = appAttBlobSize;
    *attestationBlobTotalSize = totalSize;
    return S_OK;
}

// Naive security callback.
RPC_STATUS CALLBACK SecurityCallback(RPC_IF_HANDLE /*hInterface*/, void* /*pBindingHandle*/)
{
    return RPC_S_OK; // Always allow anyone.
}

void ProcessAppEventLogs(AppEventLog app_logs[], size_t log_size) {
    int i = 0;
    for (i = 0; i < log_size; i++) {
        if (app_logs[i].PID != 0) {
            printf("App %d, PID: %d\n", i, app_logs[i].PID);
            for (int j = 0; j < MAX_EVENT_LOGS; j++) {
                if (memcmp(app_logs[i].eventMessages[j], EMPTY_BUF, MAX_EVENT_MSG_LEN) != 0) {
                    // process log here
                    printf("\tLog %d: %s\n", j, app_logs[i].eventMessages[j]);
                    uint8_t digest[WBCL_HASH_LEN_SHA1] = { 0x0 };
                    GetSHA1Digest(digest, (uint8_t*)app_logs[i].eventMessages[j], MAX_EVENT_MSG_LEN);
                    uint32_t pcrIndex = 23;
                    uint32_t eventType = 1;
                    SHA1PCRExtend(pcrIndex, digest);
                    AppendAppTCGEventLog(GetAppLogPath(), pcrIndex, eventType, digest, (uint8_t*)app_logs[i].eventMessages[j], MAX_EVENT_MSG_LEN);
                }
            }
        }
    }
}

// Thread function
DWORD WINAPI GetAndProcessAppEventLogs(LPVOID lpParam) {
    while (1) {
        HANDLE hDevice = CreateFileW(
            L"\\\\.\\MyAttestationDriver",           // Name of the device
            GENERIC_READ | GENERIC_WRITE,   // Open for reading/writing
            FILE_SHARE_READ | FILE_SHARE_WRITE,                              // No sharing
            NULL,                           // security attributes
            OPEN_EXISTING,                  // Opens existing device
            FILE_ATTRIBUTE_NORMAL,          // Normal file attribute
            NULL                            // No template file
        );

        if (hDevice == INVALID_HANDLE_VALUE)
        {
            printf("Could not open device (error %d)\n", GetLastError());
            return 1;
        }

        AppEventLog app_logs[MAX_APP_LOGS] = { 0 };

        DWORD bytesReturned;

        if (DeviceIoControl(
            hDevice,                      // Device handle
            RECEIVE_APP_LOGS,           // IOCTL code
            NULL,                         // Input buffer
            0,                            // Input buffer size
            &app_logs,                     // Output buffer
            sizeof(app_logs),              // Output buffer size
            &bytesReturned,               // Bytes returned
            NULL                          // Overlapped
        ) == 0)
        {
            printf("DeviceIoControl failed (error %d)\n", GetLastError());
        }
        else
        {
            //printf("App logs received from the kernel mode, bytes returned: %u\n", bytesReturned);
            ProcessAppEventLogs(app_logs, MAX_APP_LOGS);
        }

        CloseHandle(hDevice);

        Sleep(2000); // Sleep for 2 seconds
    }
    return 0;
}

// Thread function
DWORD WINAPI ListenToClientRPC(LPVOID lpParam) {
    RPC_STATUS status;

    // Uses the protocol combined with the endpoint for receiving
    // remote procedure calls.
    status = RpcServerUseProtseqEp(
        reinterpret_cast<unsigned char*>("ncalrpc"), // Local RPC Protocol Sequence
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT, // Backlog queue length.
        reinterpret_cast<unsigned char*>("AppAttestationRPCEndpoint"), // Name of the Endpoint
        NULL); // No security.

    if (status)
        exit(status);

    // Registers the Example1 interface.
    status = RpcServerRegisterIf2(
        RPCDefinitions_v1_0_s_ifspec, // Interface to register.
        NULL, // Use the MIDL generated entry-point vector.
        NULL, // Use the MIDL generated entry-point vector.
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, // Forces use of security callback.
        RPC_C_LISTEN_MAX_CALLS_DEFAULT, // Use default number of concurrent calls.
        (unsigned)-1, // Infinite max size of incoming data blocks.
        SecurityCallback); // Naive security callback.

    if (status)
        exit(status);

    // Start to listen for remote procedure calls for all registered interfaces.
    // This call will not return until RpcMgmtStopServerListening is called.
    status = RpcServerListen(
        1, // Recommended minimum number of threads.
        RPC_C_LISTEN_MAX_CALLS_DEFAULT, // Recommended maximum number of threads.
        FALSE); // Start listening now.

    if (status)
        exit(status);
}

int main()
{   
    HANDLE appLogProcessingThread;
    DWORD appLogThreadId;

    HANDLE clientRPCThread;
    DWORD rpcThreadId;

    // Create the app log processing thread
    appLogProcessingThread = CreateThread(
        NULL,                   // Default security attributes
        0,                      // Default stack size
        GetAndProcessAppEventLogs,        // Thread function
        NULL,                   // No parameters to pass to thread function
        0,                      // Default creation flags
        &appLogThreadId               // Thread ID
    );

    if (appLogProcessingThread == NULL) {
        fprintf(stderr, "Failed to create App Log processing thread\n");
        return 1;
    }

    // Create the RPC listening thread
    clientRPCThread = CreateThread(
        NULL,                   // Default security attributes
        0,                      // Default stack size
        ListenToClientRPC,        // Thread function
        NULL,                   // No parameters to pass to thread function
        0,                      // Default creation flags
        &rpcThreadId               // Thread ID
    );

    if (clientRPCThread == NULL) {
        fprintf(stderr, "Failed to create RPC thread\n");
        return 1;
    }

    // Wait for the thread to finish execution
    WaitForSingleObject(appLogProcessingThread, INFINITE);

    // Terminate the thread
    if (!TerminateThread(clientRPCThread, 0)) {
        printf("RPC Thread termination failed\n");
        return 1;
    }

    // Close thread handles
    CloseHandle(appLogProcessingThread);
    CloseHandle(clientRPCThread);

    return 0;
}

// Memory allocation function for RPC.
// The runtime uses these two functions for allocating/deallocating
// enough memory to pass the string to the server.
void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

// Memory deallocation function for RPC.
void __RPC_USER midl_user_free(void* p)
{
    free(p);
}
