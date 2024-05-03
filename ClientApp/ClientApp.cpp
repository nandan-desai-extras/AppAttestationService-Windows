// File ClientApp.cpp
#include <iostream>
#include "RemoteServerComm.h"
#include "RPC_Wrapper_Functions.h"

#define AIK_NAME L"myClientAIK"

#pragma section(".attest", read)
__declspec(allocate(".attest")) char attestationSection[16] = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10
};


void InitialHandshakeWithRemoteServer() {
    unsigned char* nonce = NULL;
    size_t nonce_size = 0;

    unsigned char* EK = NULL;
    unsigned long EKSize = 0;
    unsigned char* idBinding = NULL;
    unsigned long idBindingSize = 0;

    unsigned char* activationBlob = NULL;
    size_t activationBlobSize = 0;
    unsigned char* serverSecret = NULL;
    unsigned long serverSecretSize = 0;

    unsigned char* secretVerifiedConfirmation = NULL;
    size_t secretVerifiedConfirmationSize = 0;
    const char* positiveConfirmation = "AIK_ACCEPTED";

    if (ReceiveData(&nonce, &nonce_size, CLIENT_PORT) != 0) {
        goto Cleanup;
    }

    Wrapper_GetEK_CreateAIK(AIK_NAME, (wchar_t*)nonce, &EK, &EKSize, &idBinding, &idBindingSize);

    // Send EK and ID-Binding
    if (SendData(SERVER_IP, SERVER_PORT, EK, EKSize) != 0) {
        goto Cleanup;
    }

    if(SendData(SERVER_IP, SERVER_PORT, idBinding, idBindingSize) != 0) {
        goto Cleanup;
    }

    // Wait for the server to send the Activation Blob
    if(ReceiveData(&activationBlob, &activationBlobSize, CLIENT_PORT) != 0) {
        goto Cleanup;
    }

    // Decrypt the server secret from the Activation Blob
    Wrapper_VerifyActivationBlob(AIK_NAME, activationBlob, activationBlobSize, &serverSecret, &serverSecretSize);

    // Send the server secret back to the server for verification
    if (SendData(SERVER_IP, SERVER_PORT, serverSecret, serverSecretSize) != 0) {
        goto Cleanup;
    }
    
    // Receive the verification confirmation from the server
    if (ReceiveData(&secretVerifiedConfirmation, &secretVerifiedConfirmationSize, CLIENT_PORT) != 0) {
        goto Cleanup;
    }

    if (memcmp(secretVerifiedConfirmation, (unsigned char*)positiveConfirmation, strlen(positiveConfirmation)) == 0) {

        // If server has accepted the client's AIK, save the AIK in the Registry
        Wrapper_RegisterAIK(AIK_NAME);
    }
    else {
        printf("Server refused to accept the AIK.\n");
        goto Cleanup;
    }

Cleanup:
    free(secretVerifiedConfirmation);
    free(serverSecret);
    free(activationBlob);
    free(EK);
    free(idBinding);
    free(nonce);
}



void SendAttestationDataToRemoteServer(void) {
    unsigned long totalSize = 0;
    unsigned long appAttestationSize = 0;
    unsigned long platformAttestationSize = 0;
    unsigned char* attBlob = NULL;

    AttestationBlob* pAttBlob = NULL;

    AttestationRequest* attestationRequest = NULL;
    size_t attestationRequestSize = 0;

    // Receive the attestation request from the server
    if (ReceiveData((unsigned char**)&attestationRequest, &attestationRequestSize, CLIENT_PORT) != 0) {
        goto Cleanup;
    }

    char* requestFromServer = "GET_ATTESTATION";
    if (memcmp(attestationRequest->requestMsg, (unsigned char*)requestFromServer, strlen(requestFromServer)) == 0) {
        
        Wrapper_GetAppAttestation(AIK_NAME, (wchar_t*)attestationRequest->serverNonce, &attBlob, &appAttestationSize, &platformAttestationSize, &totalSize);

        size_t blobStructSize = sizeof(AttestationBlob) - 1 + totalSize;

        pAttBlob = (AttestationBlob*) malloc(blobStructSize);

        pAttBlob->appAttestationSize = appAttestationSize;
        pAttBlob->platformAttestationSize = platformAttestationSize;
        pAttBlob->attestationBlobTotalSize = totalSize;
        memcpy(pAttBlob->attestationBlob, attBlob, totalSize);

        

        if (SendData(SERVER_IP, SERVER_PORT, (unsigned char*) pAttBlob, blobStructSize) != 0) {
            goto Cleanup;
        }

    }
    else {
        printf("Invalid attestation request received from the server.\n");
        goto Cleanup;
    }
Cleanup:
    free(attestationRequest);
    free(attBlob);
    free(pAttBlob);
}

int main()
{
    InitialHandshakeWithRemoteServer();
    SendAttestationDataToRemoteServer();
}