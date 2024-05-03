#include <stdio.h>
#include <iostream>
#include "../ClientApp/RemoteServerComm.h"
#include "../AttestationLibrary/ServerOperations.h"

void Local_WriteFile(const wchar_t* filename, unsigned char* bytes, size_t size) {
    // Open the file for writing in binary mode
    FILE* file = _wfopen(filename, L"wb");
    if (file == NULL) {
        printf("Error opening file %ws for writing.\n", filename);
        return;
    }

    // Write the array of bytes to the file
    size_t bytesWritten = fwrite(bytes, sizeof(unsigned char), size, file);
    if (bytesWritten != size) {
        printf("Error writing to file %ws.\n", filename);
    }
    else {
        printf("Array of bytes successfully written to %ws.\n", filename);
    }

    // Close the file
    fclose(file);
}

unsigned char* Local_ReadFile(const wchar_t* filename, unsigned long* size) {
    // Open the file for reading in binary mode
    FILE* file = _wfopen(filename, L"rb");
    if (file == NULL) {
        printf("Error opening file %ws for reading.\n", filename);
        return NULL;
    }
    // Get the size of the file
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (buffer == NULL) {
        printf("Error allocating memory for buffer.\n");
        fclose(file);
        return NULL;
    }
    // Read the file into the buffer
    size_t bytesRead = fread(buffer, sizeof(unsigned char), fileSize, file);
    if (bytesRead != fileSize) {
        printf("Error reading from file %ws.\n", filename);
        free(buffer);
        fclose(file);
        return NULL;
    }
    // Close the file
    fclose(file);
    // Set the size of the file in the pointer
    *size = fileSize;
    return buffer;
}

int search_string(unsigned char* blob, size_t blob_size, const char* target_string) {
    size_t target_len = strlen(target_string);
    size_t i;

    for (i = 0; i < blob_size - target_len; i++) {
        if (memcmp(blob + i, target_string, target_len) == 0) {
            return 1; // Found the target string
        }
    }

    return 0; // Target string not found
}


void InitialHandshakeWithClient(void) {

    unsigned char* EK = NULL;
    size_t EKSize = 0;
    unsigned char* idBinding = NULL;
    size_t idBindingSize = 0;

    unsigned char* activationBlob = NULL;
    size_t activationBlobSize = 0;
    unsigned char* serverSecret = NULL;
    size_t serverSecretSize = 0;

    const char* positiveConfirmation = "AIK_ACCEPTED";

    const wchar_t* secret = L"456";

    const wchar_t* nonce = L"123";
    if (SendData((char*)CLIENT_IP, CLIENT_PORT, (unsigned char*) nonce, (wcslen(nonce) * sizeof(wchar_t) + 2)) != 0) {
        goto Cleanup;
    }

    // add delay here

    if (ReceiveData(&EK, &EKSize, SERVER_PORT) != 0) {
        goto Cleanup;
    }

    Local_WriteFile(L"EKCert", EK, EKSize);
    printf("EK received! Bytes received: %u\n", EKSize);

    if (ReceiveData(&idBinding, &idBindingSize, SERVER_PORT) != 0) {
        goto Cleanup;
    }

    Local_WriteFile(L"idBinding", idBinding, idBindingSize);
    printf("idBinding received! Bytes received: %u\n", EKSize);


    ExtractEK(L"EKCert", L"EKpub");

    ChallengeAIK(L"idBinding", L"EKpub", secret, L"activationBlob", nonce);

    activationBlob = Local_ReadFile(L"activationBlob", (unsigned long*) &activationBlobSize);

    if (SendData((char*)CLIENT_IP, CLIENT_PORT, (unsigned char*)activationBlob, activationBlobSize) != 0) {
        goto Cleanup;
    }

    if (ReceiveData(&serverSecret, &serverSecretSize, SERVER_PORT) != 0) {
        goto Cleanup;
    }

    if (memcmp(serverSecret, (unsigned char*)secret, serverSecretSize) == 0) {
        if (SendData((char*)CLIENT_IP, CLIENT_PORT, (unsigned char*)positiveConfirmation, strlen(positiveConfirmation) + 1) != 0) {
            goto Cleanup;
        }
    }
    else {
        printf("Secret returned by the server didn't match\n");
    }

Cleanup:
    free(serverSecret);
    free(activationBlob);
    free(EK);
    free(idBinding);
}

void RequestAppAttestationFromClient(void) {
    size_t totalSize;
    AttestationBlob* pAttBlob = NULL;

    const wchar_t* nonce = L"123";
    size_t attReqSize = sizeof(AttestationRequest); //+ (wcslen(nonce) * sizeof(wchar_t) + 2)
    AttestationRequest* pAttReq = (AttestationRequest*) malloc(attReqSize);
    const char* attReqMsg = "GET_ATTESTATION";

    memcpy(pAttReq->requestMsg, attReqMsg, strlen(attReqMsg)+1);

    pAttReq->serverNonceSize = (wcslen(nonce) * sizeof(wchar_t) + 2);

    memcpy((unsigned char*)pAttReq->serverNonce, (unsigned char*)nonce, pAttReq->serverNonceSize);
    
    if (SendData((char*)CLIENT_IP, CLIENT_PORT, (unsigned char*)pAttReq, attReqSize) != 0) {
        goto Cleanup;
    }

    // Receive the attestation blob from the client
    if (ReceiveData((unsigned char**) &pAttBlob, (size_t*) &totalSize, SERVER_PORT) != 0) {
        goto Cleanup;
    }

    Local_WriteFile(L"platformAttestationBlob", pAttBlob->attestationBlob, pAttBlob->platformAttestationSize);

    GetPubAIK(L"idBinding", L"Aikpub"); // on the server
    ValidatePlatformAttestation(L"platformAttestationBlob", L"Aikpub", nonce); // on the server

    Local_WriteFile(L"appAttestationBlob", ((pAttBlob->attestationBlob) + pAttBlob->platformAttestationSize), pAttBlob->appAttestationSize);

    if (ServerValidateAppAttestation(L"appAttestationBlob", L"Aikpub", nonce) == S_OK) {
        if (search_string(((pAttBlob->attestationBlob) + pAttBlob->platformAttestationSize), pAttBlob->appAttestationSize, "Debugger"))
            printf("String 'Debugger' found! Client CANNOT be trusted!\n");
        else
            printf("String 'Debugger' not found. Client can be trusted!\n");
    }
    
Cleanup:
    free(pAttReq);
    free(pAttBlob);
}


int main(int argc, char const* argv[]) {
    InitialHandshakeWithClient();
    RequestAppAttestationFromClient();
}
