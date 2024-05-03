#pragma once
#include <stdio.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_BUFFER_SIZE 102400

#define CLIENT_PORT 8080
#define SERVER_PORT 9080

#define SERVER_IP "127.0.0.1"
#define CLIENT_IP "127.0.0.1"

typedef struct AttestationBlob {
    unsigned long attestationBlobTotalSize;
    unsigned long appAttestationSize;
    unsigned long platformAttestationSize;
    unsigned char attestationBlob[1];
};

typedef struct AttestationRequest {
    char requestMsg[100];
    wchar_t serverNonce[100];
    size_t serverNonceSize;
};

int SendData(char* ip_address, int port, unsigned char* buffer, size_t size);

int ReceiveData(unsigned char** buffer_ptr, size_t* size_ptr, int port);

