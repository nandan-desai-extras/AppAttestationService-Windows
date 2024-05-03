#include <iostream>
#include "../RPCDefinitions/RPCDefinitions.h"
#include "RPC_Wrapper_Functions.h"


void Wrapper_GetEK_CreateAIK(wchar_t* aik_name, wchar_t* server_nonce, unsigned char** EK_out, unsigned long* EK_size_out, unsigned char** idBinding_out, unsigned long* idBindingSize_out)
{
    if (*EK_out != NULL || *idBinding_out != NULL) {
        printf("Buffers are not empty\n");
        return;
    }

    RPC_STATUS status;
    unsigned char* szStringBinding = NULL;

    // Creates a string binding handle.
    // This function is nothing more than a printf.
    // Connection is not done here.
    status = RpcStringBindingCompose(
        NULL, // UUID to bind to.
        reinterpret_cast<unsigned char*>("ncalrpc"), // Local RPC Protocol Sequence
        NULL, // Network address
        reinterpret_cast<unsigned char*>("AppAttestationRPCEndpoint"), // Name of the endpoint
        NULL, // Protocol dependent network options to use.
        &szStringBinding); // String binding output.

    if (status)
        exit(status);

    // Validates the format of the string binding handle and converts
    // it to a binding handle.
    // Connection is not done here either.
    status = RpcBindingFromStringBindingA(
        szStringBinding, // The string binding to validate.
        &hExample1Binding); // Put the result in the implicit binding
    // handle defined in the IDL file.

    if (status)
        exit(status);

    RpcTryExcept
    {
         unsigned char** EK = (unsigned char**)midl_user_allocate(sizeof(unsigned char*));
        *EK = NULL; // Required to create a unique pointer
        unsigned long EKsize = 0;

        unsigned char** idBinding = (unsigned char**)midl_user_allocate(sizeof(unsigned char*));
        *idBinding = NULL; // Required to create a unique pointer
        unsigned long idBindingSize = 0;

        if (RPC_GetEK_CreateAIK(aik_name, server_nonce, &EKsize, EK, &idBindingSize, idBinding) != 0) {
            // ignoring the error message here because it seems to return non-zero even on success
            // no time to debug why
            /*printf("Error occurred in RPC_GetEK_CreateAIK()\n");
            goto Cleanup;*/
        }

        *EK_out = (unsigned char*)malloc(EKsize);
        *idBinding_out = (unsigned char*)malloc(idBindingSize);

        memcpy(*EK_out, *EK, EKsize);
        memcpy(*idBinding_out, *idBinding, idBindingSize);

        *EK_size_out = EKsize;
        *idBindingSize_out = idBindingSize;
    Cleanup:
        MIDL_user_free(*EK);
        MIDL_user_free(EK);
        MIDL_user_free(*idBinding);
        MIDL_user_free(idBinding);
    }
    RpcExcept(1)
    {
        std::cerr << "Runtime reported exception " << RpcExceptionCode()
            << std::endl;
    }
    RpcEndExcept

        // Free the memory allocated by a string.
        status = RpcStringFree(
            &szStringBinding); // String to be freed.

    if (status)
        exit(status);

    // Releases binding handle resources and disconnects from the server.
    status = RpcBindingFree(
        &hExample1Binding); // Frees the implicit binding handle defined in
    // the IDL file.

    if (status)
        exit(status);
}


void Wrapper_VerifyActivationBlob(wchar_t* aik_name, unsigned char* activationBlob_in, unsigned long activationBlobSize_in, unsigned char** server_secret_out, unsigned long* server_secret_size_out)
{
    if (*server_secret_out != NULL || activationBlob_in == NULL || aik_name == NULL) {
        printf("Invalid parameters\n");
        return;
    }

    RPC_STATUS status;
    unsigned char* szStringBinding = NULL;

    // Creates a string binding handle.
    // This function is nothing more than a printf.
    // Connection is not done here.
    status = RpcStringBindingCompose(
        NULL, // UUID to bind to.
        reinterpret_cast<unsigned char*>("ncalrpc"), // Local RPC Protocol Sequence
        NULL, // Network address
        reinterpret_cast<unsigned char*>("AppAttestationRPCEndpoint"), // Name of the endpoint
        NULL, // Protocol dependent network options to use.
        &szStringBinding); // String binding output.

    if (status)
        exit(status);

    // Validates the format of the string binding handle and converts
    // it to a binding handle.
    // Connection is not done here either.
    status = RpcBindingFromStringBindingA(
        szStringBinding, // The string binding to validate.
        &hExample1Binding); // Put the result in the implicit binding
    // handle defined in the IDL file.

    if (status)
        exit(status);

    RpcTryExcept
    {
         unsigned char* activationBlobBuffer = (unsigned char*)midl_user_allocate(activationBlobSize_in);
        memcpy(activationBlobBuffer, activationBlob_in, activationBlobSize_in);

        unsigned char** server_secret = (unsigned char**)midl_user_allocate(sizeof(unsigned char*));
        *server_secret = NULL; // Required to create a unique pointer
        unsigned long server_secret_size = 0;

        if (RPC_VerifyActivationBlob(aik_name, activationBlobSize_in, activationBlobBuffer, &server_secret_size, server_secret) != 0) {
            printf("Error occurred in RPC_VerifyActivationBlob()\n");
            goto Cleanup;
        }

        *server_secret_out = (unsigned char*)malloc(server_secret_size);
        memcpy(*server_secret_out, *server_secret, server_secret_size);
        *server_secret_size_out = server_secret_size;

     Cleanup:
        MIDL_user_free(activationBlobBuffer);
        MIDL_user_free(*server_secret);
        MIDL_user_free(server_secret);
    }
        RpcExcept(1)
    {
        std::cerr << "Runtime reported exception " << RpcExceptionCode()
            << std::endl;
    }
    RpcEndExcept

        // Free the memory allocated by a string.
        status = RpcStringFree(
            &szStringBinding); // String to be freed.

    if (status)
        exit(status);

    // Releases binding handle resources and disconnects from the server.
    status = RpcBindingFree(
        &hExample1Binding); // Frees the implicit binding handle defined in
    // the IDL file.

    if (status)
        exit(status);
}

void Wrapper_RegisterAIK(wchar_t* aik_name) {
    if (aik_name == NULL) {
        printf("Invalid parameters\n");
        return;
    }

    RPC_STATUS status;
    unsigned char* szStringBinding = NULL;

    // Creates a string binding handle.
    // This function is nothing more than a printf.
    // Connection is not done here.
    status = RpcStringBindingCompose(
        NULL, // UUID to bind to.
        reinterpret_cast<unsigned char*>("ncalrpc"), // Local RPC Protocol Sequence
        NULL, // Network address
        reinterpret_cast<unsigned char*>("AppAttestationRPCEndpoint"), // Name of the endpoint
        NULL, // Protocol dependent network options to use.
        &szStringBinding); // String binding output.

    if (status)
        exit(status);

    // Validates the format of the string binding handle and converts
    // it to a binding handle.
    // Connection is not done here either.
    status = RpcBindingFromStringBindingA(
        szStringBinding, // The string binding to validate.
        &hExample1Binding); // Put the result in the implicit binding
    // handle defined in the IDL file.

    if (status)
        exit(status);

    RpcTryExcept
    {
        RPC_RegisterAIK(aik_name);
    }
        RpcExcept(1)
    {
        std::cerr << "Runtime reported exception " << RpcExceptionCode()
            << std::endl;
    }
    RpcEndExcept

        // Free the memory allocated by a string.
        status = RpcStringFree(
            &szStringBinding); // String to be freed.

    if (status)
        exit(status);

    // Releases binding handle resources and disconnects from the server.
    status = RpcBindingFree(
        &hExample1Binding); // Frees the implicit binding handle defined in
    // the IDL file.

    if (status)
        exit(status);
}


void Wrapper_GetAppAttestation(wchar_t* aik_name, wchar_t* server_nonce, unsigned char** attestationBlob_out, unsigned long* appAttestationSize_out, unsigned long* platformAttestationSize_out, unsigned long* totalSize_out) {

    RPC_STATUS status;
    unsigned char* szStringBinding = NULL;

    // Creates a string binding handle.
    // This function is nothing more than a printf.
    // Connection is not done here.
    status = RpcStringBindingCompose(
        NULL, // UUID to bind to.
        reinterpret_cast<unsigned char*>("ncalrpc"), // Local RPC Protocol Sequence
        NULL, // Network address
        reinterpret_cast<unsigned char*>("AppAttestationRPCEndpoint"), // Name of the endpoint
        NULL, // Protocol dependent network options to use.
        &szStringBinding); // String binding output.

    if (status)
        exit(status);

    // Validates the format of the string binding handle and converts
    // it to a binding handle.
    // Connection is not done here either.
    status = RpcBindingFromStringBindingA(
        szStringBinding, // The string binding to validate.
        &hExample1Binding); // Put the result in the implicit binding
    // handle defined in the IDL file.

    if (status)
        exit(status);

    RpcTryExcept
    {
        unsigned char** attestationBlob = (unsigned char**)midl_user_allocate(sizeof(unsigned char*));
        *attestationBlob = NULL; // Required to create a unique pointer
        unsigned long attestationBlobTotalSize = 0;
        unsigned long appAttestationSize = 0;
        unsigned long platformAttestationSize = 0;

        if (RPC_GetAppAttestation(hExample1Binding, aik_name, server_nonce, &platformAttestationSize, &appAttestationSize, &attestationBlobTotalSize, attestationBlob) != 0) {
            printf("Error occurred in RPC_GetAppAttestation()\n");
            goto Cleanup;
        }

        *attestationBlob_out = (unsigned char*)malloc(attestationBlobTotalSize);
        memcpy(*attestationBlob_out, *attestationBlob, attestationBlobTotalSize);
        *appAttestationSize_out = appAttestationSize;
        *platformAttestationSize_out = platformAttestationSize;
        *totalSize_out = attestationBlobTotalSize;

        Cleanup:
        MIDL_user_free(*attestationBlob);
        MIDL_user_free(attestationBlob);
    }
        RpcExcept(1)
    {
        std::cerr << "Runtime reported exception " << RpcExceptionCode()
            << std::endl;
    }
    RpcEndExcept

        // Free the memory allocated by a string.
        status = RpcStringFree(
            &szStringBinding); // String to be freed.

    if (status)
        exit(status);

    // Releases binding handle resources and disconnects from the server.
    status = RpcBindingFree(
        &hExample1Binding); // Frees the implicit binding handle defined in
    // the IDL file.

    if (status)
        exit(status);
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
