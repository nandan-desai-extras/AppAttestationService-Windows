#pragma once

void Wrapper_GetEK_CreateAIK(wchar_t* aik_name, wchar_t* server_nonce, unsigned char** EK_out, unsigned long* EK_size_out, unsigned char** idBinding_out, unsigned long* idBindingSize_out);

void Wrapper_VerifyActivationBlob(wchar_t* aik_name, unsigned char* activationBlob_in, unsigned long activationBlobSize_in, unsigned char** server_secret_out, unsigned long* server_secret_size_out);

void Wrapper_RegisterAIK(wchar_t* aik_name);

void Wrapper_GetAppAttestation(wchar_t* aik_name, wchar_t* server_nonce, unsigned char** attestationBlob_out, unsigned long* appAttestationSize_out, unsigned long* platformAttestationSize_out, unsigned long* totalSize_out);
