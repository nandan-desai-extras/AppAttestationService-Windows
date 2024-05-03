#pragma once
#include "includes.h"

HRESULT
GetEKCert(
    unsigned char** rpc_buffer,
    unsigned long* rpc_buffer_size
);

HRESULT
GetEK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
);

HRESULT
CreateAIK(
    const WCHAR* keyName,
    const WCHAR* nonce,
    unsigned char** idBinding,
    unsigned long* idBindingSize
);

HRESULT
ActivateAIK(
    const WCHAR* keyName,
    unsigned char* serverActivationBlob,
    unsigned long serverActivationBlobSize,
    unsigned long* serverSecretSize,
    unsigned char** serverSecret
);

HRESULT
GetPubKey(
    const WCHAR* keyName,
    const WCHAR* keyFile
);

HRESULT
RegisterAIK(
    const WCHAR* keyName
);

HRESULT
EnumerateAIK();



