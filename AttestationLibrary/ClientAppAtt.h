#pragma once
#include "AppAttestationApi.h"

HRESULT
ClientGetAppAttestation(
    WCHAR* aikName,
    WCHAR* nonce,
    unsigned char** appAttestationBlob,
    unsigned long* appAttestationBlobSize
);