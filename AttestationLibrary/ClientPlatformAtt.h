#pragma once
#include "includes.h"

HRESULT
GetPlatformAttestation(
    WCHAR* aikName,
    WCHAR* nonce,
    unsigned char** platformAttestationBlob,
    unsigned long* platformAttestationBlobSize
);


