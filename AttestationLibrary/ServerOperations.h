#pragma once
#include "includes.h"

HRESULT
ExtractEK(
    const WCHAR* certFile,
    const WCHAR* ekPubFile
);

HRESULT
ChallengeAIK(
    const WCHAR* idBindingFile,
    const WCHAR* ekPubFile,
    const WCHAR* activationSecret,
    const WCHAR* activationBlobFile,
    const WCHAR* nonce
);

HRESULT
GetPubAIK(
    const WCHAR* idBindingFile,
    const WCHAR* keyFile
);

HRESULT
ValidatePlatformAttestation(
    const WCHAR* attestationFile,
    const WCHAR* aikName,
    const WCHAR* nonce
);

HRESULT
ServerValidateAppAttestation(
    const WCHAR* attestationFile,
    const WCHAR* aikName,
    const WCHAR* nonce
);
