#include "Utils.h"
#include "ServerOperations.h"
#include "AppAttestationApi.h"

HRESULT
ExtractEK(
    const WCHAR* certFile,
    const WCHAR* ekPubFile
)
/*++
Retrieve the EKPub from the EKCert as BCRYPT_RSAKEY_BLOB structure. This code
is used on the server side after the EKCert has been validated and deemed
trustworthy.
--*/
{
    HRESULT hr = S_OK;
    PCCERT_CONTEXT pcCertContext = NULL;
    PBYTE pbEkCert = NULL;
    UINT32 cbEkCert = 0;
    BCRYPT_KEY_HANDLE hEK = NULL;
    BYTE pbEkPub[1024] = { 0 };
    DWORD cbEkPub = 0;

    if (FAILED(hr = ReadFile(
        certFile,
        NULL,
        0,
        &cbEkCert)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbEkCert, cbEkCert)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadFile(
        certFile,
        pbEkCert,
        cbEkCert,
        &cbEkCert)))
    {
        goto Cleanup;
    }

    // Open Certificate
    if ((pcCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING |
        PKCS_7_ASN_ENCODING,
        pbEkCert,
        cbEkCert)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }


    // Since this is a PKCS_RSAES_OAEP_PARAMETERS encoded public key
    // that is not directly consumed by Windows, we have to tinker with it
    // a little so Windows will ignore the OAEP OCTET_STRING in it and just
    // process the RSA public key.
    pcCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;

    // Instantiate the key from the cert
    if (!CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING,
        &pcCertContext->pCertInfo->SubjectPublicKeyInfo,
        0,
        NULL,
        &hEK))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Export the public key
    if (FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
        hEK,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        pbEkPub,
        sizeof(pbEkPub),
        &cbEkPub,
        0))))
    {
        goto Cleanup;
    }

    // Store the key
    if (ekPubFile != NULL)
    {
        if (FAILED(hr = WriteFile(ekPubFile, pbEkPub, cbEkPub)))
        {
            goto Cleanup;
        }
    }

    // Output results
    DisplayKey(L"EndorsementKey", pbEkPub, cbEkPub, 0);

Cleanup:
    if (pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if (hEK != NULL)
    {
        BCryptDestroyKey(hEK);
        hEK = NULL;
    }
    ZeroAndFree((PVOID*)&pbEkCert, cbEkCert);
    CallResult((WCHAR*)L"ExtractEK()", hr);
    return hr;
}

HRESULT
ChallengeAIK(
    const WCHAR* idBindingFile,
    const WCHAR* ekPubFile,
    const WCHAR* activationSecret,
    const WCHAR* activationBlobFile,
    const WCHAR* nonce
)
/*++
This function is the third step in what is known as the AIK handshake and
executed on the server. The server will have already looked at the EKCert and
extracted the EKPub from it. This step will generate the activation blob, which
is the challenge to the client. The secret may be a nonce or a symmetric key
that encrypts a certificate for the AIK for example.
--*/
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hEK = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    PBYTE pbIdBinding = NULL;
    UINT32 cbIdBinding = 0;
    PBYTE pbEkPub = NULL;
    UINT32 cbEkPub = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = { 0 };
    PBYTE pbActivationBlob = NULL;
    UINT32 cbActivationBlob = 0;
    UINT32 result = 0;
    
    // idBindingFile
    if (FAILED(hr = ReadFile(
        idBindingFile,
        NULL,
        0,
        &cbIdBinding)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbIdBinding, cbIdBinding)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadFile(idBindingFile,
        pbIdBinding,
        cbIdBinding,
        &cbIdBinding)))
    {
        goto Cleanup;
    }
    

    // EKPub
    if (FAILED(hr = ReadFile(ekPubFile, NULL, 0, &cbEkPub)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbEkPub, cbEkPub)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadFile(ekPubFile,
        pbEkPub,
        cbEkPub,
        &cbEkPub)))
    {
        goto Cleanup;
    }

    // Nonce
    if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
        NULL,
        0,
        (PBYTE)nonce,
        (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
        nonceDigest,
        sizeof(nonceDigest),
        &result)))
    {
        goto Cleanup;
    }
    

    // Load the keys
    if (FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RSA_ALGORITHM,
        MS_PRIMITIVE_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
        hAlg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &hEK,
        pbEkPub,
        cbEkPub,
        0))))
    {
        goto Cleanup;
    }

    // Get a handle to the AIK and export it
    if (FAILED(hr = TpmAttPubKeyFromIdBinding(
        pbIdBinding,
        cbIdBinding,
        hAlg,
        &hAik)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
        hAik,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        0,
        (PULONG)&cbAikPub,
        0))))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
        hAik,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        pbAikPub,
        cbAikPub,
        (PULONG)&cbAikPub,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = TpmAttGenerateActivation(
        hEK,
        pbIdBinding,
        cbIdBinding,
        (nonce) ? nonceDigest : NULL,
        (nonce) ? sizeof(nonceDigest) : 0,
        (PBYTE)activationSecret,
        (UINT16)((wcslen(activationSecret) + 1) *
            sizeof(WCHAR)),
        NULL,
        0,
        &cbActivationBlob)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbActivationBlob, cbActivationBlob)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = TpmAttGenerateActivation(
        hEK,
        pbIdBinding,
        cbIdBinding,
        (nonce) ? nonceDigest : NULL,
        (nonce) ? sizeof(nonceDigest) : 0,
        (PBYTE)activationSecret,
        (UINT16)((wcslen(activationSecret) + 1) *
            sizeof(WCHAR)),
        pbActivationBlob,
        cbActivationBlob,
        &cbActivationBlob)))
    {
        goto Cleanup;
    }

    // Store the activation if required
    if (idBindingFile != NULL)
    {
        if (FAILED(hr = WriteFile(
            activationBlobFile,
            pbActivationBlob,
            cbActivationBlob)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<Activation>\n");
    if (FAILED(hr = DisplayKey(L"AIK", pbAikPub, cbAikPub, 1)))
    {
        goto Cleanup;
    }
    LevelPrefix(1);
    wprintf(L"<ActivationBlob size=\"%u\">\n", cbActivationBlob);
    LevelPrefix(2);
    for (UINT32 n = 0; n < cbActivationBlob; n++)
    {
        wprintf(L"%02x", pbActivationBlob[n]);
    }
    wprintf(L"\n");
    LevelPrefix(1);
    wprintf(L"</ActivationBlob>\n");
    wprintf(L"</Activation>\n");

Cleanup:
    if (hEK != NULL)
    {
        BCryptDestroyKey(hEK);
        hEK = NULL;
    }
    if (hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if (hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbIdBinding, cbIdBinding);
    ZeroAndFree((PVOID*)&pbEkPub, cbEkPub);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    ZeroAndFree((PVOID*)&pbActivationBlob, cbActivationBlob);
    CallResult((WCHAR*)L"ChallengeAIK()", hr);
    return hr;
}

HRESULT
GetPubAIK(
    const WCHAR* idBindingFile,
    const WCHAR* keyFile
)
/*++
Export the public portion from an AIK as
BCRYPT_RSAKEY_BLOB structure.
--*/
{
    HRESULT hr = S_OK;
    PBYTE pbIdBinding = NULL;
    UINT32 cbIdBinding = 0;
    BCRYPT_ALG_HANDLE hProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE pbPubKey[1024] = { 0 };
    DWORD cbPubKey = 0;

    if (FAILED(hr = ReadFile(
        idBindingFile,
        NULL,
        0,
        &cbIdBinding)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbIdBinding, cbIdBinding)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadFile(idBindingFile,
        pbIdBinding,
        cbIdBinding,
        &cbIdBinding)))
    {
        goto Cleanup;
    }

    // Open key
    if (FAILED(hr = BCryptOpenAlgorithmProvider(
        &hProv,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0)))
    {
        goto Cleanup;
    }

    if (FAILED(hr = TpmAttPubKeyFromIdBinding(
        pbIdBinding,
        cbIdBinding,
        hProv,
        &hKey)))
    {
        goto Cleanup;
    }

    // Export public key
    if (FAILED(hr = BCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        pbPubKey,
        sizeof(pbPubKey),
        &cbPubKey,
        0)))
    {
        goto Cleanup;
    }

    // Export key
    if (keyFile != NULL)
    {
        if (FAILED(hr = WriteFile(keyFile, pbPubKey, cbPubKey)))
        {
            goto Cleanup;
        }
    }

    // Output results
    if (FAILED(hr = DisplayKey(L"AIK", pbPubKey, cbPubKey, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if (hKey != NULL)
    {
        BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        BCryptCloseAlgorithmProvider(hProv, 0);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbIdBinding, cbIdBinding);
    CallResult((WCHAR*)L"GetPubAIK()", hr);
    return hr;
}

HRESULT
ValidatePlatformAttestation(
    const WCHAR* attestationFile,
    const WCHAR* aikName,
    const WCHAR* nonce
)
/*++
This function will validate an AIK signed platform attestation blob. In this case
the attestation is signed and nonces are supported. This attestation is tamper
proof.
--*/
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 cbNonceDigest = sizeof(nonceDigest);

    // Attestation blob file
    if (FAILED(hr = ReadFile(
        attestationFile,
        NULL,
        0,
        &cbAttestation)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadFile(
        attestationFile,
        pbAttestation,
        cbAttestation,
        &cbAttestation)))
    {
        goto Cleanup;
    }
    

    // AIK pub
    if (wcslen(aikName) > 0)
    {
        if (FAILED(hr = ReadFile(aikName, NULL, 0, &cbAikPub)))
        {
            goto Cleanup;
        }
        if (FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
        {
            goto Cleanup;
        }
        if (FAILED(hr = ReadFile(
            aikName,
            pbAikPub,
            cbAikPub,
            &cbAikPub)))
        {
            goto Cleanup;
        }
    }
    

    //  Nonce
    if (wcslen(nonce) > 0)
    {
        if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
            NULL,
            0,
            (PBYTE)nonce,
            (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
            nonceDigest,
            sizeof(nonceDigest),
            &cbNonceDigest)))
        {
            goto Cleanup;
        }
    }
    else
    {
        nonce = NULL;
    }
    

    // Load the AIKPub
    if (wcslen(aikName) > 0)
    {
        if (FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_RSA_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            0))))
        {
            goto Cleanup;
        }

        if (FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
            hAlg,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &hAik,
            pbAikPub,
            cbAikPub,
            0))))
        {
            goto Cleanup;
        }
    }

    // Validate the Attestation Blob
    if (FAILED(hr = TpmAttValidatePlatformAttestation(
        hAik,
        (nonce) ? nonceDigest : NULL,
        (nonce) ? sizeof(nonceDigest) : 0,
        pbAttestation,
        cbAttestation)))
    {
        goto Cleanup;
    }

    // Output
    wprintf(L"Platform Attestation Verified - OK.\n");

Cleanup:
    if (hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if (hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    CallResult((WCHAR*)L"ValidatePlatformAttestation()", hr);
    return hr;
}




HRESULT
ServerValidateAppAttestation(
    const WCHAR* attestationFile,
    const WCHAR* aikName,
    const WCHAR* nonce
)
/*++
This function will validate an AIK signed platform attestation blob. In this case
the attestation is signed and nonces are supported. This attestation is tamper
proof.
--*/
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 cbNonceDigest = sizeof(nonceDigest);

    // Attestation blob file
    if (FAILED(hr = ReadFile(
        attestationFile,
        NULL,
        0,
        &cbAttestation)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadFile(
        attestationFile,
        pbAttestation,
        cbAttestation,
        &cbAttestation)))
    {
        goto Cleanup;
    }


    // AIK pub
    if (wcslen(aikName) > 0)
    {
        if (FAILED(hr = ReadFile(aikName, NULL, 0, &cbAikPub)))
        {
            goto Cleanup;
        }
        if (FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
        {
            goto Cleanup;
        }
        if (FAILED(hr = ReadFile(
            aikName,
            pbAikPub,
            cbAikPub,
            &cbAikPub)))
        {
            goto Cleanup;
        }
    }


    //  Nonce
    if (wcslen(nonce) > 0)
    {
        if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
            NULL,
            0,
            (PBYTE)nonce,
            (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
            nonceDigest,
            sizeof(nonceDigest),
            &cbNonceDigest)))
        {
            goto Cleanup;
        }
    }
    else
    {
        nonce = NULL;
    }


    // Load the AIKPub
    if (wcslen(aikName) > 0)
    {
        if (FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_RSA_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            0))))
        {
            goto Cleanup;
        }

        if (FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
            hAlg,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &hAik,
            pbAikPub,
            cbAikPub,
            0))))
        {
            goto Cleanup;
        }
    }

    // Validate the Attestation Blob
    if (FAILED(hr = ValidateAppAttestation(
        hAik,
        (nonce) ? nonceDigest : NULL,
        (nonce) ? sizeof(nonceDigest) : 0,
        pbAttestation,
        cbAttestation)))
    {
        goto Cleanup;
    }

    // Output
    wprintf(L"App Attestation Verified - OK.\n");

Cleanup:
    if (hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if (hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    // Uncomment below line to learn more about the error (if too lazy to debug)
    //CallResult((WCHAR*)L"ServerValidateAppAttestation()", hr);
    if (hr != S_OK) {
        wprintf(L"App Attestation Verification Failed due to mismatched PCRs or something else went wrong.\n");
    }
    return hr;
}

