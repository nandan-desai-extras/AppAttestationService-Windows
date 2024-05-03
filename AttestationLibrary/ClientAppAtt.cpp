#include "ClientAppAtt.h"

HRESULT
ClientGetAppAttestation(
    WCHAR* aikName,
    WCHAR* nonce,
    unsigned char** appAttestationBlob,
    unsigned long* appAttestationBlobSize
)
/*++
This function will create an AIK signed platform attestation blob. In this case
the attestation is signed and nonces are supported. This attestation is tamper
proof.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hAik = NULL;
    PCWSTR aikAuthValue = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 result = 0;
    char* app_log_path = GetAppLogPath();

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

    if (wcslen(aikName) > 0)
    {
        // Open AIK
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
            &hProv,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0))))
        {
            goto Cleanup;
        }
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
            hProv,
            &hAik,
            aikName,
            0,
            0))))
        {
            goto Cleanup;
        }
        if ((aikAuthValue != NULL) && (wcslen(aikAuthValue) != 0))
        {
            if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                hAik,
                NCRYPT_PIN_PROPERTY,
                (PBYTE)aikAuthValue,
                (DWORD)((wcslen(aikAuthValue) + 1) * sizeof(WCHAR)),
                0))))
            {
                goto Cleanup;
            }
        }
    }

    if (FAILED(hr = GenerateAppAttestation(
        hAik,
        (0x00000001 << 23), // PCR mask PCR[23]
        (nonce) ? nonceDigest : NULL,
        (nonce) ? sizeof(nonceDigest) : 0,
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
    if (FAILED(hr = GenerateAppAttestation(
        hAik,
        (0x00000001 << 23), // Default PCR mask PCR[0-6, 8-10, 12-15]
        (nonce) ? nonceDigest : NULL,
        (nonce) ? sizeof(nonceDigest) : 0,
        pbAttestation,
        cbAttestation,
        &cbAttestation)))
    {
        goto Cleanup;
    }

    // Copy attestation data to destination pointer
    *appAttestationBlob = (unsigned char*)malloc(cbAttestation);
    if (*appAttestationBlob == NULL) {
        hr = E_OUTOFMEMORY;
        goto Cleanup;
    }
    memcpy(*appAttestationBlob, pbAttestation, cbAttestation);
    *appAttestationBlobSize = cbAttestation;

    // Display logs that were just attested
    DisplayAppTCGEventLogs(app_log_path);
    printf("App Attestation Generated.\n");

Cleanup:
    if (hAik != NULL)
    {
        NCryptFreeObject(hAik);
        hAik = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    free(app_log_path);
    CallResult((WCHAR*)L"GetAppAttestation()", hr);
    return hr;
}