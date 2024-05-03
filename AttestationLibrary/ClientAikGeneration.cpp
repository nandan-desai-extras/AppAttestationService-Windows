#include "includes.h"
#include "Utils.h"

typedef
PCCERT_CONTEXT
(*fnCryptUIDlgSelectCertificateFromStore)
(
    IN HCERTSTORE hCertStore,
    IN OPTIONAL HWND hwnd,              // Defaults to the desktop window      
    IN OPTIONAL LPCWSTR pwszTitle,
    IN OPTIONAL LPCWSTR pwszDisplayString,
    IN DWORD dwDontUseColumn,
    IN DWORD dwFlags,
    IN void* pvReserved
    );

typedef
BOOL
(*fnCryptUIDlgViewContext)
(
    IN          DWORD dwContextType,
    IN          const void* pvContext,
    IN OPTIONAL HWND hwnd,              // Defaults to the desktop window      
    IN OPTIONAL LPCWSTR pwszTitle,      // Defaults to the context type title      
    IN          DWORD dwFlags,
    IN          void* pvReserved
    );

HRESULT
CryptUIDlgViewContextWrapper(
    PCCERT_CONTEXT* pcCertContext
)
{
    HRESULT hr = S_FALSE;
    HMODULE hModule = NULL;
    fnCryptUIDlgViewContext fpCUIDVC = NULL;

    hModule = LoadLibraryExW(L"cryptui.dll", NULL, 0);

    if (hModule == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    fpCUIDVC = (fnCryptUIDlgViewContext)GetProcAddress(hModule, "CryptUIDlgViewContext");

    if (fpCUIDVC == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if (!fpCUIDVC(
        CERT_STORE_CERTIFICATE_CONTEXT,
        pcCertContext,
        NULL,
        NULL,
        0,
        NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

Cleanup:

    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = NULL;
    }
    return hr;
}

HRESULT
CryptUIDlgSelectCertificateFromStoreWrapper(
    PCCERT_CONTEXT* pcCertContext,
    HCERTSTORE* hStore
)
{
    HRESULT hr = S_OK;
    HMODULE hModule = NULL;
    fnCryptUIDlgSelectCertificateFromStore fpCUIDSCFS = NULL;

    hModule = LoadLibraryExW(L"cryptui.dll", NULL, 0);

    if (hModule == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    fpCUIDSCFS = (fnCryptUIDlgSelectCertificateFromStore)GetProcAddress(hModule, "CryptUIDlgSelectCertificateFromStore");

    if (fpCUIDSCFS == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if ((*pcCertContext = fpCUIDSCFS(
        hStore,
        NULL,
        NULL,
        NULL,
        0,
        0,
        NULL)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

Cleanup:

    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = NULL;
    }
    return hr;
}

HRESULT
GetEKCert(
    unsigned char** rpc_buffer,
    unsigned long* rpc_buffer_size
)
/*++
Retrieve the EKCert from the TPM EKStore. The cert is provided in
a certificate store. In the future there may be several certificates for the
platforms EKs in the returned store.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    HCERTSTORE hStore = NULL;
    DWORD cbhStore = 0;
    PCCERT_CONTEXT pcCertContext = NULL;
    UINT32 certCount = 0;
    BOOL fSilent = TRUE;

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hProv,
        NCRYPT_PCP_EKCERT_PROPERTY,
        (PBYTE)&hStore,
        sizeof(hStore),
        &cbhStore,
        0))))
    {
        goto Cleanup;
    }

    // Count the EK certs in the returned store
    while ((pcCertContext = CertEnumCertificatesInStore(
        hStore,
        pcCertContext)) != NULL)
    {
        certCount++;
    }

    if (certCount == 0)
    {
        wprintf(L"No EK Certificates found.\n");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }
    else if (fSilent)
    {
        // Pick the first cert
        if ((pcCertContext = CertEnumCertificatesInStore(hStore, NULL)) == NULL)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }
    else if (certCount == 1)
    {
        // Pick the first and only cert
        if ((pcCertContext = CertEnumCertificatesInStore(hStore, NULL)) == NULL)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        // Show the cert
        if (FAILED(hr = CryptUIDlgViewContextWrapper(&pcCertContext)))
        {
            goto Cleanup;
        }
    }
    else
    {
        // Have the user select one
        if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pcCertContext, &hStore)))
        {
            goto Cleanup;
        }
    }

    /*if (fileName != NULL)
    {
        if (FAILED(hr = WriteFile(
            fileName,
            pcCertContext->pbCertEncoded,
            pcCertContext->cbCertEncoded)))
        {
            goto Cleanup;
        }
    }*/
    if (FAILED(hr = RPCWriteData(
        rpc_buffer,
        rpc_buffer_size,
        pcCertContext->pbCertEncoded,
        pcCertContext->cbCertEncoded)))
    {
        goto Cleanup;
    }
    wprintf(L"OK.\n");

Cleanup:
    if (pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if (hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    CallResult((WCHAR*)L"GetEKCert()", hr);
    return hr;
}

/* THE BELOW FUNCTION IS OPTIONAL */
HRESULT
GetEK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
)
/*++
Retrieve the EKPub from the TPM through the PCP. The key is provided as a
BCRYPT_RSAKEY_BLOB structure.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BYTE pbEkPub[1024] = { 0 };
    DWORD cbEkPub = 0;

    if (argc > 2)
    {
        fileName = argv[2];
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
        NCRYPT_PCP_EKPUB_PROPERTY,
        pbEkPub,
        sizeof(pbEkPub),
        &cbEkPub,
        0))))
    {
        goto Cleanup;
    }

    if ((fileName != NULL) &&
        (FAILED(hr = WriteFile(fileName, pbEkPub, cbEkPub))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = DisplayKey(L"EndorsementKey", pbEkPub, cbEkPub, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    CallResult((WCHAR*) L"GetEK()", hr);
    return hr;
}


HRESULT
CreateAIK(
    const WCHAR* keyName,
    const WCHAR* nonce,
    unsigned char** idBinding,
    unsigned long* idBindingSize
)
/*++
This function will create an AIK. The AIK is completely usable after creation.
If strong remote trust has to be established in that key for platform or key
attestation for example, the AIK handshake has to be used.

This is the second step in the AIK handshake: Step one is a nonce that is
randomly generated by the validator of the AIK. In this step the client creates
the key and Identity Binding, that is the proof of possession.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwKeyUsage = NCRYPT_PCP_IDENTITY_KEY;
    BYTE pbIdBinding[1024] = { 0 };
    DWORD cbIdBinding = 0;
    BYTE pbAikPub[1024] = { 0 };
    DWORD cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 result = 0;
    BOOLEAN tUIRequested = false;
    LPCWSTR optionalPIN = L"This AIK requires usage consent and an optional PIN.";
    LPCWSTR mandatoryPIN = L"This AIK has a mandatory a PIN.";
    NCRYPT_UI_POLICY rgbUiPolicy = { 1, 0, L"", NULL, NULL };


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

    // Create the AIK
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptCreatePersistedKey(
        hProv,
        &hKey,
        BCRYPT_RSA_ALGORITHM,
        keyName,
        0,
        NCRYPT_OVERWRITE_KEY_FLAG))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
        hKey,
        NCRYPT_UI_POLICY_PROPERTY,
        (PBYTE)&rgbUiPolicy,
        sizeof(NCRYPT_UI_POLICY),
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
        hKey,
        NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
        (PBYTE)&dwKeyUsage,
        sizeof(dwKeyUsage),
        0))))
    {
        goto Cleanup;
    }

    if (nonce != NULL)
    {
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(hKey,
            NCRYPT_PCP_TPM12_IDBINDING_PROPERTY,
            nonceDigest,
            sizeof(nonceDigest),
            0))))
        {
            goto Cleanup;
        }
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptFinalizeKey(hKey, 0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        pbAikPub,
        sizeof(pbAikPub),
        &cbAikPub,
        0))))
    {
        goto Cleanup;
    }

    // Store the IdBinding
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hKey,
        NCRYPT_PCP_TPM12_IDBINDING_PROPERTY,
        pbIdBinding,
        sizeof(pbIdBinding),
        &cbIdBinding,
        0))))
    {
        goto Cleanup;
    }
    
    if (FAILED(hr = RPCWriteData(
        idBinding,
        idBindingSize,
        pbIdBinding,
        cbIdBinding)))
    {
        goto Cleanup;
    }

    // Output results
    wprintf(L"<AIK>\n");
    if (FAILED(hr = DisplayKey(keyName, pbAikPub, cbAikPub, 1)))
    {
        goto Cleanup;
    }
    LevelPrefix(1);
    wprintf(L"<IdentityBinding size=\"%u\">", cbIdBinding);
    for (UINT32 n = 0; n < cbIdBinding; n++)
    {
        wprintf(L"%02x", pbIdBinding[n]);
    }
    wprintf(L"</IdentityBinding>\n");
    wprintf(L"</AIK>\n");

Cleanup:
    if (hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    CallResult((WCHAR*)L"CreateAIK()", hr);
    return hr;
}


HRESULT
ActivateAIK(
    const WCHAR* keyName,
    unsigned char* serverActivationBlob,
    unsigned long serverActivationBlobSize,
    unsigned long* serverSecretSize,
    unsigned char** serverSecret
)
/*++
This function is the last step in what is known as the AIK handshake. The client
will load the AIK into the TPM and perform the activation to retrieve the secret
challenge. If the specified EK and AIK reside in the same TPM, it will release
the secret. The secret may be a nonce or a symmetric key that protects other
data that may be release if the handshake was successful.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbActivationBlob = serverActivationBlob;
    UINT32 cbActivationBlob = serverActivationBlobSize;
    BYTE pbSecret[256] = { 0 };
    DWORD cbSecret = 0;

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
        &hKey,
        keyName,
        0,
        0))))
    {
        goto Cleanup;
    }

    // Perform the activation
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
        hKey,
        NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
        pbActivationBlob,
        cbActivationBlob,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hKey,
        NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
        pbSecret,
        sizeof(pbSecret),
        &cbSecret,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = RPCWriteData(
        serverSecret,
        serverSecretSize,
        pbSecret,
        cbSecret)))
    {
        goto Cleanup;
    }

    // Output results
    wprintf(L"<Activation>\n");
    LevelPrefix(1);
    wprintf(L"<Secret size=\"%u\">%s</Secret>\n", cbSecret, (PWCHAR)pbSecret);
    wprintf(L"</Activation>\n");


Cleanup:
    if (hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    CallResult((WCHAR*)L"ActivateAIK()", hr);
    return hr;
}


HRESULT
GetPubKey(
    const WCHAR* keyName,
    const WCHAR* keyFile
)
/*++
Export the public portion from a user key in the PCP storage as
BCRYPT_RSAKEY_BLOB structure.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    BYTE pbPubKey[1024] = { 0 };
    DWORD cbPubKey = 0;

    // Open key
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
        hProv,
        &hKey,
        keyName,
        0,
        0))))
    {
        goto Cleanup;
    }

    // Export public key
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        pbPubKey,
        sizeof(pbPubKey),
        &cbPubKey,
        0))))
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
    if (FAILED(hr = DisplayKey(keyName, pbPubKey, cbPubKey, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if (hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    CallResult((WCHAR*)L"GetPubKey()", hr);
    return hr;
}


HRESULT
RegisterAIK(
    const WCHAR* keyName 
)
/*++
This function will register an AIK in the registry. Every time the machine
boots or resumes from hibernation, it will generate a Quote in the log and make
it permanently trustworthy. There may be multiple keys registered at the same
time and the system will make a Quote with each key. However this may lead
system boot time degradation. An average 1.2 TPM for example requires around
500ms to create a quote in the log.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbAik = NULL;
    UINT32 cbAik = 0;
    HKEY hRegKey = NULL;

    // Export AIK pub
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
        hProv,
        &hKey,
        keyName,
        0,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        NULL,
        0,
        (PDWORD)&cbAik,
        0))))
    {
        goto Cleanup;
    }
    if (FAILED(hr = AllocateAndZero((PVOID*)&pbAik, cbAik)))
    {
        goto Cleanup;
    }
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        pbAik,
        cbAik,
        (PDWORD)&cbAik,
        0))))
    {
        goto Cleanup;
    }

    // Register AIK for trust point generation
    if (FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
        HKEY_LOCAL_MACHINE,
        TPM_STATIC_CONFIG_QUOTE_KEYS,
        &hRegKey))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(RegSetValueExW(
        hRegKey,
        keyName,
        NULL,
        REG_BINARY,
        pbAik,
        cbAik))))
    {
        goto Cleanup;
    }

    RegCloseKey(hRegKey);
    hRegKey = NULL;

    // Register AIK for key attestation generation
    if (FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
        HKEY_LOCAL_MACHINE,
        TPM_STATIC_CONFIG_KEYATTEST_KEYS,
        &hRegKey))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(RegSetValueExW(
        hRegKey,
        keyName,
        NULL,
        REG_BINARY,
        pbAik,
        cbAik))))
    {
        goto Cleanup;
    }

    // Output results
    wprintf(L"Key '%s' registered. OK!\n", keyName);

Cleanup:
    if (hRegKey != NULL)
    {
        RegCloseKey(hRegKey);
        hRegKey = NULL;
    }
    if (hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbAik, cbAik);
    CallResult((WCHAR*)L"RegisterAIK()", hr);
    return hr;
}

HRESULT EnumerateAIK()
/*++
This function show all currently registered AIKs in the registry. Every time the
machine boots or resumes from hibernation, it will generate a Quote in the log
and make it permanently trustworthy. There may be multiple keys registered at
the same time and the system will make a Quote with each key. However this may
lead to system boot time degradation. An average 1.2 TPM for example requires
around 500ms to create a quote in the log.
--*/
{
    HRESULT hr = S_OK;
    WCHAR keyName[256] = L"";
    DWORD cchKeyName = sizeof(keyName) / sizeof(WCHAR);
    DWORD valueType = 0;
    BYTE pbAikPub[1024] = { 0 };
    DWORD cbAikPub = sizeof(pbAikPub);
    HKEY hRegKey = NULL;

    if (FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
        HKEY_LOCAL_MACHINE,
        TPM_STATIC_CONFIG_QUOTE_KEYS,
        &hRegKey))))
    {
        goto Cleanup;
    }

    wprintf(L"<RegisteredAIK>\n");
    LevelPrefix(1);
    wprintf(L"<PlatformAttestationKeys>\n");
    for (DWORD index = 0; SUCCEEDED(hr); index++)
    {
        cbAikPub = sizeof(pbAikPub);
        cchKeyName = sizeof(keyName) / sizeof(WCHAR);
        hr = HRESULT_FROM_WIN32(RegEnumValueW(
            hRegKey,
            index,
            (LPWSTR)keyName,
            &cchKeyName,
            NULL,
            &valueType,
            pbAikPub,
            &cbAikPub));
        if (FAILED(hr))
        {
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                hr = S_OK;
                break;
            }
            else if (hr != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                goto Cleanup;
            }
        }
        if (valueType == REG_BINARY)
        {
            LevelPrefix(2);
            wprintf(L"<QuoteKey name=\"%s\" size=\"%u\">", keyName, cbAikPub);
            for (UINT32 n = 0; n < cbAikPub; n++)
            {
                wprintf(L"%02x", pbAikPub[n]);
            }
            wprintf(L"</QuoteKey>\n");
        }
    }
    LevelPrefix(1);
    wprintf(L"</PlatformAttestationKeys>\n");
    RegCloseKey(hRegKey);
    hRegKey = NULL;


    if (FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
        HKEY_LOCAL_MACHINE,
        TPM_STATIC_CONFIG_KEYATTEST_KEYS,
        &hRegKey))))
    {
        goto Cleanup;
    }
    LevelPrefix(1);
    wprintf(L"<KeyAttestationKeys>\n");
    for (DWORD index = 0; SUCCEEDED(hr); index++)
    {
        cbAikPub = sizeof(pbAikPub);
        cchKeyName = sizeof(keyName) / sizeof(WCHAR);
        hr = HRESULT_FROM_WIN32(RegEnumValueW(
            hRegKey,
            index,
            (LPWSTR)keyName,
            &cchKeyName,
            NULL,
            &valueType,
            pbAikPub,
            &cbAikPub));
        if (FAILED(hr))
        {
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                hr = S_OK;
                break;
            }
            else if (hr != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                goto Cleanup;
            }
        }
        if (valueType == REG_BINARY)
        {
            LevelPrefix(2);
            wprintf(L"<QuoteKey name=\"%s\" size=\"%u\">", keyName, cbAikPub);
            for (UINT32 n = 0; n < cbAikPub; n++)
            {
                wprintf(L"%02x", pbAikPub[n]);
            }
            wprintf(L"</QuoteKey>\n");
        }
    }
    LevelPrefix(1);
    wprintf(L"</KeyAttestationKeys>\n");
    wprintf(L"</RegisteredAIK>\n");

Cleanup:
    if (hRegKey != NULL)
    {
        RegCloseKey(hRegKey);
        hRegKey = NULL;
    }
    CallResult((WCHAR*)L"EnumerateAIK()", hr);
    return hr;
}