/*

Plan: 
On the client:
At the very first time, read and store the PCR value to our log file.
Whenever there is an event, do the following:
- Create a SHA1 or SHA268 hash of the Event (this hash is referred to as an 'Integrity Measurement' (IM), or 'digest').
- Extend this IM into any PCR.
- Store the actual Event data and the resulting PCR value to the log file.

- When the server requests the attestation of application logs, issue a TPM Quote on the PCR. The TPM is going to sign the PCR value with its EK.
- Send the quote to the server.

On the server:

- Receive the latest PCR value, the "Quote", and the log file.
- Verify the Quote
- Verify whether the logs in the log file result in the final PCR or not.


Use 'TCG_PCClientPCREventStruct' struct to represent the logs. Its defined in wbcl.h and being used in Utils.cpp (in DisplayLogs func).


*/
#include "AppAttestationApi.h"


// Byte array taken from:
// https://github.com/Infineon/eltt2/blob/master/eltt2.c
static const uint8_t tpm2_pcr_extend[] = {
    0x80, 0x02,			// TPM_ST_SESSIONS
    0x00, 0x00, 0x00, 0x00,		// commandSize (will be set later)
    0x00, 0x00, 0x01, 0x82,		// TPM_CC_PCR_Extend
    0x00, 0x00, 0x00, 0x00,		// {PCR_FIRST:PCR_LAST} (TPMI_DH_PCR)
    0x00, 0x00,			// authSize (NULL Password)
    // null (indicate a NULL Password)
    0x00, 0x09,			// authSize (password authorization session)
    0x40, 0x00, 0x00, 0x09,		// TPM_RS_PW (indicate a password authorization session)
    0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,		// count (TPML_DIGEST_VALUES)
    0x00, 0x00			// hashAlg (TPMT_HA; will be set later)
    // digest (TPMT_HA; will be added later)
};

static const uint8_t sha1_alg[] = {
    0x00, 0x04			// command for sha1 alg
};

HRESULT SHA1PCRExtend(UINT8 pcrIndex, BYTE digest[WBCL_HASH_LEN_SHA1]) {
    TBS_HCONTEXT hContext;
    TBS_CONTEXT_PARAMS2 contextParams;
    BYTE result[4096];
    UINT32 resultLen = sizeof(result);
    TBS_RESULT tbsResult;
    uint8_t cmdBuf[sizeof(tpm2_pcr_extend) + WBCL_HASH_LEN_SHA1];

    // Copy basic command bytes.
    memcpy(cmdBuf, tpm2_pcr_extend, sizeof(tpm2_pcr_extend));

    // Store PCR index at the correct byte index in the command byte stream.
    cmdBuf[13] = pcrIndex;

    // Copy the digest
    memcpy(cmdBuf + sizeof(tpm2_pcr_extend), digest, WBCL_HASH_LEN_SHA1);

    // Size of the entire cmd buffer
    cmdBuf[5] = sizeof(tpm2_pcr_extend) + WBCL_HASH_LEN_SHA1;

    // Specify the algorithm type
    memcpy(cmdBuf + 31, sha1_alg, sizeof(sha1_alg));

    // Initialize the context parameters
    ZeroMemory(&contextParams, sizeof(contextParams));
    contextParams.version = TBS_CONTEXT_VERSION_TWO;
    contextParams.includeTpm12 = 0;
    contextParams.includeTpm20 = 1;

    // Create a TBS context
    tbsResult = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&contextParams, &hContext);
    if (tbsResult != TBS_SUCCESS) {
        printf("Tbsi_Context_Create failed with error: 0x%x\n", tbsResult);
        return E_UNEXPECTED;
    }

    // Send the TPM command
    tbsResult = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmdBuf, sizeof(cmdBuf), result, &resultLen);
    if (tbsResult != TBS_SUCCESS) {
        printf("Tbsip_Submit_Command failed with error: 0x%x\n", tbsResult);
        Tbsip_Context_Close(hContext);
        return E_UNEXPECTED;
    }

    // Close the TBS context
    Tbsip_Context_Close(hContext);

    return S_OK;
}


HRESULT GetSHA1Digest(
    uint8_t digest[WBCL_HASH_LEN_SHA1],
    uint8_t* eventData,
    uint32_t eventDataSize)
{
    uint32_t result = 0;
    HRESULT hr = S_OK;
    if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
        NULL,
        0,
        eventData,
        eventDataSize,
        digest,
        WBCL_HASH_LEN_SHA1,
        &result)))
    {
        fprintf(stderr, "Failed to get a digest for event data\n");
    }
    CallResult((WCHAR*)L"GetEventDigest()", hr);
    return hr;
}

char* GetAppLogPath() {
    char* filename = (char*)malloc(256);
    if (filename == NULL) {
        printf("Failed to allocate the memory.\n");
        free(filename);
        exit(1);
    }
    memset(filename, 0x0, 256);
    char* app_log_dir = APP_LOG_DIR;
    if (app_log_dir != NULL) {
        memcpy(filename, app_log_dir, strlen(app_log_dir));
        // Check if the path ends with a backslash
        if (filename[strlen(filename) - 1] != '\\') {
            strcat(filename, "\\"); // Append a backslash if necessary
        }
        strcat(filename, APP_LOG_FILE_NAME);
    }
    else {
        printf("Failed to retrieve the home folder path.\n");
        free(filename);
        exit(1);
    }
    return filename;
}

/*
Use the below function like this:
    uint8_t* bytes;
    size_t cbytes;
    ReadAppTCGEventLogFile("output.log", &bytes, &cbytes);

    // Cast the memory block to the log header
    WBCL_LogHdr* logHeader = (WBCL_LogHdr*)bytes;

    // Move the pointer to the position after the log header
    uint8_t* currentPos = bytes + sizeof(WBCL_LogHdr);

    // Access each log entry
    for (uint32_t i = 0; i < logHeader->entries; i++) {
        TCG_PCClientPCREventStruct* entry = (TCG_PCClientPCREventStruct*)currentPos;
    }

    // Don't forget to free the memory
    ZeroAndFree((PVOID*)&bytes, cbytes);
*/
HRESULT ReadAppTCGEventLogFile(const char* filename, uint8_t** bytes, UINT32* logSize) {
    HRESULT hr = S_OK;
    // Read the existing log file into memory
    HANDLE readFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (readFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening file for reading\n");
        hr = E_HANDLE;
        goto CleanUp;
    }

    // File exists, read the existing log file into memory
    // Determine the file size
    LARGE_INTEGER fileSize;
    GetFileSizeEx(readFile, &fileSize);

    if (fileSize.QuadPart <= 0) {
        fprintf(stderr, "Log file exists but no contents available\n");
        CloseHandle(readFile);
        hr = E_UNEXPECTED;
        goto CleanUp;
    }

    // Allocate memory for the entire file
    if (FAILED(hr = AllocateAndZero((PVOID*)bytes, fileSize.QuadPart)))
    {
        fprintf(stderr, "Error allocating memory\n");
        CloseHandle(readFile);
        hr = E_OUTOFMEMORY;
        goto CleanUp;
    }

    // Read the file into memory
    DWORD bytesRead;
    if (!ReadFile(readFile, *bytes, (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
        fprintf(stderr, "Error reading file: %lu\n", GetLastError());
        // Handle the error as needed
        CloseHandle(readFile);
        free(*bytes);
        hr = E_HANDLE;
        goto CleanUp;
    }
    CloseHandle(readFile);
    *logSize = fileSize.QuadPart;
CleanUp:
    CallResult((WCHAR*)L"ReadAppTCGEventLogFile()", hr);
    return hr;
}

void FillTCGPCClientPCREventStruct_Internal(PTCG_PCClientPCREventStruct eventStruct,
    uint32_t pcrIndex,
    uint32_t eventType,
    uint8_t* digest,
    uint32_t eventDataSize,
    uint8_t* eventData)
{
    eventStruct->pcrIndex = pcrIndex;
    eventStruct->eventType = eventType;
    memcpy(eventStruct->digest, digest, sizeof(eventStruct->digest));
    eventStruct->eventDataSize = eventDataSize;
    memcpy(eventStruct->event, eventData, eventDataSize);
}

HRESULT AppendAppTCGEventLog(const char* filename,
    uint32_t pcrIndex,
    uint32_t eventType,
    uint8_t digest[WBCL_HASH_LEN_SHA1],
    uint8_t eventData[],
    uint32_t eventDataSize)
{
    HRESULT hr = S_OK;
    // Try to read the existing log file into memory
    HANDLE readFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (readFile == INVALID_HANDLE_VALUE) {
        // File doesn't exist, create a new file with the first log entry

        // Number of entries in the log
        uint32_t numEntries = 1;

        // Calculate the required size for the entire structure with variable-sized array
        size_t structSize = sizeof(TCG_PCClientPCREventStruct) + eventDataSize - 1;

        // Calculate the size of the log header
        size_t logHeaderSize = sizeof(WBCL_LogHdr);

        // Calculate the total size for the log file
        size_t totalSize = logHeaderSize + numEntries * structSize;

        // Allocate memory for the entire log
        uint8_t* logData = (uint8_t*)malloc(totalSize);
        if (logData == NULL) {
            fprintf(stderr, "Error allocating memory\n");
            hr = E_OUTOFMEMORY;
            goto CleanUp;
        }

        // Fill the log header
        WBCL_LogHdr* logHeader = (WBCL_LogHdr*)logData;
        logHeader->signature = 0x12345678; // TODO: Change this?
        logHeader->version = 1;
        logHeader->entries = numEntries;
        logHeader->length = (UINT32)totalSize;

        // Move the pointer to the position after the log header
        uint8_t* currentPos = logData + logHeaderSize;

        // Fill the first log entry
        TCG_PCClientPCREventStruct* firstEntry = (TCG_PCClientPCREventStruct*)currentPos;
        FillTCGPCClientPCREventStruct_Internal(firstEntry, pcrIndex, eventType, digest, eventDataSize, eventData);

        // Open the file for writing
        HANDLE writeFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (writeFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Error opening file for writing\n");
            free(logData);
            hr = E_HANDLE;
            goto CleanUp;
        }

        // Write the entire log to the file
        DWORD bytesWritten;
        if (!WriteFile(writeFile, logData, (DWORD)totalSize, &bytesWritten, NULL)) {
            fprintf(stderr, "Error writing to file: %lu\n", GetLastError());
            // Handle the error as needed
            CloseHandle(writeFile);
            free(logData);
            hr = E_HANDLE;
            goto CleanUp;
        }

        // Close the write file
        CloseHandle(writeFile);

        // Free allocated memory
        free(logData);
    }
    else {
        // File exists, read the existing log file into memory
        // Determine the file size
        LARGE_INTEGER fileSize;
        GetFileSizeEx(readFile, &fileSize);

        if (fileSize.QuadPart <= 0) {
            fprintf(stderr, "Log file exists but no contents available\n");
            CloseHandle(readFile);
            hr = E_UNEXPECTED;
            goto CleanUp;
        }

        // Allocate memory for the entire file
        uint8_t* fileData = (uint8_t*)malloc((size_t)fileSize.QuadPart);
        if (fileData == NULL) {
            fprintf(stderr, "Error allocating memory\n");
            CloseHandle(readFile);
            hr = E_OUTOFMEMORY;
            goto CleanUp;
        }

        // Read the file into memory
        DWORD bytesRead;
        if (!ReadFile(readFile, fileData, (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
            fprintf(stderr, "Error reading file: %lu\n", GetLastError());
            // Handle the error as needed
            CloseHandle(readFile);
            free(fileData);
            hr = E_HANDLE;
            goto CleanUp;
        }

        // Close the read file
        CloseHandle(readFile);

        // Open the file for writing
        HANDLE writeFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (writeFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Error opening file for writing\n");
            free(fileData);
            hr = E_HANDLE;
            goto CleanUp;
        }

        // Cast the memory block to the log header
        WBCL_LogHdr* logHeader = (WBCL_LogHdr*)fileData;

        // Determine the size of each log entry
        size_t newstructSize = sizeof(TCG_PCClientPCREventStruct) + eventDataSize - 1;

        // Calculate the total size for the log file
        size_t totalSize = logHeader->length + newstructSize;

        // Reallocate memory to accommodate the new entry
        uint8_t* newfileData = (uint8_t*)realloc(fileData, totalSize);
        if (newfileData == NULL) {
            fprintf(stderr, "Error reallocating memory\n");
            CloseHandle(writeFile);
            hr = E_OUTOFMEMORY;
            goto CleanUp;
        }

        // Move the pointer to the position after the existing log entries
        uint8_t* currentPos = newfileData + logHeader->length;

        // Fill the new log entry
        TCG_PCClientPCREventStruct* newEntry = (TCG_PCClientPCREventStruct*)currentPos;
        FillTCGPCClientPCREventStruct_Internal(newEntry, pcrIndex, eventType, digest, eventDataSize, eventData);

        logHeader = (WBCL_LogHdr*)newfileData;

        // Update the log header entries count
        logHeader->entries = logHeader->entries + 1;

        // Update the log header length
        logHeader->length = (UINT32)totalSize;

        // Write the entire log to the file
        DWORD bytesWritten;
        if (!WriteFile(writeFile, newfileData, (DWORD)totalSize, &bytesWritten, NULL)) {
            fprintf(stderr, "Error writing to file: %lu\n", GetLastError());
            // Handle the error as needed
            CloseHandle(writeFile);
            free(newfileData);
            hr = E_HANDLE;
            goto CleanUp;
        }

        // Close the write file
        CloseHandle(writeFile);

        // Free allocated memory
        free(newfileData);
    }

CleanUp:
    CallResult((WCHAR*)L"AppendAppTCGEventLog()", hr);
    return hr;
}

HRESULT
AppAttComputeSoftPCRs(
    PBYTE pbLog, 
    UINT32 cbLog, 
    UINT16 pcrAlgId, 
    PBYTE pbSwPcr,
    UINT32 cbSwPcr,
    UINT32* pcrMaskLog)
{
    HRESULT hr = S_OK;
    // Cast the memory block to the log header
    WBCL_LogHdr* logHeader = (WBCL_LogHdr*)pbLog;

    // Move the pointer to the position after the log header
    uint8_t* currentPos = pbLog + sizeof(WBCL_LogHdr);

    // Below are some sanity checks
    if (pcrAlgId != TPM_API_ALG_ID_SHA1) 
    {
        hr = E_NOTIMPL;
        goto Cleanup;
    }

    if (cbSwPcr != (AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE)) {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if (pcrMaskLog == NULL) 
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // a temp buffer to hold (prev_pcr || event_digest) while calculating new_pcr = SHA1(prev_pcr || event_digest)
    BYTE tempPcrBuf[2 * SHA1_DIGEST_SIZE];

    // Iterate through each log entry
    for (uint32_t i = 0; i < logHeader->entries; i++) 
    {
        TCG_PCClientPCREventStruct* entry = (TCG_PCClientPCREventStruct*)currentPos;
        if ((entry->pcrIndex >= AVAILABLE_PLATFORM_PCRS)) {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        // Calculate new_pcr = SHA1(prev_pcr || event_digest)
        memcpy(tempPcrBuf, (pbSwPcr + (SHA1_DIGEST_SIZE * entry->pcrIndex)), SHA1_DIGEST_SIZE);
        memcpy(tempPcrBuf + SHA1_DIGEST_SIZE, entry->digest, SHA1_DIGEST_SIZE);
        if (FAILED(hr = GetSHA1Digest((pbSwPcr + (SHA1_DIGEST_SIZE * entry->pcrIndex)), tempPcrBuf, sizeof(tempPcrBuf)))) 
        {
            goto Cleanup;
        }
        
        // Mark the Pcr mask to indicate that this pcr was found in the given logs
        *pcrMaskLog |= (0x00000001 << entry->pcrIndex);

        // Determine the size of each log entry
        size_t structSize = sizeof(TCG_PCClientPCREventStruct) + entry->eventDataSize - 1;

        // Move the pointer to the next position for the next entry
        currentPos += structSize;
    }

Cleanup:
    CallResult((WCHAR*)L"AppAttComputeSoftPCRs()", hr);
    return hr;
}

HRESULT
GenerateAppAttestation(
    NCRYPT_KEY_HANDLE hAik,
    UINT32 pcrMask,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0, cbOutput) PUINT32 pcbResult
)
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BOOLEAN tSignedAttestation = FALSE;
    UINT32 tpmVersion = 0;
    TBS_HCONTEXT hPlatformTbsHandle = 0;
    UINT32 hPlatformKeyHandle = 0;
    BYTE tUsageAuthRequired = 0;
    BYTE usageAuth[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 cbRequired = 0;
    UINT32 cbQuote = 0;
    UINT32 cbSignature = 0;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestationBlob = (PPCP_PLATFORM_ATTESTATION_BLOB)pbOutput;
    UINT32 cursor = 0;
    char* app_log_path = GetAppLogPath();

    // Check the parameters
    if (pcbResult == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // Is this a signed attestation?
    if (hAik != NULL)
    {
        tSignedAttestation = TRUE;
    }

    // Get TPM version to select implementation
    if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
    {
        goto Cleanup;
    }

    // Obtain specific key information from the provider
    if (tSignedAttestation != FALSE)
    {
        // Obtain the provider handle from the key so we can get to the TBS handle
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hAik,
            NCRYPT_PROVIDER_HANDLE_PROPERTY,
            (PUCHAR)&hProv,
            sizeof(hProv),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }

        // Obtain the TBS handle that has been used to load the AIK
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hProv,
            NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
            (PUCHAR)&hPlatformTbsHandle,
            sizeof(hPlatformTbsHandle),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }

        // Obtain the virtualized TPM key handle that is used by the provider
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hAik,
            NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
            (PUCHAR)&hPlatformKeyHandle,
            sizeof(hPlatformKeyHandle),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }

        // Obtain the size of the signature from this key
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hAik,
            BCRYPT_SIGNATURE_LENGTH,
            (PUCHAR)&cbSignature,
            sizeof(cbSignature),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }
        // Does the key need authorization?
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hAik,
            NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
            (PUCHAR)&tUsageAuthRequired,
            sizeof(tUsageAuthRequired),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }

        if (tUsageAuthRequired != FALSE)
        {
            // Get the usageAuth from the provider
            if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                hAik,
                NCRYPT_PCP_USAGEAUTH_PROPERTY,
                usageAuth,
                sizeof(usageAuth),
                (PULONG)&cbRequired,
                0))))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        // If we don't have a key we need to open a TBS session to read the PCRs
        TBS_CONTEXT_PARAMS2 contextParams;
        contextParams.version = TBS_CONTEXT_VERSION_TWO;
        contextParams.asUINT32 = 0;
        contextParams.includeTpm12 = 0;
        contextParams.includeTpm20 = 1;
        if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
        {
            goto Cleanup;
        }
    }

    // Get the logs from the filesystem
    if (FAILED(hr = ReadAppTCGEventLogFile(app_log_path, &pbLog, &cbLog))) {
        goto Cleanup;
    }

    // Quote size check for signed attestation
    if (tSignedAttestation == TRUE)
    {
        if (tpmVersion == TPM_VERSION_12)
        {
            hr = E_NOTIMPL;
            goto Cleanup;
        }
        else if (tpmVersion == TPM_VERSION_20)
        {
            if (FAILED(hr = GenerateQuote20Internal(
                hPlatformTbsHandle,
                hPlatformKeyHandle,
                (tUsageAuthRequired) ? usageAuth : NULL,
                (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
                pcrMask,
                WBCL_DIGEST_ALG_ID_SHA_1,
                pbNonce,
                cbNonce,
                NULL,
                0,
                &cbQuote)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_FAIL;
            goto Cleanup;
        }
    }

    // Calculate output buffer
    cbRequired = sizeof(PCP_PLATFORM_ATTESTATION_BLOB2) +
        AVAILABLE_PLATFORM_PCRS * WBCL_HASH_LEN_SHA1 +
        cbQuote - cbSignature +
        cbSignature +
        cbLog;
    if ((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    if (cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Create the output structure
    pAttestationBlob->Magic = PCP_PLATFORM_ATTESTATION_MAGIC;
    pAttestationBlob->Platform = tpmVersion;
    pAttestationBlob->HeaderSize = sizeof(PCP_PLATFORM_ATTESTATION_BLOB);
    pAttestationBlob->cbPcrValues = AVAILABLE_PLATFORM_PCRS * WBCL_HASH_LEN_SHA1;
    pAttestationBlob->cbQuote = cbQuote - cbSignature;
    pAttestationBlob->cbSignature = cbSignature;
    pAttestationBlob->cbLog = cbLog;
    cursor = pAttestationBlob->HeaderSize;

    // Perform platform attestation and obtain the PCRs
    if (tpmVersion == TPM_VERSION_12)
    {
        hr = E_NOTIMPL;
        goto Cleanup;
    }
    else if (tpmVersion == TPM_VERSION_20)
    {
        // Get the PCRs
        if (FAILED(hr = GetPlatformPcrs20Internal(
            hPlatformTbsHandle,
            WBCL_DIGEST_ALG_ID_SHA_1,
            &pbOutput[cursor],
            pAttestationBlob->cbPcrValues,
            &cbRequired)))
        {
            goto Cleanup;
        }
        cursor += cbRequired;

        // Make OACR happy
        if ((cursor + pAttestationBlob->cbQuote + pAttestationBlob->cbSignature) > cbOutput)
        {
            hr = E_FAIL;
            goto Cleanup;
        }

        // Quote for signed attestation
        if (tSignedAttestation != FALSE)
        {
            if (FAILED(hr = GenerateQuote20Internal(
                hPlatformTbsHandle,
                hPlatformKeyHandle,
                (tUsageAuthRequired) ? usageAuth : NULL,
                (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
                pcrMask,
                WBCL_DIGEST_ALG_ID_SHA_1,
                pbNonce,
                cbNonce,
                &pbOutput[cursor],
                pAttestationBlob->cbQuote + pAttestationBlob->cbSignature,
                &cbRequired)))
            {
                goto Cleanup;
            }
            cursor += cbRequired;
        }
    }
    else
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Make OACR happy
    if ((cursor + pAttestationBlob->cbLog) > cbOutput)
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Copy the logs to the output buffer
    memcpy(&pbOutput[cursor], pbLog, cbLog);
    cbRequired = cbLog;
    cursor += cbRequired;

    // Return the final size
    *pcbResult = cursor;

Cleanup:
    // Close the TBS handle if we opened it in here
    if ((tSignedAttestation == FALSE) && (hPlatformTbsHandle != NULL))
    {
        Tbsip_Context_Close(hPlatformTbsHandle);
        hPlatformTbsHandle = NULL;
    }
    ZeroAndFree((PVOID*)&pbLog, cbLog);
    free(app_log_path);
    CallResult((WCHAR*)L"GenerateAppAttestation()", hr);
    return hr;
}


HRESULT
ValidateAppAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation
)
{
    HRESULT hr = S_OK;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)pbAttestation;
    PPCP_PLATFORM_ATTESTATION_BLOB2 pAttestation2 = NULL;
    UINT32 cursor = 0;
    PBYTE pbPcrValues = NULL;
    UINT32 cbPcrValues = 0;
    PBYTE pbQuote = NULL;
    UINT32 cbQuote = 0;
    PBYTE pbSignature = NULL;
    UINT32 cbSignature = 0;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;
    BYTE quoteDigest[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 cbQuoteDigest = 0;
    BCRYPT_PKCS1_PADDING_INFO pPkcs = { BCRYPT_SHA1_ALGORITHM };
    UINT32 pcrMask = 0;
    UINT32 pcrMaskLog = 0;
    UINT16 pcrAlgId = TPM_API_ALG_ID_SHA1;
    UINT32 digestSize = SHA1_DIGEST_SIZE;
    BYTE softwarePCR[AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE] = { 0 };
    TBS_HCONTEXT hPlatformTbsHandle = 0;
    PBYTE zeroInitializedPCR = NULL;
    PBYTE ffInitializedPCR = NULL;

    // Check the parameters
    if ((pbAttestation == NULL) ||
        (cbAttestation < sizeof(PCP_PLATFORM_ATTESTATION_BLOB)) ||
        ((pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC) &&
            (pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC2)) ||
        (cbAttestation != (pAttestation->HeaderSize +
            pAttestation->cbPcrValues +
            pAttestation->cbQuote +
            pAttestation->cbSignature +
            pAttestation->cbLog)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if (pAttestation->Magic == PCP_PLATFORM_ATTESTATION_MAGIC2)
    {
        hr = E_NOTIMPL;
        goto Cleanup;
    }

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize;
    pbPcrValues = &pbAttestation[cursor];
    cbPcrValues = pAttestation->cbPcrValues;
    cursor += pAttestation->cbPcrValues;
    if (pAttestation->cbQuote != 0)
    {
        pbQuote = &pbAttestation[cursor];
        cbQuote = pAttestation->cbQuote;
        cursor += pAttestation->cbQuote;
    }

    if (pAttestation->cbSignature != 0)
    {
        pbSignature = &pbAttestation[cursor];
        cbSignature = pAttestation->cbSignature;
        cursor += pAttestation->cbSignature;
    }
    pbLog = &pbAttestation[cursor];
    cbLog = pAttestation->cbLog;
    cursor += pAttestation->cbLog;

    // Remote attestation?
    if (hAik != NULL)
    {
        // Step 1: Calculate the digest of the quote
        // The use of SHA1 here is determined by the hashing algorithm
        // associated with the AIK key. We currently define the AIK
        // keys to use SHA1 as hashing algorithm.
        // If that behavior changes, this code has to be adapted as well.
        if (FAILED(hr = TpmAttiShaHash(
            BCRYPT_SHA1_ALGORITHM,
            NULL,
            0,
            pbQuote,
            cbQuote,
            quoteDigest,
            sizeof(quoteDigest),
            &cbQuoteDigest)))
        {
            goto Cleanup;
        }

        // Step 2: Verify the signature with the public AIK
        if (FAILED(hr = HRESULT_FROM_NT(BCryptVerifySignature(
            hAik,
            &pPkcs,
            quoteDigest,
            sizeof(quoteDigest),
            pbSignature,
            cbSignature,
            BCRYPT_PAD_PKCS1))))
        {
            goto Cleanup;
        }

        // Step 3: Platform specific verification of nonce and pcrlist and receive the pcrMask in the quote
        if (pAttestation->Platform == TPM_VERSION_12)
        {
            hr = E_NOTIMPL;
            goto Cleanup;
        }
        else if (pAttestation->Platform == TPM_VERSION_20)
        {
            if (FAILED(hr = ValidateQuoteContext20Internal(
                pbQuote,
                cbQuote,
                pbPcrValues,
                cbPcrValues,
                pbNonce,
                cbNonce,
                pcrAlgId,
                &pcrMask)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }

    // Step 4: Calculate log PCRs
    if (FAILED(hr = AppAttComputeSoftPCRs(pbLog, cbLog, pcrAlgId, softwarePCR, sizeof(softwarePCR), &pcrMaskLog)))
    {
        goto Cleanup;
    }

    if (hAik == 0)
    {
        pcrMask = pcrMaskLog;
    }

    // Step 5: Compare the PCRs from the quote with the PCRs from the log
    if (FAILED(hr = AllocateAndZero((PVOID*)&zeroInitializedPCR, digestSize)))
    {
        goto Cleanup;
    }

    if (FAILED(hr = AllocateAndZero((PVOID*)&ffInitializedPCR, digestSize)))
    {
        goto Cleanup;
    }

    memset(ffInitializedPCR, 0xff, digestSize);

    for (UINT32 n = 0; n < AVAILABLE_PLATFORM_PCRS; n++)
    {
        if ((pcrMask & (0x00000001 << n)) == 0)
        {
            // Identify events in the log, not covered by the quote
            if ((memcmp(&softwarePCR[digestSize * n], zeroInitializedPCR, digestSize) != 0) &&
                (memcmp(&softwarePCR[digestSize * n], ffInitializedPCR, digestSize) != 0))
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
        else
        {
            // Check log PCRs with quote PCRs
            if (memcmp(&pbPcrValues[digestSize * n], &softwarePCR[digestSize * n], digestSize) != 0)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
    }

    // Step 6: Optional - Local attestation
    if (hAik == 0)
    {
        BYTE currentPCR[AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = { 0 };
        UINT32 cbCurrentPCR = sizeof(currentPCR);
        UINT32 tpmVersion = 0;
        TBS_CONTEXT_PARAMS2 contextParams;
        contextParams.version = TBS_CONTEXT_VERSION_TWO;
        contextParams.asUINT32 = 0;
        contextParams.includeTpm12 = 1;
        contextParams.includeTpm20 = 1;

        // Get TPM version to select implementation
        if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
        {
            goto Cleanup;
        }

        // Open a TBS session to read the PCRs
        if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
        {
            goto Cleanup;
        }

        if (tpmVersion == TPM_VERSION_12)
        {
            hr = E_NOTIMPL;
            goto Cleanup;
        }
        else if (tpmVersion == TPM_VERSION_20)
        {
            // Get the PCRs
            if (FAILED(hr = GetPlatformPcrs20Internal(
                hPlatformTbsHandle,
                pcrAlgId,
                currentPCR,
                cbCurrentPCR,
                &cbCurrentPCR)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_FAIL;
            goto Cleanup;
        }

        for (UINT32 n = 0; n < AVAILABLE_PLATFORM_PCRS; n++)
        {
            if ((pcrMaskLog & (0x00000001 << n)) != 0)
            {
                // Check PCRs with platform PCRs
                if (memcmp(&pbPcrValues[digestSize * n], &currentPCR[digestSize * n], digestSize) != 0)
                {
                    hr = E_INVALIDARG;
                    goto Cleanup;
                }
            }
        }
    }

    // Congratulations! Everything checks out and the log data may be considered trustworthy

Cleanup:
    // Close the TBS handle if we opened it in here
    if (hPlatformTbsHandle != NULL)
    {
        Tbsip_Context_Close(hPlatformTbsHandle);
        hPlatformTbsHandle = NULL;
    }

    ZeroAndFree((PVOID*)&zeroInitializedPCR, digestSize);
    ZeroAndFree((PVOID*)&ffInitializedPCR, digestSize);
    // Uncomment below line to learn more about the error (if too lazy to debug)
    //CallResult((WCHAR*)L"ValidateAppAttestation()", hr);
    return hr;
}

void DisplayAppTCGEventLogs(const char* filename)
{
    uint8_t* fileData;
    uint32_t fileSize;

    if (FAILED(ReadAppTCGEventLogFile(filename, &fileData, &fileSize))) {
        fprintf(stderr, "Error reading the log file\n");
        return;
    }

    // Cast the memory block to the log header
    WBCL_LogHdr* logHeader = (WBCL_LogHdr*)fileData;

    // Move the pointer to the position after the log header
    uint8_t* currentPos = fileData + sizeof(WBCL_LogHdr);

    // Print each log entry
    for (uint32_t i = 0; i < logHeader->entries; i++) {
        TCG_PCClientPCREventStruct* entry = (TCG_PCClientPCREventStruct*)currentPos;

        // Print the log entry information
        printf("Log Entry %u:\n", i + 1);
        printf("PCR Index: %u\n", entry->pcrIndex);
        printf("Event Type: %u\n", entry->eventType);
        printf("Digest: ");
        for (size_t j = 0; j < sizeof(entry->digest); ++j) {
            printf("%02x ", entry->digest[j]);
        }
        printf("\n");
        printf("Event Data Size: %u\n", entry->eventDataSize);
        printf("Event Data: ");
        for (size_t j = 0; j < entry->eventDataSize; j++) {
            printf("%02x ", entry->event[j]);
        }
        printf("\n\n");

        // Determine the size of each log entry
        size_t structSize = sizeof(TCG_PCClientPCREventStruct) + entry->eventDataSize - 1;

        // Move the pointer to the next position for the next entry
        currentPos += structSize;
    }

    // Free allocated memory
    free(fileData);
}

