#pragma once
#include "Utils.h"
#include "TpmAtt.h"

#define APP_LOG_DIR getenv("USERPROFILE")
#define APP_LOG_FILE_NAME "app_attestation.log"

HRESULT SHA1PCRExtend(UINT8 pcrIndex, BYTE digest[WBCL_HASH_LEN_SHA1]);

HRESULT GetSHA1Digest(
    uint8_t digest[WBCL_HASH_LEN_SHA1],
    uint8_t* eventData,
    uint32_t eventDataSize);

char* GetAppLogPath();

HRESULT ReadAppTCGEventLogFile(const char* filename, uint8_t** bytes, UINT32* logSize);

HRESULT AppendAppTCGEventLog(const char* filename,
    uint32_t pcrIndex,
    uint32_t eventType,
    uint8_t digest[WBCL_HASH_LEN_SHA1],
    uint8_t eventData[],
    uint32_t eventDataSize);

HRESULT
AppAttComputeSoftPCRs(
    PBYTE pbLog,
    UINT32 cbLog,
    UINT16 pcrAlgId,
    PBYTE pbSwPcr,
    UINT32 cbSwPcr,
    UINT32* pcrMaskLog);

HRESULT
GenerateAppAttestation(
    NCRYPT_KEY_HANDLE hAik,
    UINT32 pcrMask,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0, cbOutput) PUINT32 pcbResult
);

HRESULT
ValidateAppAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation
);

void DisplayAppTCGEventLogs(const char* filename);

