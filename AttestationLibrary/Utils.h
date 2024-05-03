#pragma once

#include "includes.h"


#define EV_PREBOOT_CERT (0x00000000)
#define EV_POST_CODE (0x00000001)
#define EV_UNUSED (0x00000002)
#define EV_NO_ACTION (0x00000003)
#define EV_SEPARATOR (0x00000004)
#define EV_ACTION (0x00000005)
#define EV_EVENT_TAG (0x00000006)
#define EV_S_CRTM_CONTENTS (0x00000007)
#define EV_S_CRTM_VERSION (0x00000008)
#define EV_CPU_MICROCODE (0x00000009)
#define EV_PLATFORM_CONFIG_FLAGS (0x0000000A)
#define EV_TABLE_OF_DEVICES (0x0000000B)
#define EV_COMPACT_HASH (0x0000000C)
#define EV_IPL (0x0000000D)
#define EV_IPL_PARTITION_DATA (0x0000000E)
#define EV_NONHOST_CODE (0x0000000F)
#define EV_NONHOST_CONFIG (0x00000010)
#define EV_NONHOST_INFO (0x00000011)
#define EV_EFI_EVENT_BASE (0x80000000)
#define EV_EFI_VARIABLE_DRIVER_CONFIG (0x80000001)
#define EV_EFI_VARIABLE_BOOT (0x80000002)
#define EV_EFI_BOOT_SERVICES_APPLICATION (0x80000003)
#define EV_EFI_BOOT_SERVICES_DRIVER (0x80000004)
#define EV_EFI_RUNTIME_SERVICES_DRIVER (0x80000005)
#define EV_EFI_GPT_EVENT (0x80000006)
#define EV_EFI_ACTION (0x80000007)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB (0x80000008)
#define EV_EFI_HANDOFF_TABLES (0x80000009)

#define AVAILABLE_PLATFORM_PCRS (24)

typedef struct {
    UINT32 Id;
    const WCHAR* Name;
} EVENT_TYPE_DATA;

void
LevelPrefix(
    UINT32 level
);

void
PrintBufferAsRawBytes(
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    UINT32 cbBuffer);

HRESULT
DisplaySIPAVsmIdkInfo(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
);

HRESULT
DisplaySIPASIPolicy(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
);

HRESULT
DisplaySIPA(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
);

HRESULT
DisplayLog(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
);

HRESULT
DisplayKey(
    _In_ PCWSTR lpKeyName,
    _In_reads_(cbKey) PBYTE pbKey,
    DWORD cbKey,
    UINT32 level
);

HRESULT
DisplayKeyBlob(
    _In_ PCWSTR lpKeyName,
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    DWORD cbKeyBlob,
    UINT32 level
);

HRESULT
DisplayPlatformAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
);

HRESULT
DisplayKeyAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
);

HRESULT
WriteFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
);

HRESULT
AppendFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
);

HRESULT
ReadFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData,
    _Out_ PUINT32 pcbData
);

HRESULT
ReadFile(
    _In_ PCWSTR lpFileName,
    UINT32 offset,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData
);

void
CallResult(
    _In_ WCHAR* func,
    HRESULT hr
);

/*Taken from  - TpmAtt project*/
HRESULT
GenerateQuote20Internal(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT32 hPlatformKeyHandle,
    _In_reads_opt_(cbKeyAuth) PBYTE pbKeyAuth,
    UINT32 cbKeyAuth,
    UINT32 pcrMask,
    UINT16 pcrAlgId,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbQuote, *pcbResult) PBYTE pbQuote,
    UINT32 cbQuote,
    _Out_ PUINT32 pcbResult
);

/*Taken from  - TpmAtt project*/
HRESULT
GetPlatformPcrs20Internal(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT16 pcrAlgId,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
);

/*Taken from  - TpmAtt project*/
/*
Verify 2.0 specific parts of the Quote, like nonce and PCRlist
*/
HRESULT
ValidateQuoteContext20Internal(
    _In_reads_(cbQuote) PBYTE pbQuote,
    UINT32 cbQuote,
    _In_reads_(cbPcrList) PBYTE pbPcrList,
    UINT32 cbPcrList,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    UINT16 pcrAlgId,
    _Out_ PUINT32 pPcrMask
);


