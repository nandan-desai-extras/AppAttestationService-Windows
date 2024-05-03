/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    Support.cpp

Abstract:

    Support functions for  that are not in direct relation for the SDK
    samples for the Platform Crypto Provider.

--*/

#include "includes.h"
#include "Utils.h"

#ifndef SIPAEVENT_MORBIT_NOT_CANCELABLE
#define SIPAEVENT_MORBIT_NOT_CANCELABLE    (SIPAEVENTTYPE_INFORMATION + 0x0008)
#endif // SIPAEVENT_MORBIT_NOT_CANCELABLE

#ifndef SIPAEVENT_APPLICATION_SVN
#define SIPAEVENT_APPLICATION_SVN          (SIPAEVENTTYPE_INFORMATION + 0x0009)
#endif // SIPAEVENT_APPLICATION_SVN

#ifndef SIPAEVENT_SVN_CHAIN_STATUS
#define SIPAEVENT_SVN_CHAIN_STATUS         (SIPAEVENTTYPE_INFORMATION + 0x000a)
#endif // SIPAEVENT_SVN_CHAIN_STATUS

#ifndef SIPAEVENT_BOOT_REVOCATION_LIST
#define SIPAEVENT_BOOT_REVOCATION_LIST     (SIPAEVENTTYPE_PREOSPARAMETER + 0x0002)
#endif // SIPAEVENT_BOOT_REVOCATION_LIST

#ifndef SIPAEVENT_SI_POLICY
#define SIPAEVENT_SI_POLICY                (SIPAEVENTTYPE_OSPARAMETER + 0x000F)
#endif // SIPAEVENT_SI_POLICY

#ifndef SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY
#define SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY (SIPAEVENTTYPE_OSPARAMETER + 0x0010)
#endif // SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY

#ifndef SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY
#define SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY (SIPAEVENTTYPE_OSPARAMETER + 0x0011)
#endif // SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY

#ifndef SIPAEVENT_VSM_LAUNCH_TYPE
#define SIPAEVENT_VSM_LAUNCH_TYPE          (SIPAEVENTTYPE_OSPARAMETER + 0x0012)
#endif // SIPAEVENT_VSM_LAUNCH_TYPE

#ifndef SIPAEVENT_OS_REVOCATION_LIST
#define SIPAEVENT_OS_REVOCATION_LIST       (SIPAEVENTTYPE_OSPARAMETER + 0x0013)
#endif // SIPAEVENT_OS_REVOCATION_LIST

#ifndef SIPAEVENT_VSM_IDK_INFO
#define SIPAEVENT_VSM_IDK_INFO             (SIPAEVENTTYPE_OSPARAMETER + 0x0020)
#endif // SIPAEVENT_VSM_IDK_INFO

#ifndef SIPAEVENT_MODULE_SVN
#define SIPAEVENT_MODULE_SVN               (SIPAEVENTTYPE_LOADEDMODULE + 0x000b)
#endif // SIPAEVENT_MODULE_SVN

#ifndef SIPAEVENTTYPE_VBS
#define SIPAEVENTTYPE_VBS                  (0x000A0000)

#define SIPAEVENT_VBS_VSM_REQUIRED         (SIPAEVENTTYPE_VBS + 0x0001)

#define SIPAEVENT_VBS_SECUREBOOT_REQUIRED  (SIPAEVENTTYPE_VBS + 0x0002)

#define SIPAEVENT_VBS_IOMMU_REQUIRED       (SIPAEVENTTYPE_VBS + 0x0003)

#define SIPAEVENT_VBS_MMIO_NX_REQUIRED     (SIPAEVENTTYPE_VBS + 0x004)

#define SIPAEVENT_VBS_MSR_FILTERING_REQUIRED (SIPAEVENTTYPE_VBS + 0x0005)

#define SIPAEVENT_VBS_MANDATORY_ENFORCEMENT (SIPAEVENTTYPE_VBS + 0x006)

#define SIPAEVENT_VBS_HVCI_POLICY          (SIPAEVENTTYPE_VBS + 0x007)

#define SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED (SIPAEVENTTYPE_VBS + 0x008)

#endif // SIPAEVENTTYPE_VBS

EVENT_TYPE_DATA TcgId[] = {
    {SIPAEV_PREBOOT_CERT, L"EV_Preboot_Cert"},
    {SIPAEV_POST_CODE, L"EV_Post_Code"},
    {SIPAEV_UNUSED, L"EV_Unused"},
    {SIPAEV_NO_ACTION, L"EV_No_Action"},
    {SIPAEV_SEPARATOR, L"EV_Separator"},
    {SIPAEV_ACTION, L"EV_Action"},
    {SIPAEV_EVENT_TAG, L"EV_Event_Tag"},
    {SIPAEV_S_CRTM_CONTENTS, L"EV_CRTM_Contents"},
    {SIPAEV_S_CRTM_VERSION, L"EV_CRTM_Version"},
    {SIPAEV_CPU_MICROCODE, L"EV_CPU_Microcode"},
    {SIPAEV_PLATFORM_CONFIG_FLAGS, L"EV_Platform_Config_Flags"},
    {SIPAEV_TABLE_OF_DEVICES, L"EV_Table_Of_Devices"},
    {SIPAEV_COMPACT_HASH, L"EV_Compact_Hash"},
    {SIPAEV_IPL, L"EV_IPL"},
    {SIPAEV_IPL_PARTITION_DATA, L"EV_IPL_Partition_Data"},
    {SIPAEV_NONHOST_CODE, L"EV_NonHost_Code"},
    {SIPAEV_NONHOST_CONFIG, L"EV_NonHost_Config"},
    {SIPAEV_NONHOST_INFO, L"EV_NonHost_Info"},
    {SIPAEV_EFI_EVENT_BASE, L"EV_EFI_Event_Base"},
    {SIPAEV_EFI_VARIABLE_DRIVER_CONFIG, L"EV_EFI_Variable_Driver_Config"},
    {SIPAEV_EFI_VARIABLE_BOOT, L"EV_EFI_Variable_Boot"},
    {SIPAEV_EFI_BOOT_SERVICES_APPLICATION, L"EV_EFI_Boot_Services_Application"},
    {SIPAEV_EFI_BOOT_SERVICES_DRIVER, L"EV_EFI_Boot_Services_Driver"},
    {SIPAEV_EFI_RUNTIME_SERVICES_DRIVER, L"EV_EFI_Runtime_Services_Driver"},
    {SIPAEV_EFI_GPT_EVENT, L"EV_EFI_GPT_Event"},
    {SIPAEV_EFI_ACTION, L"EV_EFI_Action"},
    {SIPAEV_EFI_PLATFORM_FIRMWARE_BLOB, L"EV_EFI_Platform_Firmware_Blog"},
    {SIPAEV_EFI_HANDOFF_TABLES, L"EV_EFI_Handoff_Tables"},
    {0xFFFFFFFF, L"EV_Unknown"}
};

EVENT_TYPE_DATA SipaId[] = {
    {SIPAEVENT_TRUSTBOUNDARY, L"Trustboundary"},
    {SIPAEVENT_ELAM_AGGREGATION, L"ELAM_Aggregation"},
    {SIPAEVENT_LOADEDMODULE_AGGREGATION, L"LoadedModule_Aggregation"},
    {SIPAEVENT_TRUSTPOINT_AGGREGATION, L"TrustPoint_Aggregation"},
    {SIPAERROR_FIRMWAREFAILURE, L"FirmwareFailure"},
    {SIPAERROR_TPMFAILURE, L"TpmFailure"},
    {SIPAERROR_INTERNALFAILURE, L"InternalFailure"},
    {SIPAEVENT_INFORMATION, L"Information"},
    {SIPAEVENT_BOOTCOUNTER, L"BootCounter"},
    {SIPAEVENT_TRANSFER_CONTROL, L"Transfer_Control"},
    {SIPAEVENT_APPLICATION_RETURN, L"Application_Return"},
    {SIPAEVENT_BITLOCKER_UNLOCK, L"BitLocker_Unlock"},
    {SIPAEVENT_EVENTCOUNTER, L"EventCounter"},
    {SIPAEVENT_COUNTERID, L"CounterId"},
    {SIPAEVENT_MORBIT_NOT_CANCELABLE, L"MorBitNotCancelable"},
    {SIPAEVENT_APPLICATION_SVN, L"ApplicationSvn"},
    {SIPAEVENT_SVN_CHAIN_STATUS, L"SvnChainStatus"},
    {SIPAEVENT_BOOTDEBUGGING, L"BootDebug"},
    {SIPAEVENT_BOOT_REVOCATION_LIST, L"BootRevocationList"},
    {SIPAEVENT_OSKERNELDEBUG, L"OsKernelDebug"},
    {SIPAEVENT_CODEINTEGRITY, L"CodeIntegrity"},
    {SIPAEVENT_TESTSIGNING, L"Testsigning"},
    {SIPAEVENT_DATAEXECUTIONPREVENTION, L"DataExecutionPrevention"},
    {SIPAEVENT_SAFEMODE, L"SafeMode"},
    {SIPAEVENT_WINPE, L"WinPE"},
    {SIPAEVENT_PHYSICALADDRESSEXTENSION, L"PhysicalAddressExtension"},
    {SIPAEVENT_OSDEVICE, L"OsDevice"},
    {SIPAEVENT_SYSTEMROOT, L"SystemRoot"},
    {SIPAEVENT_HYPERVISOR_LAUNCH_TYPE, L"HypervisorLaunchType"},
    {SIPAEVENT_HYPERVISOR_IOMMU_POLICY, L"HypervisorIOMMUPolicy"},
    {SIPAEVENT_HYPERVISOR_DEBUG, L"HypervisorDebug"},
    {SIPAEVENT_DRIVER_LOAD_POLICY, L"DriverLoadPolicy"},
    {SIPAEVENT_SI_POLICY, L"SIPolicy"},
    {SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY, L"HypervisorMmioNxPolicy"},
    {SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY, L"HypervisorMsrFilterPolicy"},
    {SIPAEVENT_VSM_LAUNCH_TYPE, L"VsmLaunchType"},
    {SIPAEVENT_OS_REVOCATION_LIST, L"OsRevocationList"},
    {SIPAEVENT_VSM_IDK_INFO, L"VsmIdkInfo"},
    {SIPAEVENT_NOAUTHORITY, L"NoAuthority"},
    {SIPAEVENT_AUTHORITYPUBKEY, L"AuthorityPubKey"},
    {SIPAEVENT_FILEPATH, L"FilePath"},
    {SIPAEVENT_IMAGESIZE, L"ImageSize"},
    {SIPAEVENT_HASHALGORITHMID, L"HashAlgorithmId"},
    {SIPAEVENT_AUTHENTICODEHASH, L"AuthenticodeHash"},
    {SIPAEVENT_AUTHORITYISSUER, L"AuthorityIssuer"},
    {SIPAEVENT_AUTHORITYSERIAL, L"AuthoritySerial"},
    {SIPAEVENT_IMAGEBASE, L"ImageBase"},
    {SIPAEVENT_AUTHORITYPUBLISHER, L"AuthorityPublisher"},
    {SIPAEVENT_AUTHORITYSHA1THUMBPRINT, L"AuthoritySHA1Thumbprint"},
    {SIPAEVENT_IMAGEVALIDATED, L"ImageValidated"},
    {SIPAEVENT_MODULE_SVN, L"ModuleSvn"},
    {SIPAEVENT_QUOTE, L"Quote"},
    {SIPAEVENT_QUOTESIGNATURE, L"QuoteSignature"},
    {SIPAEVENT_AIKID, L"AikId"},
    {SIPAEVENT_AIKPUBDIGEST, L"AikPubDigest"},
    {SIPAEVENT_ELAM_KEYNAME, L"ELAM_KeyName"},
    {SIPAEVENT_ELAM_CONFIGURATION, L"ELAM_Configuration"},
    {SIPAEVENT_ELAM_POLICY, L"ELAM_Policy"},
    {SIPAEVENT_ELAM_MEASURED, L"ELAM_Measured"},
    {SIPAEVENT_VBS_VSM_REQUIRED, L"VBS_VsmRequired"},
    {SIPAEVENT_VBS_SECUREBOOT_REQUIRED, L"VBS_SecureBootRequired"},
    {SIPAEVENT_VBS_IOMMU_REQUIRED, L"VBS_IommuRequired"},
    {SIPAEVENT_VBS_MMIO_NX_REQUIRED, L"VBS_MmioNxRequired"},
    {SIPAEVENT_VBS_MSR_FILTERING_REQUIRED, L"VBS_MsrFilteringRequired"},
    {SIPAEVENT_VBS_MANDATORY_ENFORCEMENT, L"VBS_MandatoryEnforcement"},
    {SIPAEVENT_VBS_HVCI_POLICY, L"VBS_HvciPolicy"},
    {SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED, L"VBS_MicrosoftBootChainRequired"},
    {0xFFFFFFFF, L"Unknown"}
};

EVENT_TYPE_DATA OsDeviceId[] = {
    {OSDEVICE_TYPE_UNKNOWN, L"UNKNOWN"},
    {OSDEVICE_TYPE_BLOCKIO_HARDDISK, L"BLOCKIO_HARDDISK"},
    {OSDEVICE_TYPE_BLOCKIO_REMOVABLEDISK, L"BLOCKIO_REMOVABLEDISK"},
    {OSDEVICE_TYPE_BLOCKIO_CDROM, L"BLOCKIO_CDROM"},
    {OSDEVICE_TYPE_BLOCKIO_PARTITION, L"BLOCKIO_PARTITION"},
    {OSDEVICE_TYPE_BLOCKIO_FILE, L"BLOCKIO_FILE"},
    {OSDEVICE_TYPE_BLOCKIO_RAMDISK, L"BLOCKIO_RAMDISK"},
    {OSDEVICE_TYPE_BLOCKIO_VIRTUALHARDDISK, L"BLOCKIO_VIRTUALHARDDISK"},
    {OSDEVICE_TYPE_SERIAL, L"SERIAL"},
    {OSDEVICE_TYPE_UDP, L"UDP"},
    {0xFFFFFFFF, L"Unknown"}
};

EVENT_TYPE_DATA TransferControlId[] = {
    {0x00000000, L"NONE"},
    {0x00000001, L"OSLOADER"},
    {0x00000002, L"RESUME"},
    {0x00000003, L"MSUTILITY"},
    {0x00000004, L"NOSIGCHECK"},
    {0x00000005, L"HYPERVISOR"},
    {0xFFFFFFFF, L"Unknown"}
};

void
LevelPrefix(
    UINT32 level
)
{
    for (UINT32 n = 0; n < level; n++)
    {
        wprintf(L"  ");
    }
}

void
PrintBufferAsRawBytes(
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    UINT32 cbBuffer)
    /*
        Prints out the contents of a byte buffer - 2 hex digits per byte: 123456789ABC...
    */
{
    for (unsigned i = 0; i < cbBuffer; i++)
    {
        wprintf(L"%02X", pbBuffer[i]);
    }
}

HRESULT
DisplaySIPASIPolicy(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
)
/*
    Prints out the contents of SIPAEVENT_SI_POLICY_PAYLOAD as the following Xml:

    <Version>1.2.3.4</Version>
    <HashAlgID>1</HashAlgID>
    <Name>FooBarPolicy</Name>
    <Digest Size="32">123456789A...</Digest>
*/
{
    PCWSTR pcwszPolicyVersion = L"Version";
    PCWSTR pcwszHashAlgID = L"HashAlgID";
    PCWSTR pcwszPolicyName = L"Name";
    PCWSTR pcwszDigest = L"Digest";

    PSIPAEVENT_SI_POLICY_PAYLOAD pSIPolicyPayload = (PSIPAEVENT_SI_POLICY_PAYLOAD)pbSipaData;

    if (cbSipaEventData != sizeof(SIPAEVENT_SI_POLICY_PAYLOAD) - 1 +
        pSIPolicyPayload->PolicyNameLength +
        pSIPolicyPayload->DigestLength)
    {
        wprintf(L"Bad format!");
        return E_FAIL;
    }

    wprintf(L"\n");

    //
    // Print the element for Version. 
    // Treat pSIPolicyPayload->PolicyVersion as 4 USHORTs.
    //
    USHORT* pVersionElements = (USHORT*)&(pSIPolicyPayload->PolicyVersion);

    LevelPrefix(level);
    wprintf(L"<%s>%hd.%hd.%hd.%hd</%s>\n",
        pcwszPolicyVersion,
        *(pVersionElements + 3),
        *(pVersionElements + 2),
        *(pVersionElements + 1),
        *(pVersionElements + 0),
        pcwszPolicyVersion);

    // Print the HashAlgID element.
    LevelPrefix(level);
    wprintf(L"<%s>%d</%s>\n",
        pcwszHashAlgID,
        pSIPolicyPayload->HashAlgID,
        pcwszHashAlgID);

    // Print the Name element.
    LevelPrefix(level);
    wprintf(L"<%s>%s</%s>\n",
        pcwszPolicyName,
        (WCHAR*)(pSIPolicyPayload->VarLengthData),
        pcwszPolicyName);

    // Print the Digest element.
    LevelPrefix(level);
    wprintf(L"<%s Size=\"%d\">",
        pcwszDigest,
        pSIPolicyPayload->DigestLength);

    PrintBufferAsRawBytes(pSIPolicyPayload->VarLengthData + pSIPolicyPayload->PolicyNameLength,
        pSIPolicyPayload->DigestLength);

    wprintf(L"</%s>\n", pcwszDigest);

    return S_OK;
}

HRESULT
DisplaySIPAVsmIdkInfo(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
)
/*
    Prints out the contents of SIPAEVENT_VSM_IDK_INFO_PAYLOAD as the following Xml:

    <KeyAlgID>1</KeyAlgID>
    <SIPAEVENT_VSM_IDK_RSA_INFO>
     <KeyBitLength>2048</KeyBitLength>
     <PublicExponent>010001</PublicExponent>
     <Modulus>123456789A...</Modulus>
    <SIPAEVENT_VSM_IDK_RSA_INFO>
*/
{
    PCWSTR pcwszKeyAlgID = L"KeyAlgID";
    PCWSTR pcwszSIPAEVENT_VSM_IDK_RSA_INFO = L"SIPAEVENT_VSM_IDK_RSA_INFO";
    PCWSTR pcwszKeyBitLength = L"KeyBitLength";
    PCWSTR pcwszPublicExponent = L"PublicExponent";
    PCWSTR pcwszModulus = L"Modulus";

    PSIPAEVENT_VSM_IDK_INFO_PAYLOAD pVsmIdkPayload = (PSIPAEVENT_VSM_IDK_INFO_PAYLOAD)pbSipaData;

    if (pVsmIdkPayload->KeyAlgID != 1)
    {
        wprintf(L"Unsupported algorithm ID!");
        return E_FAIL;
    }

    if (cbSipaEventData != sizeof(SIPAEVENT_VSM_IDK_INFO_PAYLOAD) - 1 +
        pVsmIdkPayload->RsaKeyInfo.PublicExpLengthBytes +
        pVsmIdkPayload->RsaKeyInfo.ModulusSizeBytes)
    {
        wprintf(L"Bad format!");
        return E_FAIL;
    }

    if (pVsmIdkPayload->RsaKeyInfo.PublicExpLengthBytes > 4)
    {
        wprintf(L"Unexpected size of public exponent!");
        return E_FAIL;
    }

    wprintf(L"\n");

    // Print the element for KeyAlgID.
    LevelPrefix(level);
    wprintf(L"<%s>%d</%s>\n",
        pcwszKeyAlgID,
        pVsmIdkPayload->KeyAlgID,
        pcwszKeyAlgID);

    // Print the opening <SIPAEVENT_VSM_IDK_RSA_INFO>.
    LevelPrefix(level);
    wprintf(L"<%s>\n", pcwszSIPAEVENT_VSM_IDK_RSA_INFO);

    // Print the KeyBitLength element.
    LevelPrefix(level + 1);
    wprintf(L"<%s>%d</%s>\n",
        pcwszKeyBitLength,
        pVsmIdkPayload->RsaKeyInfo.KeyBitLength,
        pcwszKeyBitLength);

    // Print the PublicExponent element.
    LevelPrefix(level + 1);
    wprintf(L"<%s>", pcwszPublicExponent);
    PrintBufferAsRawBytes(pVsmIdkPayload->RsaKeyInfo.PublicKeyData,
        pVsmIdkPayload->RsaKeyInfo.PublicExpLengthBytes);
    wprintf(L"</%s>\n", pcwszPublicExponent);

    // Print the Modulus element.
    LevelPrefix(level + 1);
    wprintf(L"<%s>", pcwszModulus);
    PrintBufferAsRawBytes(pVsmIdkPayload->RsaKeyInfo.PublicKeyData + pVsmIdkPayload->RsaKeyInfo.PublicExpLengthBytes,
        pVsmIdkPayload->RsaKeyInfo.ModulusSizeBytes);
    wprintf(L"</%s>\n", pcwszModulus);

    // Print the closing </SIPAEVENT_VSM_IDK_RSA_INFO>
    LevelPrefix(level);
    wprintf(L"</%s>\n", pcwszSIPAEVENT_VSM_IDK_RSA_INFO);

    return S_OK;
}

HRESULT
DisplaySIPARevocationList(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
)
/*
    Prints out the contents of SIPAEVENT_REVOCATION_LIST_PAYLOAD as the following Xml:

    <CreationTime>0</CreationTime>
    <HashAlgID>1</HashAlgID>
    <Digest Size="32">123456789A...</Digest>
*/
{
    PCWSTR pcwszCreationTime = L"CreationTime";
    PCWSTR pcwszHashAlgID = L"HashAlgID";
    PCWSTR pcwszDigest = L"Digest";

    PSIPAEVENT_REVOCATION_LIST_PAYLOAD pRevocationPayload = (PSIPAEVENT_REVOCATION_LIST_PAYLOAD)pbSipaData;

    if (cbSipaEventData != sizeof(SIPAEVENT_REVOCATION_LIST_PAYLOAD) - 1 +
        pRevocationPayload->DigestLength)
    {
        wprintf(L"Bad format!");
        return E_FAIL;
    }

    wprintf(L"\n");

    // Print the element for CreationTime.
    LevelPrefix(level);
    wprintf(L"<%s>%I64u</%s>\n",
        pcwszCreationTime,
        pRevocationPayload->CreationTime,
        pcwszCreationTime);

    // Print the HashAlgID element.
    LevelPrefix(level);
    wprintf(L"<%s>%d</%s>\n",
        pcwszHashAlgID,
        pRevocationPayload->HashAlgID,
        pcwszHashAlgID);

    // Print the Digest element.
    LevelPrefix(level);
    wprintf(L"<%s Size=\"%d\">",
        pcwszDigest,
        pRevocationPayload->DigestLength);

    PrintBufferAsRawBytes(pRevocationPayload->Digest,
        pRevocationPayload->DigestLength);

    wprintf(L"</%s>\n", pcwszDigest);

    return S_OK;
}

HRESULT
DisplaySIPA(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
)
{
    HRESULT hr = S_OK;
    PBYTE pbWBCLIntern = pbWBCL;
    UINT32 cbWBCLIntern = cbWBCL;
    UINT32 sipaType = 0;
    UINT32 cbSipaLen = 0;
    PBYTE pbSipaData = NULL;
    PWSTR eventStr = NULL;

    while (cbWBCLIntern > (2 * sizeof(UINT32)))
    {
        PWSTR eventEndStr = (PWSTR) L"SipaEvent";

        sipaType = *((PUINT32)pbWBCLIntern);
        cbSipaLen = *((PUINT32)&pbWBCLIntern[sizeof(UINT32)]);
        if (cbWBCLIntern < (2 * sizeof(UINT32) + cbSipaLen))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        if (cbSipaLen > 0)
        {
            pbSipaData = &pbWBCLIntern[2 * sizeof(UINT32)];
        }
        else
        {
            pbSipaData = NULL;
        }

        for (UINT32 n = 0; SipaId[n].Id != 0xFFFFFFFF; n++)
        {
            if (SipaId[n].Id == sipaType)
            {
                eventStr = (PWCHAR) SipaId[n].Name;
            }
        }

        LevelPrefix(level);
        if (eventStr != NULL)
        {
            wprintf(L"<%s Size=\"%u\"%s>",
                eventStr,
                cbSipaLen,
                (cbSipaLen == 0) ? L"/" : L"");
            eventEndStr = eventStr;
        }
        else
        {
            wprintf(L"<SipaEvent Type=\"0x%08x\" Size=\"%u\"%s>",
                sipaType,
                cbSipaLen,
                (cbSipaLen == 0) ? L"/" : L"");
        }

        if (cbSipaLen > 0)
        {
            if ((sipaType & (SIPAEVENTTYPE_AGGREGATION |
                SIPAEVENTTYPE_CONTAINER)) == (SIPAEVENTTYPE_AGGREGATION |
                    SIPAEVENTTYPE_CONTAINER))
            {
                wprintf(L"\n");
                if (FAILED(hr = DisplaySIPA(pbSipaData,
                    cbSipaLen,
                    level + 1)))
                {
                    goto Cleanup;
                }
                LevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
            else if ((cbSipaLen == sizeof(BYTE)) &
                ((sipaType == SIPAEVENT_BOOTDEBUGGING) ||
                    (sipaType == SIPAEVENT_OSKERNELDEBUG) ||
                    (sipaType == SIPAEVENT_CODEINTEGRITY) ||
                    (sipaType == SIPAEVENT_TESTSIGNING) ||
                    (sipaType == SIPAEVENT_WINPE) ||
                    (sipaType == SIPAEVENT_SAFEMODE) ||
                    (sipaType == SIPAEVENT_IMAGEVALIDATED) ||
                    (sipaType == SIPAEVENT_VBS_VSM_REQUIRED) ||
                    (sipaType == SIPAEVENT_VBS_SECUREBOOT_REQUIRED) ||
                    (sipaType == SIPAEVENT_VBS_IOMMU_REQUIRED) ||
                    (sipaType == SIPAEVENT_VBS_MMIO_NX_REQUIRED) ||
                    (sipaType == SIPAEVENT_VBS_MSR_FILTERING_REQUIRED) ||
                    (sipaType == SIPAEVENT_VBS_MANDATORY_ENFORCEMENT) ||
                    (sipaType == SIPAEVENT_NOAUTHORITY)))
            {
                if (pbSipaData[0] == 0)
                {
                    wprintf(L"FALSE</%s>\n", eventEndStr);
                }
                else
                {
                    wprintf(L"TRUE</%s>\n", eventEndStr);
                }
            }
            else if ((cbSipaLen == sizeof(UINT64)) &
                ((sipaType == SIPAEVENT_IMAGESIZE) ||
                    (sipaType == SIPAEVENT_IMAGEBASE) ||
                    (sipaType == SIPAEVENT_HYPERVISOR_LAUNCH_TYPE) ||
                    (sipaType == SIPAEVENT_HYPERVISOR_IOMMU_POLICY) ||
                    (sipaType == SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY) ||
                    (sipaType == SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY) ||
                    (sipaType == SIPAEVENT_VSM_LAUNCH_TYPE) ||
                    (sipaType == SIPAEVENT_VBS_HVCI_POLICY) ||
                    (sipaType == SIPAEVENT_DATAEXECUTIONPREVENTION) ||
                    (sipaType == SIPAEVENT_PHYSICALADDRESSEXTENSION) ||
                    (sipaType == SIPAEVENT_BOOTCOUNTER) ||
                    (sipaType == SIPAEVENT_EVENTCOUNTER) ||
                    (sipaType == SIPAEVENT_COUNTERID)))
            {
                wprintf(L"%I64u<!-- 0x%016I64x --></%s>\n",
                    *((PUINT64)pbSipaData),
                    *((PUINT64)pbSipaData),
                    eventEndStr);
            }
            else if ((sipaType == SIPAEVENT_FILEPATH) ||
                (sipaType == SIPAEVENT_SYSTEMROOT) ||
                (sipaType == SIPAEVENT_AUTHORITYPUBLISHER) ||
                (sipaType == SIPAEVENT_AUTHORITYISSUER))
            {
                wprintf(L"%s</%s>\n", (PWCHAR)pbSipaData, eventEndStr);
            }
            else if ((cbSipaLen == sizeof(UINT32)) &
                (sipaType == SIPAEVENT_BITLOCKER_UNLOCK))
            {
                UINT32 dwBitLockerUnlock = *((PUINT32)pbSipaData);
                if (dwBitLockerUnlock == FVEB_UNLOCK_FLAG_NONE)
                {
                    wprintf(L"</%s>\n", eventEndStr);
                }
                else
                {
                    if (dwBitLockerUnlock & FVEB_UNLOCK_FLAG_CACHED)
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>CACHED</BitLockerKeyFlag>");
                    }
                    if (dwBitLockerUnlock & FVEB_UNLOCK_FLAG_MEDIA)
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>MEDIA</BitLockerKeyFlag>");
                    }
                    if (dwBitLockerUnlock & FVEB_UNLOCK_FLAG_TPM)
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>TPM</BitLockerKeyFlag>");
                    }
                    if (dwBitLockerUnlock & FVEB_UNLOCK_FLAG_PIN)
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>PIN</BitLockerKeyFlag>");
                    }
                    if (dwBitLockerUnlock & FVEB_UNLOCK_FLAG_EXTERNAL)
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>EXTERNAL</BitLockerKeyFlag>");
                    }
                    if (dwBitLockerUnlock & FVEB_UNLOCK_FLAG_RECOVERY)
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>RECOVERY</BitLockerKeyFlag>");
                    }
                    if (dwBitLockerUnlock & ~(FVEB_UNLOCK_FLAG_CACHED |
                        FVEB_UNLOCK_FLAG_MEDIA |
                        FVEB_UNLOCK_FLAG_TPM |
                        FVEB_UNLOCK_FLAG_PIN |
                        FVEB_UNLOCK_FLAG_EXTERNAL |
                        FVEB_UNLOCK_FLAG_RECOVERY))
                    {
                        wprintf(L"\n");
                        LevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>UNKNOWN</BitLockerKeyFlag>");
                    }
                    wprintf(L"\n");
                    LevelPrefix(level);
                    wprintf(L"</%s>\n", eventEndStr);
                }
            }
            else if ((cbSipaLen == sizeof(UINT32)) &
                (sipaType == SIPAEVENT_OSDEVICE))
            {
                UINT32 dwOsDevice = *((PUINT32)pbSipaData);
                UINT32 n = 0;
                for (n = 0; OsDeviceId[n].Id != 0xFFFFFFFF; n++)
                {
                    if (OsDeviceId[n].Id == dwOsDevice)
                    {
                        break;
                    }
                }
                wprintf(L"%s</%s>\n",
                    OsDeviceId[n].Name, eventEndStr);
            }
            else if ((cbSipaLen == sizeof(UINT32)) &
                (sipaType == SIPAEVENT_DRIVER_LOAD_POLICY))
            {
                UINT32 dwDriverLoadPolicy = *((PUINT32)pbSipaData);
                if (dwDriverLoadPolicy == 0x00000001)
                {
                    wprintf(L"DEFAULT</%s>\n", eventEndStr);
                }
                else
                {
                    wprintf(L"%u</%s>\n",
                        dwDriverLoadPolicy, eventEndStr);
                }
            }
            else if (sipaType == SIPAEVENT_SI_POLICY)
            {
                DisplaySIPASIPolicy(pbSipaData,
                    cbSipaLen,
                    level + 1);

                LevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
            else if (sipaType == SIPAEVENT_VSM_IDK_INFO)
            {
                DisplaySIPAVsmIdkInfo(pbSipaData,
                    cbSipaLen,
                    level + 1);

                LevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
            else if (sipaType == SIPAEVENT_BOOT_REVOCATION_LIST ||
                sipaType == SIPAEVENT_OS_REVOCATION_LIST)
            {
                DisplaySIPARevocationList(pbSipaData,
                    cbSipaLen,
                    level + 1);

                LevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
            else if ((cbSipaLen == sizeof(UINT32)) &
                (sipaType == SIPAEVENT_TRANSFER_CONTROL))
            {
                UINT32 dwTransferControl = *((PUINT32)pbSipaData);
                UINT32 n = 0;
                for (n = 0; TransferControlId[n].Id != 0xFFFFFFFF; n++)
                {
                    if (TransferControlId[n].Id == dwTransferControl)
                    {
                        break;
                    }
                }
                wprintf(L"%s</%s>\n",
                    TransferControlId[n].Name, eventEndStr);
            }
            else if ((cbSipaLen == sizeof(UINT32)) &
                (sipaType == SIPAEVENT_HASHALGORITHMID))
            {
                UINT32 dwAlgId = *((PUINT32)pbSipaData);
                switch (dwAlgId)
                {
                case CALG_MD4:
                    wprintf(L"MD4</%s>\n", eventEndStr);
                    break;
                case CALG_MD5:
                    wprintf(L"MD5</%s>\n", eventEndStr);
                    break;
                case CALG_SHA1:
                    wprintf(L"SHA-1</%s>\n", eventEndStr);
                    break;
                case CALG_SHA_256:
                    wprintf(L"SHA-256</%s>\n", eventEndStr);
                    break;
                case CALG_SHA_384:
                    wprintf(L"SHA-384</%s>\n", eventEndStr);
                    break;
                case CALG_SHA_512:
                    wprintf(L"SHA-512</%s>\n", eventEndStr);
                    break;
                default:
                    wprintf(L"%u<!-- 0x%08x --></%s>\n",
                        *((PUINT32)pbSipaData),
                        *((PUINT32)pbSipaData),
                        eventEndStr);
                    break;
                }
            }
            else if ((cbSipaLen == sizeof(UINT32)) &&
                (sipaType == SIPAEVENT_MORBIT_NOT_CANCELABLE))
            {
                UINT32 dwProtocolVersion = *((PUINT32)pbSipaData);

                wprintf(L"<ProtocolVersion>%u</ProtocolVersion></%s>\n",
                    dwProtocolVersion,
                    eventEndStr);
            }
            else
            {
                wprintf(L"\n");
                LevelPrefix(level + 1);
                for (UINT32 n = 0; n < cbSipaLen; n++)
                {
                    wprintf(L"%02x", pbSipaData[n]);
                }
                wprintf(L"\n");
                LevelPrefix(level + 1);
                wprintf(L"<!-- ");
                for (UINT32 n = 0; n < cbSipaLen; n++)
                {
                    if (((pbSipaData[n] >= '0') && (pbSipaData[n] <= '9')) ||
                        ((pbSipaData[n] >= 'A') && (pbSipaData[n] <= 'Z')) ||
                        ((pbSipaData[n] >= 'a') && (pbSipaData[n] <= 'z')))
                    {
                        wprintf(L"%c", pbSipaData[n]);
                    }
                    else
                    {
                        wprintf(L".");
                    }
                }
                wprintf(L" -->\n");
                LevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
        }

        if (cbWBCLIntern >= (2 * sizeof(UINT32) + cbSipaLen))
        {
            pbWBCLIntern += (2 * sizeof(UINT32) + cbSipaLen);
            cbWBCLIntern -= (2 * sizeof(UINT32) + cbSipaLen);
        }
        else
        {
            break;
        }
    }

Cleanup:
    return hr;
}

HRESULT
DisplayLog(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
)
{
    HRESULT hr = S_OK;
    BYTE extendBuffer[MAX_DIGEST_SIZE * 2] = { 0 };
    BYTE softPCR[24][MAX_DIGEST_SIZE] = { 0 };
    BOOLEAN usedPcr[24] = { 0 };
    UINT32 result = 0;
    WBCL_Iterator wbclIterator;
    LPCWSTR szAlgorithm = BCRYPT_SHA1_ALGORITHM;
    int n;

    for (n = 17; n < 23; n++)
    {
        memset(softPCR[n], 0xff, MAX_DIGEST_SIZE);
    }

    // Parameter check
    if ((pbWBCL == NULL) ||
        (cbWBCL < sizeof(TCG_PCClientPCREventStruct)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    LevelPrefix(level);
    wprintf(L"<TCGLog>\n");

    LevelPrefix(level + 1);
    wprintf(L"<WBCLBlob size=\"%u\">\n", cbWBCL);
    LevelPrefix(level + 2);
    for (UINT32 n = 0; n < cbWBCL; n++)
    {
        wprintf(L"%02x", pbWBCL[n]);
    }
    wprintf(L"\n");
    LevelPrefix(level + 1);
    wprintf(L"</WBCLBlob>\n");

    LevelPrefix(level + 1);
    wprintf(L"<WBCL size=\"%u\">\n", cbWBCL);

    if (FAILED(hr = WbclApiInitIteratorInternal(pbWBCL,
        cbWBCL,
        &wbclIterator)))
    {
        goto Cleanup;
    }
    if (wbclIterator.hashAlgorithm == WBCL_DIGEST_ALG_ID_SHA_2_256)
    {
        szAlgorithm = BCRYPT_SHA256_ALGORITHM;
    }

    for (; hr == S_OK;
        hr = WbclApiMoveToNextElementInternal(&wbclIterator))
    {
        BYTE eventDataDigest[MAX_DIGEST_SIZE] = { 0 };
        UINT32 PcrIndex;
        UINT32 EventType;
        UINT32 EventDataSize;
        PBYTE pbEventData;
        PBYTE pbDigest;

        hr = WbclApiGetCurrentElementInternal(
            &wbclIterator,
            &PcrIndex,
            &EventType,
            &pbDigest,
            &EventDataSize,
            &pbEventData);

        if (FAILED(hr))
        {
            goto Cleanup;
        }

        BOOLEAN digestMatchesData = FALSE;
        WCHAR digestStr[MAX_DIGEST_SIZE * 2 + 1] = L""; // each byte takes up two char
        PWSTR eventStr = NULL;

        for (UINT32 n = 0; TcgId[n].Id != 0xFFFFFFFF; n++)
        {
            if (TcgId[n].Id == EventType)
            {
                eventStr = (PWCHAR) TcgId[n].Name;
            }
        }

        PWSTR digestStringIndex = digestStr;
        size_t cchDigestSrting = sizeof(digestStr) / sizeof(WCHAR);
        for (UINT32 n = 0; n < wbclIterator.digestSize; n++)
        {
            if (FAILED(hr = StringCchPrintfExW(
                digestStringIndex,
                cchDigestSrting,
                &digestStringIndex,
                &cchDigestSrting,
                0,
                L"%02x",
                pbDigest[n])))
            {
                goto Cleanup;
            }
        }

        // Validate the event digest
        if (FAILED(hr = TpmAttiShaHash(szAlgorithm,
            NULL,
            0,
            pbEventData,
            EventDataSize,
            eventDataDigest,
            wbclIterator.digestSize,
            &result)))
        {
            goto Cleanup;
        }
        digestMatchesData = (memcmp(eventDataDigest,
            pbDigest,
            wbclIterator.digestSize) == 0);

        LevelPrefix(level + 2);
        if (eventStr != NULL)
        {
            wprintf(L"<%s PCR=\"%02i\" %sDigest=\"%s\" Size=\"%u\"%s>\n",
                eventStr,
                PcrIndex,
                digestMatchesData ? L"Event" : L"",
                digestStr,
                EventDataSize,
                (EventDataSize == 0) ? L"/" : L"");
        }
        else
        {
            wprintf(L"<TCGEvent Type=\"%08x\" PCR=\"%02i\" %sDigest=\"%s\" Size=\"%u\"%s>\n",
                EventType,
                PcrIndex,
                digestMatchesData ? L"Event" : L"",
                digestStr,
                EventDataSize,
                (EventDataSize == 0) ? L"/" : L"");
        }

        // Decode SIPA events
        if ((((PcrIndex >= 12) &&
            (PcrIndex <= 14)) ||
            (PcrIndex == 0xffffffff)) &&
            ((EventType == EV_EVENT_TAG) ||
                (EventType == EV_NO_ACTION)))
        {
            if (FAILED(hr = DisplaySIPA(
                pbEventData,
                EventDataSize,
                level + 3)))
            {
                goto Cleanup;
            }
        }
        else
        {
            if (EventDataSize > 0)
            {
                LevelPrefix(level + 3);
                for (UINT32 n = 0; n < EventDataSize; n++)
                {
                    wprintf(L"%02x", pbEventData[n]);
                }
                wprintf(L"\n");
                LevelPrefix(level + 3);
                wprintf(L"<!-- ");
                for (UINT32 n = 0; n < EventDataSize; n++)
                {
                    if (((pbEventData[n] >= '0') && (pbEventData[n] <= '9')) ||
                        ((pbEventData[n] >= 'A') && (pbEventData[n] <= 'Z')) ||
                        ((pbEventData[n] >= 'a') && (pbEventData[n] <= 'z')))
                    {
                        wprintf(L"%c", pbEventData[n]);
                    }
                    else
                    {
                        wprintf(L".");
                    }
                }
                wprintf(L" -->\n");
            }
        }
        LevelPrefix(level + 2);
        if (EventDataSize > 0)
        {
            if (eventStr != NULL)
            {
                wprintf(L"</%s>\n", eventStr);
            }
            else
            {
                wprintf(L"</TCGEvent>\n");
            }
        }

        if (PcrIndex < 24)
        {
            if (memcpy_s(extendBuffer, sizeof(extendBuffer), softPCR[PcrIndex], wbclIterator.digestSize))
            {
                hr = E_FAIL;
                goto Cleanup;
            }
            if (memcpy_s(&extendBuffer[wbclIterator.digestSize], sizeof(extendBuffer) - wbclIterator.digestSize, pbDigest, wbclIterator.digestSize))
            {
                hr = E_FAIL;
                goto Cleanup;
            }
            if (FAILED(hr = TpmAttiShaHash(szAlgorithm,
                NULL,
                0,
                extendBuffer,
                wbclIterator.digestSize * 2,
                softPCR[PcrIndex],
                wbclIterator.digestSize,
                &result)))
            {
                goto Cleanup;
            }
            usedPcr[PcrIndex] = TRUE;
        }
    }
    // reset hr
    if (hr == S_FALSE)
    {
        hr = S_OK;
    }
    LevelPrefix(level + 1);
    wprintf(L"</WBCL>\n");
    LevelPrefix(level + 1);
    wprintf(L"<PCRs>\n");
    for (UINT32 n = 0; n < TPM_AVAILABLE_PLATFORM_PCRS; n++)
    {
        if (usedPcr[n] != FALSE)
        {
            LevelPrefix(level + 2);
            wprintf(L"<PCR Index=\"%02u\">", n);
            for (UINT32 m = 0; m < wbclIterator.digestSize; m++)
            {
                wprintf(L"%02x", softPCR[n][m]);
            }
            wprintf(L"</PCR>\n");
        }
    }
    LevelPrefix(level + 1);
    wprintf(L"</PCRs>\n");
    LevelPrefix(level);
    wprintf(L"</TCGLog>\n");

Cleanup:
    return hr;
}

HRESULT
DisplayKey(
    _In_ PCWSTR lpKeyName,
    _In_reads_(cbKey) PBYTE pbKey,
    DWORD cbKey,
    UINT32 level
)
{
    HRESULT hr = S_OK;
    BCRYPT_RSAKEY_BLOB* pKey = (BCRYPT_RSAKEY_BLOB*)pbKey;
    BYTE pubKeyDigest[20] = { 0 };
    UINT32 cbRequired = 0;

    // Parameter check
    if ((pbKey == NULL) ||
        (cbKey < sizeof(BCRYPT_RSAKEY_BLOB)) ||
        (cbKey < (sizeof(BCRYPT_RSAKEY_BLOB) +
            pKey->cbPublicExp +
            pKey->cbModulus +
            pKey->cbPrime1 +
            pKey->cbPrime2)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
        NULL,
        0,
        &pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
        pKey->cbPublicExp],
        pKey->cbModulus,
        pubKeyDigest,
        sizeof(pubKeyDigest),
        &cbRequired)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    LevelPrefix(level);
    wprintf(L"<RSAKey size=\"%u\"", cbKey);
    if ((lpKeyName != NULL) &&
        (wcslen(lpKeyName) != 0))
    {
        wprintf(L" keyName=\"%s\"", lpKeyName);
    }
    wprintf(L">\n");

    LevelPrefix(level + 1);
    wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
        ((PBYTE)&pKey->Magic)[0],
        ((PBYTE)&pKey->Magic)[1],
        ((PBYTE)&pKey->Magic)[2],
        ((PBYTE)&pKey->Magic)[3],
        pKey->Magic);

    LevelPrefix(level + 1);
    wprintf(L"<BitLength>%u</BitLength>\n", pKey->BitLength);

    LevelPrefix(level + 1);
    wprintf(L"<PublicExp size=\"%u\">\n", pKey->cbPublicExp);
    LevelPrefix(level + 2);
    for (UINT32 n = 0; n < pKey->cbPublicExp; n++)
    {
        wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) + n]);
    }
    wprintf(L"\n");
    LevelPrefix(level + 1);
    wprintf(L"</PublicExp>\n");

    LevelPrefix(level + 1);
    wprintf(L"<Modulus size=\"%u\" digest=\"", pKey->cbModulus);
    for (UINT32 n = 0; n < sizeof(pubKeyDigest); n++)
    {
        wprintf(L"%02x", pubKeyDigest[n]);
    }
    wprintf(L"\">\n");
    LevelPrefix(level + 2);
    for (UINT32 n = 0; n < pKey->cbModulus; n++)
    {
        wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
            pKey->cbPublicExp +
            n]);
    }
    wprintf(L"\n");
    LevelPrefix(level + 1);
    wprintf(L"</Modulus>\n");

    LevelPrefix(level + 1);
    if (pKey->cbPrime1 == 0)
    {
        wprintf(L"<Prime1/>\n");
    }
    else
    {
        wprintf(L"<Prime1 size=\"%u\">\n", pKey->cbPrime1);
        LevelPrefix(level + 2);
        for (UINT32 n = 0; n < pKey->cbPrime1; n++)
        {
            wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                pKey->cbPublicExp +
                pKey->cbModulus +
                n]);
        }
        wprintf(L"\n");
        LevelPrefix(level + 1);
        wprintf(L"</Prime1>\n");
    }
    LevelPrefix(level + 1);
    if (pKey->cbPrime2 == 0)
    {
        wprintf(L"<Prime2/>\n");
    }
    else
    {
        wprintf(L"<Prime2 size=\"%u\">\n", pKey->cbPrime2);
        LevelPrefix(level + 2);
        for (UINT32 n = 0; n < pKey->cbPrime2; n++)
        {
            wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                pKey->cbPublicExp +
                pKey->cbModulus +
                pKey->cbPrime1 +
                n]);
        }
        wprintf(L"\n");
        LevelPrefix(level + 1);
        wprintf(L"</Prime2>\n");
    }
    LevelPrefix(level);
    wprintf(L"</RSAKey>\n");

Cleanup:
    return hr;
}

HRESULT
DisplayPlatformAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
)
{
    HRESULT hr = S_OK;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;
    UINT32 digestSize = SHA1_DIGEST_SIZE;

    // Parameter check
    if ((pbAttestation == NULL) ||
        (cbAttestation < sizeof(PCP_PLATFORM_ATTESTATION_BLOB)) ||
        ((pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC) &&
            (pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC2)) ||
        (cbAttestation < (pAttestation->HeaderSize +
            pAttestation->cbPcrValues +
            pAttestation->cbQuote +
            pAttestation->cbSignature +
            pAttestation->cbLog)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    LevelPrefix(level);
    wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
        ((PBYTE)&pAttestation->Magic)[0],
        ((PBYTE)&pAttestation->Magic)[1],
        ((PBYTE)&pAttestation->Magic)[2],
        ((PBYTE)&pAttestation->Magic)[3],
        pAttestation->Magic);

    LevelPrefix(level);
    if (pAttestation->Platform == TPM_VERSION_12)
    {
        wprintf(L"<Platform>TPM_VERSION_12</Platform>\n");
    }
    else if (pAttestation->Platform == TPM_VERSION_20)
    {
        wprintf(L"<Platform>TPM_VERSION_20</Platform>\n");
    }
    else
    {
        wprintf(L"<Platform>0x%08x</Platform>\n", pAttestation->Platform);
    }

    LevelPrefix(level);
    wprintf(L"<HeaderSize>%u</HeaderSize>\n", pAttestation->HeaderSize);

    LevelPrefix(level);
    wprintf(L"<PcrValues size=\"%u\">\n", pAttestation->cbPcrValues);
    cursor = pAttestation->HeaderSize;

    if (pAttestation->Magic == PCP_PLATFORM_ATTESTATION_MAGIC2)
    {
        if (((PPCP_PLATFORM_ATTESTATION_BLOB2)pbAttestation)->PcrAlgorithmId == TPM_API_ALG_ID_SHA256)
        {
            digestSize = SHA256_DIGEST_SIZE;
        }
    }
    // sanity check
    if (pAttestation->cbPcrValues % digestSize != 0)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    for (UINT32 n = 0; n < (pAttestation->cbPcrValues / digestSize); n++)
    {
        LevelPrefix(level + 1);
        wprintf(L"<PCR Index=\"%u\">", n);
        for (UINT32 m = 0; m < digestSize; m++)
        {
            wprintf(L"%02x", pbAttestation[cursor]);
            cursor++;
        }
        wprintf(L"</PCR>\n");
    }
    LevelPrefix(level);
    wprintf(L"</PcrValues>\n");

    LevelPrefix(level);
    wprintf(L"<Quote size=\"%u\">\n", pAttestation->cbQuote);
    LevelPrefix(level + 1);
    for (UINT32 n = 0; n < pAttestation->cbQuote; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    LevelPrefix(level);
    wprintf(L"</Quote>\n");

    LevelPrefix(level);
    wprintf(L"<Signature size=\"%u\">\n", pAttestation->cbSignature);
    LevelPrefix(level + 1);
    for (UINT32 n = 0; n < pAttestation->cbSignature; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    LevelPrefix(level);
    wprintf(L"</Signature>\n");

    LevelPrefix(level);
    wprintf(L"<Log size=\"%u\">\n", pAttestation->cbLog);
    if (FAILED(hr = DisplayLog(&pbAttestation[cursor], pAttestation->cbLog, level + 2)))
    {
        goto Cleanup;
    }
    LevelPrefix(level);
    wprintf(L"</Log>\n");

Cleanup:
    return hr;
}

HRESULT
DisplayKeyBlob(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    DWORD cbKeyBlob,
    UINT32 level
)
{
    HRESULT hr = S_OK;
    PPCP_KEY_BLOB p12Key = (PPCP_KEY_BLOB)pbKeyBlob;
    PPCP_KEY_BLOB_WIN8 pW8Key = (PPCP_KEY_BLOB_WIN8)pbKeyBlob;
    UINT32 cursor = 0;
    PWSTR pcpTypeString[] = { (PWCHAR)L"PCPTYPE_UNKNOWN",
                             (PWCHAR)L"PCPTYPE_TPM12",
                             (PWCHAR)L"PCPTYPE_TPM20" };

    if ((p12Key != NULL) &&
        (cbKeyBlob >= sizeof(PCP_KEY_BLOB)) &&
        (p12Key->magic == BCRYPT_PCP_KEY_MAGIC) &&
        (p12Key->cbHeader >= sizeof(PCP_KEY_BLOB)) &&
        (p12Key->pcpType == PCPTYPE_TPM12) &&
        (cbKeyBlob >= p12Key->cbHeader +
            p12Key->cbTpmKey))
    {
        // TPM 1.2 Key
        LevelPrefix(level);
        wprintf(L"<BCRYPT_KEY_BLOB size=\"%u\" sizeHdr=\"%u\">\n", cbKeyBlob, p12Key->cbHeader);
        LevelPrefix(level + 1);
        wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
            ((PBYTE)&p12Key->magic)[0],
            ((PBYTE)&p12Key->magic)[1],
            ((PBYTE)&p12Key->magic)[2],
            ((PBYTE)&p12Key->magic)[3],
            p12Key->magic);
        LevelPrefix(level + 1);
        wprintf(L"<pcpType>%s</pcpType>\n", (p12Key->pcpType < ARRAYSIZE(pcpTypeString)) ? pcpTypeString[p12Key->pcpType] : pcpTypeString[0]);
        LevelPrefix(level + 1);
        wprintf(L"<flags>%08x</flags>\n", p12Key->flags);
        LevelPrefix(level + 1);
        cursor += p12Key->cbHeader;
        wprintf(L"<TPM_KEY12 size=\"%u\">\n", p12Key->cbTpmKey);
        LevelPrefix(level + 2);
        for (UINT32 n = 0; n < cbKeyBlob - cursor; n++)
        {
            wprintf(L"%02x", pbKeyBlob[cursor]);
            cursor++;
        }
        wprintf(L"\n");
        LevelPrefix(level + 1);
        wprintf(L"</TPM_KEY12>\n");
        LevelPrefix(level);
        wprintf(L"</BCRYPT_KEY_BLOB>\n");
    }
    else if ((pW8Key != NULL) &&
        (cbKeyBlob >= sizeof(PCP_KEY_BLOB_WIN8)) &&
        (pW8Key->magic == BCRYPT_PCP_KEY_MAGIC) &&
        (pW8Key->cbHeader >= sizeof(PCP_KEY_BLOB_WIN8)) &&
        (pW8Key->pcpType == PCPTYPE_TPM20) &&
        (cbKeyBlob >= pW8Key->cbHeader +
            pW8Key->cbPublic +
            pW8Key->cbPrivate +
            pW8Key->cbMigrationPublic +
            pW8Key->cbMigrationPrivate +
            pW8Key->cbPolicyDigestList +
            pW8Key->cbPCRBinding +
            pW8Key->cbPCRDigest +
            pW8Key->cbEncryptedSecret +
            pW8Key->cbTpm12HostageBlob))
    {
        // TPM 2.0 Key
        LevelPrefix(level);
        wprintf(L"<PCP_KEY_BLOB_WIN8 size=\"%u\" sizeHdr=\"%u\">\n", cbKeyBlob, pW8Key->cbHeader);
        LevelPrefix(level + 1);
        wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
            ((PBYTE)&pW8Key->magic)[0],
            ((PBYTE)&pW8Key->magic)[1],
            ((PBYTE)&pW8Key->magic)[2],
            ((PBYTE)&pW8Key->magic)[3],
            pW8Key->magic);
        LevelPrefix(level + 1);
        wprintf(L"<pcpType>%s</pcpType>\n", (p12Key->pcpType < ARRAYSIZE(pcpTypeString)) ? pcpTypeString[p12Key->pcpType] : pcpTypeString[0]);
        LevelPrefix(level + 1);
        wprintf(L"<flags>%08x</flags>\n", pW8Key->flags);
        if (pW8Key->cbHeader >= sizeof(PCP_20_KEY_BLOB))
        {
            LevelPrefix(level + 1);
            wprintf(L"<pcrAlgId>%04x</pcrAlgId>\n", ((PPCP_20_KEY_BLOB)pW8Key)->pcrAlgId);
        }
        LevelPrefix(level + 1);
        wprintf(L"<TPM2B_PUBLIC_KEY size=\"%u\">\n", pW8Key->cbPublic);
        cursor += pW8Key->cbHeader;

        if (pW8Key->cbPublic != 0)
        {
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbPublic; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPM2B_PUBLIC_KEY>\n");
            cursor += pW8Key->cbPublic;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PUBLIC_KEY/>\n");
        }

        if (pW8Key->cbPrivate != 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_KEY size=\"%u\">\n", pW8Key->cbPrivate);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbPrivate; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPM2B_PRIVATE_KEY>\n");
            cursor += pW8Key->cbPrivate;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_KEY/>\n");
        }

        if (pW8Key->cbMigrationPublic != 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PUBLIC_MIGRATION size=\"%u\">\n", pW8Key->cbMigrationPublic);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbMigrationPublic; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPM2B_PUBLIC_MIGRATION>\n");
            cursor += pW8Key->cbMigrationPublic;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PUBLIC_MIGRATION/>\n");
        }

        if (pW8Key->cbMigrationPrivate > 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_MIGRATION size=\"%u\">\n", pW8Key->cbMigrationPrivate);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbMigrationPrivate; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPM2B_PRIVATE_MIGRATION>\n");
            cursor += pW8Key->cbMigrationPrivate;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_MIGRATION/>\n");
        }

        if (pW8Key->cbPolicyDigestList > 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPML_DIGEST_POLICY size=\"%u\">\n", pW8Key->cbPolicyDigestList);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbPolicyDigestList; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPML_DIGEST_POLICY>\n");
            cursor += pW8Key->cbPolicyDigestList;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPML_DIGEST_POLICY/>\n");
        }

        if (pW8Key->cbPCRBinding > 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<PcrBinding size=\"%u\">\n", pW8Key->cbPCRBinding);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbPCRBinding; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</PcrBinding>\n");
            cursor += pW8Key->cbPCRBinding;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<PcrBinding/>\n");
        }

        if (pW8Key->cbPCRDigest > 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<PcrDigest size=\"%u\">\n", pW8Key->cbPCRDigest);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbPCRDigest; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</PcrDigest>\n");
            cursor += pW8Key->cbPCRDigest;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<PcrDigest/>\n");
        }

        if (pW8Key->cbEncryptedSecret > 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_DATA_IMPORT_SECRET size=\"%u\">\n", pW8Key->cbEncryptedSecret);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbEncryptedSecret; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPM2B_DATA_IMPORT_SECRET>\n");
            cursor += pW8Key->cbEncryptedSecret;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_DATA_IMPORT_SECRET/>\n");
        }

        if (pW8Key->cbTpm12HostageBlob > 0)
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_IMPORT size=\"%u\">\n", pW8Key->cbTpm12HostageBlob);
            LevelPrefix(level + 2);
            for (UINT32 n = 0; n < pW8Key->cbTpm12HostageBlob; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            LevelPrefix(level + 1);
            wprintf(L"</TPM2B_PRIVATE_IMPORT>\n");
            cursor += pW8Key->cbTpm12HostageBlob;
        }
        else
        {
            LevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_IMPORT/>\n");
        }

        LevelPrefix(level);
        wprintf(L"</PCP_KEY_BLOB_WIN8>\n");
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

Cleanup:
    return hr;
}

HRESULT
DisplayKeyAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
)
{
    HRESULT hr = S_OK;
    PPCP_KEY_ATTESTATION_BLOB pAttestation = (PPCP_KEY_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;

    // Parameter check
    if ((pbAttestation == NULL) ||
        (cbAttestation < sizeof(PCP_KEY_ATTESTATION_BLOB)) ||
        (pAttestation->Magic != PCP_KEY_ATTESTATION_MAGIC) ||
        (cbAttestation < (pAttestation->HeaderSize +
            pAttestation->cbKeyAttest +
            pAttestation->cbSignature +
            pAttestation->cbKeyBlob)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    LevelPrefix(level);
    wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
        ((PBYTE)&pAttestation->Magic)[0],
        ((PBYTE)&pAttestation->Magic)[1],
        ((PBYTE)&pAttestation->Magic)[2],
        ((PBYTE)&pAttestation->Magic)[3],
        pAttestation->Magic);

    LevelPrefix(level);
    if (pAttestation->Platform == TPM_VERSION_12)
    {
        wprintf(L"<Platform>TPM_VERSION_12</Platform>\n");
    }
    else if (pAttestation->Platform == TPM_VERSION_20)
    {
        wprintf(L"<Platform>TPM_VERSION_20</Platform>\n");
    }
    else
    {
        wprintf(L"<Platform>0x%08x</Platform>\n", pAttestation->Platform);
    }

    LevelPrefix(level);
    wprintf(L"<HeaderSize>%u</HeaderSize>\n", pAttestation->HeaderSize);
    cursor += pAttestation->HeaderSize;

    LevelPrefix(level);
    wprintf(L"<Certify size=\"%u\">\n", pAttestation->cbKeyAttest);
    LevelPrefix(level + 1);
    for (UINT32 n = 0; n < pAttestation->cbKeyAttest; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    LevelPrefix(level);
    wprintf(L"</Certify>\n");

    LevelPrefix(level);
    wprintf(L"<Signature size=\"%u\">\n", pAttestation->cbSignature);
    LevelPrefix(level + 1);
    for (UINT32 n = 0; n < pAttestation->cbSignature; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    LevelPrefix(level);
    wprintf(L"</Signature>\n");

    LevelPrefix(level);
    wprintf(L"<KeyBlob size=\"%u\">\n", pAttestation->cbKeyBlob);
    if (FAILED(hr = DisplayKeyBlob(&pbAttestation[cursor], pAttestation->cbKeyBlob, level + 1)))
    {
        goto Cleanup;
    }
    LevelPrefix(level);
    wprintf(L"</KeyBlob>\n");

Cleanup:
    return hr;
}

HRESULT
WriteFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
)
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;

    hFile = CreateFileW(
        lpFileName,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }


    while (cbData > bytesWritten)
    {
        DWORD bytesWrittenLast = 0;
        if (!WriteFile(hFile,
            &pbData[bytesWritten],
            (DWORD)(cbData - bytesWritten),
            &bytesWrittenLast,
            NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
        bytesWritten += bytesWrittenLast;
    }

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

HRESULT
AppendFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
)
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;

    if (pbData == NULL ||
        cbData == 0)
    {
        // don't do anything for empty buffer
        goto Cleanup;
    }

    hFile = CreateFileW(
        lpFileName,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if (SetFilePointer(hFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    while (cbData > bytesWritten)
    {
        DWORD bytesWrittenLast = 0;
        if (!WriteFile(hFile,
            &pbData[bytesWritten],
            (DWORD)(cbData - bytesWritten),
            &bytesWrittenLast,
            NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
        bytesWritten += bytesWrittenLast;
    }

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

HRESULT
ReadFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData,
    __out PUINT32 pcbData
)
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER dataSize = { 0 };
    DWORD bytesRead = 0;

    if (pcbData == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    hFile = CreateFileW(
        lpFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if (!GetFileSizeEx(hFile, &dataSize))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if (dataSize.HighPart != 0)
    {
        hr = NTE_BAD_DATA;
        goto Cleanup;
    }

    *pcbData = dataSize.LowPart;
    if ((pbData == NULL) || (cbData == 0))
    {
        goto Cleanup;
    }
    else if (cbData < *pcbData)
    {
        hr = NTE_BUFFER_TOO_SMALL;
        goto Cleanup;
    }
    else
    {
        while (cbData > bytesRead)
        {
            DWORD bytesReadLast = 0;
            if (!ReadFile(hFile,
                &pbData[bytesRead],
                (DWORD)(cbData - bytesRead),
                &bytesReadLast,
                NULL))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto Cleanup;
            }
            bytesRead += bytesReadLast;
        }
    }

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

HRESULT
ReadFile(
    _In_ PCWSTR lpFileName,
    UINT32 offset,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData
)
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER dataSize = { 0 };
    DWORD bytesRead = 0;

    if ((pbData == NULL) ||
        (cbData == 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    hFile = CreateFileW(
        lpFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if (!GetFileSizeEx(hFile, &dataSize))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if ((dataSize.HighPart != 0) ||
        (dataSize.LowPart < (offset + cbData)))
    {
        hr = NTE_BAD_DATA;
        goto Cleanup;
    }

    if (SetFilePointer(hFile, offset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    while (cbData > bytesRead)
    {
        DWORD bytesReadLast = 0;
        if (!ReadFile(hFile,
            &pbData[bytesRead],
            (DWORD)(cbData - bytesRead),
            &bytesReadLast,
            NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
        bytesRead += bytesReadLast;
    }

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

void
CallResult(
    _In_ WCHAR* func,
    HRESULT hr
)
{
    PWSTR Buffer = NULL;
    DWORD result = 0;

    if (FAILED(hr))
    {
        result = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            (PVOID)GetModuleHandle(NULL),
            hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            (PTSTR)&Buffer,
            0,
            NULL);

        if (result != 0)
        {
            wprintf(L"ERROR - %s: (0x%08lx) %s\n", func, hr, Buffer);
        }
        else
        {
            wprintf(L"ERROR - %s: (0x%08lx)\n", func, hr);
        }
        LocalFree(Buffer);
    }
}



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
)
{
    HRESULT hr = S_OK;
    UINT32 cbRequired = 0;
    BYTE cmd[0x200] = { 0 };
    BYTE rsp[0x200] = { 0 };
    UINT32 cursorCmd = 0;
    UINT32 cursorRsp = 0;
    UINT32 cursorPcrProfile = 0;
    UINT32 cbRsp = sizeof(rsp);
    BYTE pcrProfile[] = { 0x00, 0x00, 0x00, 0x01, // count = 1
                         0x00, 0x04,             // TPM_ALG_SHA
                         0x03,                   // sizeOfSelect
                         0x7f, 0x7f, 0x00 };      // Default platform PCRs mask
    UINT32 responseSize = 0;
    UINT32 returnCode = 0;
    PBYTE pbQuoteTpm = NULL;
    UINT16 cbQuoteTpm = 0;
    UINT16 sigAlg = 0;
    UINT16 sigHashAlg = 0;
    PBYTE pbSignature = NULL;
    UINT16 cbSignature = 0;

    // Check the parameters
    if (pcbResult == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // overwrite hashing algorithm
    cursorPcrProfile = 0x0004;
    if (FAILED(hr = WriteBigEndian(pcrProfile, sizeof(pcrProfile), &cursorPcrProfile, (UINT16)pcrAlgId)))
    {
        goto Cleanup;
    }

    // Fill in PCRmask
    pcrProfile[0x0007] = (BYTE)((pcrMask & 0x000000ff));
    pcrProfile[0x0008] = (BYTE)(((pcrMask & 0x0000ff00) >> 8));
    pcrProfile[0x0009] = (BYTE)(((pcrMask & 0x00ff0000) >> 16));

    // Build Quote2 command buffer
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x8002))) //TPM_ST_SESSIONS
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000000))) //paramSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000158))) //TPM_CC_Quote
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, hPlatformKeyHandle))) //keyHandle
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)(sizeof(UINT32) + // authHandle
        sizeof(UINT16) + // nonceNULL
        sizeof(BYTE) +   // sessionAttributes
        sizeof(UINT16) + // passwordSize
        cbKeyAuth))))     // authorizationSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x40000009))) //TPM_RS_PW
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x0000))) //nonceNULL
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (BYTE)0x00))) //sessionAttributes
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)cbKeyAuth))) //passwordSize
    {
        goto Cleanup;
    }
    if (cbKeyAuth != 0)
    {
        if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pbKeyAuth, cbKeyAuth))) //password
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)cbNonce))) //qualifyingDataSize
    {
        goto Cleanup;
    }
    if (cbNonce != 0)
    {
        if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pbNonce, cbNonce))) //qualifyingData
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x0010))) //TPM_ALG_NULL
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pcrProfile, sizeof(pcrProfile)))) //PCRselect 
    {
        goto Cleanup;
    }

    // Set the command size
    ENDIANSWAP_UINT32TOARRAY(cursorCmd, cmd, 0x0002); // Location of paramSize

    // Send the command to the TPM
    if (FAILED(hr = Tbsip_Submit_Command(hPlatformTbsHandle,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd,
        cursorCmd,
        rsp,
        &cbRsp)))
    {
        goto Cleanup;
    }

    // Parse the response
    if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT16)))) // skip tag
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &responseSize))) // responseSize
    {
        goto Cleanup;
    }
    if (responseSize != cbRsp)
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &returnCode))) // ReturnCode
    {
        goto Cleanup;
    }
    if (returnCode != 0)
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT32)))) // paramSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &cbQuoteTpm))) // quotedSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &pbQuoteTpm, cbQuoteTpm))) // quoted
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &sigAlg))) // sigAlg
    {
        goto Cleanup;
    }
    if (sigAlg != 0x0014) //TPM_ALG_RSASSA_PKCS1v1_5
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &sigHashAlg))) // hash == TPM_ALG_SHA
    {
        goto Cleanup;
    }
    if (sigHashAlg != TPM_API_ALG_ID_SHA1) //TPM_ALG_SHA
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &cbSignature))) // signatureSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &pbSignature, cbSignature))) // signatureSize
    {
        goto Cleanup;
    }
    // We ignore the trailing session information in the response - It does not hold any information

    // Calculate Quote output buffer
    cbRequired = cbQuoteTpm +     // quote
        cbSignature;     // Signature
    if ((pbQuote == NULL) || (cbQuote == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }
    if (cbQuote < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Generate Quote output
    *pcbResult = 0;
    if (FAILED(hr = WriteBigEndian(pbQuote, cbQuote, pcbResult, pbQuoteTpm, cbQuoteTpm)))//Quote
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(pbQuote, cbQuote, pcbResult, pbSignature, cbSignature)))//signature
    {
        goto Cleanup;
    }

    if (*pcbResult > cbQuote)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

Cleanup:
    return hr;
}

/*Taken from  - TpmAtt project*/
HRESULT
GetPlatformPcrs20Internal(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT16 pcrAlgId,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
)
{
    HRESULT hr = S_OK;
    UINT32 cbRequired = 0;
    UINT32 cursorOutput = 0;
    BYTE cmd[0x200] = { 0 };
    BYTE rsp[0x200] = { 0 };
    UINT32 cursorCmd = 0;
    UINT32 cursorRsp = 0;
    UINT32 cursorPcrProfile = 0;
    UINT32 cbRsp = sizeof(rsp);
    BYTE pcrProfile[] = { 0x00, 0x00, 0x00, 0x01, // count = 1
                         0x00, 0x04,             // TPM_ALG_SHA
                         0x03,                   // sizeofSelect
                         0x00, 0x00, 0x00 };      // pcrSelect
    UINT32 responseSize = 0;
    UINT32 returnCode = 0;
    UINT32 pcrCount = 0;

    UINT32 cursorParamSize = 0;
    UINT32 cursorPcrMask = 0;

    // Check the parameters
    if (pcbResult == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // overwrite hashing algorithm
    cursorPcrProfile = 0x0004;
    if (FAILED(hr = WriteBigEndian(pcrProfile, sizeof(pcrProfile), &cursorPcrProfile, (UINT16)pcrAlgId)))
    {
        goto Cleanup;
    }

    // Calculate output buffer
    cbRequired = AVAILABLE_PLATFORM_PCRS * ((pcrAlgId == TPM_API_ALG_ID_SHA256) ? SHA256_DIGEST_SIZE : SHA1_DIGEST_SIZE);
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

    // Build ReadPCR command buffer
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x8001))) //TPM_NO_ST_SESSIONS
    {
        goto Cleanup;
    }
    cursorParamSize = cursorCmd;
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000000))) //paramSize placeholder
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x0000017E))) //TPM_CC_PCR_Read
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pcrProfile, sizeof(pcrProfile)))) //pcrSelectionIn
    {
        goto Cleanup;
    }
    cursorPcrMask = cursorCmd - sizeof(UINT32);
    // Set the correct command size
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorParamSize, cursorCmd))) //correct paramSize
    {
        goto Cleanup;
    }

    for (UINT32 n = 0; n < 3; n++)
    {
        // Set the pcrBlock to receive
        UINT32 cursorPcrMaskIteration = cursorPcrMask;
        if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorPcrMaskIteration, (UINT32)((0x00ff0000 >> (n * 8)) | 0x03000000)))) //pcrSelectionIn
        {
            goto Cleanup;
        }

        // Send the command to the TPM
        cbRsp = sizeof(rsp);
        if (FAILED(hr = Tbsip_Submit_Command(hPlatformTbsHandle,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL,
            cmd,
            cursorCmd,
            rsp,
            &cbRsp)))
        {
            goto Cleanup;
        }

        // Parse the response
        cursorRsp = 0;
        if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT16)))) // skip tag
        {
            goto Cleanup;
        }
        if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &responseSize))) // responseSize
        {
            goto Cleanup;
        }
        if (responseSize != cbRsp)
        {
            hr = E_FAIL;
            goto Cleanup;
        }
        if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &returnCode))) // ReturnCode
        {
            goto Cleanup;
        }
        if (returnCode != 0)
        {
            hr = E_FAIL;
            goto Cleanup;
        }
        if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT32)))) // skip pcrUpdateCounter
        {
            goto Cleanup;
        }
        if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(pcrProfile)))) // pcrSelectionOut
        {
            goto Cleanup;
        }
        if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &pcrCount))) // count
        {
            goto Cleanup;
        }
        for (UINT32 m = 0; m < pcrCount; m++)
        {
            PBYTE pbDigest = NULL;
            UINT16 cbDigest = 0;

            if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &cbDigest))) // digestSize
            {
                goto Cleanup;
            }
            if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &pbDigest, cbDigest))) // digest
            {
                goto Cleanup;
            }
            if (FAILED(hr = WriteBigEndian(pbOutput, cbOutput, &cursorOutput, pbDigest, cbDigest)))
            {
                goto Cleanup;
            }
        }
    }
    *pcbResult = cursorOutput;
    if (*pcbResult > cbOutput)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }


Cleanup:
    return hr;
}


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
)
{
    HRESULT hr = S_OK;
    UINT32 cursorQuote = 0;
    UINT32 magic = 0;
    UINT16 attestType = 0;
    UINT32 count = 0;
    UINT16 digestAlg = 0;
    UINT32 pcrMaskQuote = 0;
    UINT16 cbPcrDigest = 0;
    PBYTE pbPcrDigest = 0;
    BYTE pcrReferenceBuffer[AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = { 0 };
    UINT32 cursorPcrReferenceBuffer = 0;
    UINT32 cbPcrReferenceDigest = 0;
    BYTE pcrReferenceDigest[MAX_DIGEST_SIZE] = { 0 };
    UINT32 digestSize = (pcrAlgId == TPM_API_ALG_ID_SHA256) ? SHA256_DIGEST_SIZE : SHA1_DIGEST_SIZE;

    // Check the parameters
    if ((pbQuote == NULL) || (cbQuote == 0) ||
        (pbPcrList == NULL) || (cbPcrList == 0) ||
        ((cbPcrList % digestSize) != 0) ||
        (pPcrMask == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Open up the TPMS_ATTEST structure:
    if (FAILED(hr = ReadBigEndian(pbQuote, cbQuote, &cursorQuote, &magic))) // magic
    {
        goto Cleanup;
    }
    if (magic != 0xFF544347) //TPM_GENERATED_VALUE
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(pbQuote, cbQuote, &cursorQuote, &attestType))) // type
    {
        goto Cleanup;
    }
    if (attestType != 0x8018) //TPM_ST_ATTEST_QUOTE
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    if (FAILED(hr = SkipBigEndian2B(pbQuote, cbQuote, &cursorQuote))) // qualifiedSigner
    {
        goto Cleanup;
    }
    if ((pbNonce != NULL) && (cbNonce == SHA1_DIGEST_SIZE))
    {
        // Validate the nonce
        UINT16 cbExtraData = 0;
        PBYTE pbExtraData = 0;
        if (FAILED(hr = ReadBigEndian2B(pbQuote, cbQuote, &cursorQuote, &cbExtraData, &pbExtraData))) // extraData
        {
            goto Cleanup;
        }
        if ((cbExtraData != cbNonce) || (memcmp(pbExtraData, pbNonce, cbExtraData) != 0))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }
    else
    {
        // Ignore the nonce
        if (FAILED(hr = SkipBigEndian2B(pbQuote, cbQuote, &cursorQuote))) // extraData
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = SkipBigEndian(pbQuote, cbQuote, &cursorQuote, (sizeof(UINT64) +
        sizeof(BYTE) +
        sizeof(UINT32) +
        sizeof(UINT32))))) // TPMS_CLOCK_INFO
    {
        goto Cleanup;
    }
    if (FAILED(hr = SkipBigEndian(pbQuote, cbQuote, &cursorQuote, sizeof(UINT64)))) // firmwareVersion
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(pbQuote, cbQuote, &cursorQuote, &count))) // count
    {
        goto Cleanup;
    }
    if (count != 0x00000001) //Only one set
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    // digestAlg is the algorithm ID of the PCR bank used as input for the Quote operation.
    // The algorithm ID of the hashing operation used to generate the digest of the PCRs is
    // not specified in the quote. It is determined by the key used to generate the quote.
    if (FAILED(hr = ReadBigEndian(pbQuote, cbQuote, &cursorQuote, &digestAlg))) // hashAlg
    {
        goto Cleanup;
    }
    // because the digestAlg is the algorithm ID of the PCR bank used as input into the
    // quote operation, it has to match the algorithm of the PCRs passed in for validation.
    if (digestAlg != pcrAlgId)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(pbQuote, cbQuote, &cursorQuote, &pcrMaskQuote))) // pcrMask
    {
        goto Cleanup;
    }
    if ((pcrMaskQuote & 0xff000000) != 0x03000000)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    pcrMaskQuote = ENDIANSWAPUINT32((pcrMaskQuote << 8) & 0xffffff00);
    if (FAILED(hr = ReadBigEndian2B(pbQuote, cbQuote, &cursorQuote, &cbPcrDigest, &pbPcrDigest))) // PcrDigest
    {
        goto Cleanup;
    }

    // Ensure that we consumed the entire quote
    if (cbQuote != cursorQuote)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Validate the PCRlist against the Quote
    // Read the pcr select indicated PCR values from the list and copy them into the reference buffer
    for (UINT32 n = 0; n < AVAILABLE_PLATFORM_PCRS; n++)
    {
        // Is PCR[n] selected?
        if ((pcrMaskQuote & (0x00000001 << n)) != 0)
        {
            // Copy to reference buffer
            if (FAILED(hr = WriteBigEndian(pcrReferenceBuffer, sizeof(pcrReferenceBuffer),
                &cursorPcrReferenceBuffer, &pbPcrList[n * digestSize], digestSize)))
            {
                goto Cleanup;
            }
        }
    }
    // Calculate the pcrDigest. This digest depends on the key used to generate the quote, which is 
    // not given anywhere. Guess that 32 byte digest means SHA256.
    if (FAILED(hr = TpmAttiShaHash(((cbPcrDigest == SHA256_DIGEST_SIZE) ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA1_ALGORITHM),
        NULL,
        0,
        pcrReferenceBuffer,
        cursorPcrReferenceBuffer,
        pcrReferenceDigest,
        cbPcrDigest,
        &cbPcrReferenceDigest)))
    {
        goto Cleanup;
    }
    // Compare the PCR digests
    if ((cbPcrDigest != cbPcrReferenceDigest) ||
        (memcmp(pbPcrDigest, pcrReferenceDigest, cbPcrDigest) != 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Return the included PCRMask
    *pPcrMask = pcrMaskQuote;

Cleanup:
    return hr;
}

