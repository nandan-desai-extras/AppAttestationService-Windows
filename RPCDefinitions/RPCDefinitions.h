

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Mon Jan 18 19:14:07 2038
 */
/* Compiler settings for RPCDefinitions.idl:
    Oicf, W4, Zp8, env=Win32 (32b run), target_arch=X86 8.01.0628 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __RPCDefinitions_h__
#define __RPCDefinitions_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __RPCDefinitions_INTERFACE_DEFINED__
#define __RPCDefinitions_INTERFACE_DEFINED__

/* interface RPCDefinitions */
/* [implicit_handle][version][uuid] */ 

error_status_t RPC_GetEK_CreateAIK( 
    /* [string][in] */ wchar_t *AIKname,
    /* [string][in] */ wchar_t *serverNonce,
    /* [out] */ unsigned long *EKsize,
    /* [size_is][size_is][out] */ unsigned char **EK,
    /* [out] */ unsigned long *idBindingSize,
    /* [size_is][size_is][out] */ unsigned char **idBinding);

error_status_t RPC_VerifyActivationBlob( 
    /* [string][in] */ wchar_t *AIKname,
    /* [in] */ unsigned long serverActivationBlobSize,
    /* [size_is][in] */ unsigned char *serverActivationBlob,
    /* [out] */ unsigned long *serverSecretSize,
    /* [size_is][size_is][out] */ unsigned char **serverSecret);

error_status_t RPC_RegisterAIK( 
    /* [string][in] */ wchar_t *AIKname);

error_status_t RPC_GetAppAttestation( 
    /* [in] */ handle_t Binding,
    /* [string][in] */ wchar_t *AIKname,
    /* [string][in] */ wchar_t *serverNonce,
    /* [out] */ unsigned long *platformAttestationBlobSize,
    /* [out] */ unsigned long *appAttestationBlobSize,
    /* [out] */ unsigned long *attestationBlobTotalSize,
    /* [size_is][size_is][out] */ unsigned char **attestationBlob);


extern handle_t hExample1Binding;


extern RPC_IF_HANDLE RPCDefinitions_v1_0_c_ifspec;
extern RPC_IF_HANDLE RPCDefinitions_v1_0_s_ifspec;
#endif /* __RPCDefinitions_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


