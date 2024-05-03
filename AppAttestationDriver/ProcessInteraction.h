#pragma once
#include <ntifs.h>

extern PVOID registrationHandle;
extern UNICODE_STRING altitude;
extern OB_OPERATION_REGISTRATION obOperationRegistration;
extern OB_CALLBACK_REGISTRATION obCallbackRegistration;

OB_PREOP_CALLBACK_STATUS MyPreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreOperationInfo);

