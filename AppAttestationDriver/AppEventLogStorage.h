#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "AppEventLogDefinitions.h"


extern AppEventLog APP_LOGS[MAX_APP_LOGS];

int AddAppEventLog(HANDLE processId, char* eventMsg, size_t eventMsgLen);

void ClearAppEventLogs(void);

void DisplayAppEventLogs(void);

BOOLEAN IsPIDPresentInAppLogs(HANDLE processId);

