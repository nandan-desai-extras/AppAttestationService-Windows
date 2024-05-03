#include "AppEventLogStorage.h"

AppEventLog APP_LOGS[MAX_APP_LOGS] = { 0 };

const unsigned char EMPTY_BUF[MAX_EVENT_MSG_LEN] = { 0x0 };

int AddAppEventLog(HANDLE processId, char* eventMsg, size_t eventMsgLen) {
	unsigned long pid = (unsigned long)processId;
	int i = 0;
	for (i = 0; i < MAX_APP_LOGS; i++) {
		if (APP_LOGS[i].PID == pid) {
			for (int j = 0; j < MAX_EVENT_LOGS; j++) {
				if (RtlEqualMemory((unsigned char*)APP_LOGS[i].eventMessages[j], EMPTY_BUF, MAX_EVENT_MSG_LEN) == TRUE) {
					if (eventMsgLen <= MAX_EVENT_MSG_LEN) {
						RtlCopyMemory((unsigned char*)APP_LOGS[i].eventMessages[j], (unsigned char*)eventMsg, eventMsgLen);
						return SUCCESS;
					}
					else {
						return ERROR_MSG_BUFFER_LEN;
					}
				}
			}
			return ERROR_LOG_STORAGE_FULL;
		}
	}
	for (i = 0; i < MAX_APP_LOGS; i++) {
		if (APP_LOGS[i].PID == 0) {
			APP_LOGS[i].PID = pid;
			if (eventMsgLen <= MAX_EVENT_MSG_LEN) {
				RtlCopyMemory((unsigned char*)APP_LOGS[i].eventMessages[0], (unsigned char*)eventMsg, eventMsgLen);
				return SUCCESS;
			}
			else {
				return ERROR_MSG_BUFFER_LEN;
			}
		}
	}
	return ERROR_LOG_STORAGE_FULL;
}


void ClearAppEventLogs(void) {
	RtlFillMemory(APP_LOGS, sizeof(APP_LOGS), 0x0);
}

void DisplayAppEventLogs(void) {
	int i = 0;
	for (i = 0; i < MAX_APP_LOGS; i++) {
		if (APP_LOGS[i].PID != 0) {
			DbgPrintEx(0, 0, "App %d, PID: %d\n", i, APP_LOGS[i].PID);
			for (int j = 0; j < MAX_EVENT_LOGS; j++) {
				DbgPrintEx(0, 0, "\tLog %d: %s\n", j, APP_LOGS[i].eventMessages[j]);
			}
		}
	}
}

BOOLEAN IsPIDPresentInAppLogs(HANDLE processId) {
	unsigned long pid = (unsigned long)processId;
	int i = 0;
	for (i = 0; i < MAX_APP_LOGS; i++) {
		if (APP_LOGS[i].PID == pid) {
			return TRUE;
		}
	}
	return FALSE;
}



