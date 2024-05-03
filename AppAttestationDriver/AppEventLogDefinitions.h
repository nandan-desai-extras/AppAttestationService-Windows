#pragma once

#define MAX_APP_LOGS 20
#define MAX_EVENT_LOGS 70
#define MAX_EVENT_MSG_LEN 600

#define ERROR_LOG_STORAGE_FULL -2
#define ERROR_MSG_BUFFER_LEN -1
#define SUCCESS 0

typedef struct {
	unsigned long PID;
	char eventMessages[MAX_EVENT_LOGS][MAX_EVENT_MSG_LEN];
} AppEventLog;
