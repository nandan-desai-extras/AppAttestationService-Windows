#pragma once
#include "rpc.h"
#include "rpcndr.h"

HRESULT
RPCWriteData(
    unsigned char** rpc_buffer,
    unsigned long* rpc_buffer_size,
    unsigned char* source_buffer,
    unsigned long source_buffer_size
);