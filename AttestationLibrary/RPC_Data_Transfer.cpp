#include "RPC_Data_Transfer.h"

HRESULT
RPCWriteData(
    unsigned char** rpc_buffer,
    unsigned long* rpc_buffer_size,
    unsigned char* source_buffer,
    unsigned long source_buffer_size
) 
{
    if (source_buffer == NULL || source_buffer_size <= 0) {
        return E_FAIL;
    }
    *rpc_buffer = (unsigned char*)midl_user_allocate(source_buffer_size);
    memcpy(*rpc_buffer, source_buffer, source_buffer_size);
    *rpc_buffer_size = source_buffer_size;
    return S_OK;
}


