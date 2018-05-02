/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include <tss2/xaptum_nvram.h>

#include <tss2/tss2_sys.h>

#include <string.h>

TSS2_RC
xtpm_read_nvram(unsigned char *out,
                uint16_t size,
                TPM_HANDLE index,
                TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    // 1) Create SAPI context
    unsigned char sapi_context_buffer[5120];
    if (Tss2_Sys_GetContextSize(0) > sizeof(sapi_context_buffer)) {
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
    }
    TSS2_SYS_CONTEXT *sapi_context = (TSS2_SYS_CONTEXT*)sapi_context_buffer;

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    ret = Tss2_Sys_Initialize(sapi_context,
                              Tss2_Sys_GetContextSize(0),
                              tcti_context,
                              &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        return ret;
    }

    // We (Xaptum) set AUTHREAD and no password.
    //  This means anyone can read,
    //  by using an empty password and passing the index itself as the auth handle.
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    uint16_t data_offset = 0;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        ret = Tss2_Sys_NV_Read(sapi_context,
                               index,
                               index,
                               &sessionsData,
                               bytes_to_read,
                               data_offset,
                               &nv_data,
                               &sessionsDataOut);

        if (ret != TSS2_RC_SUCCESS) {
            goto finish;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

finish:
    Tss2_Sys_Finalize(sapi_context);

    return ret;
}

