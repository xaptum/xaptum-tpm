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

#include <tss2/tss2_sys.h>

#include "internal/command_utils.h"
#include "internal/sys_context_common.h"
#include "internal/marshal.h"
#include "internal/execute.h"
#include "internal/cmdauths.h"

#include <assert.h>


TSS2_RC
Tss2_Sys_NV_DefineSpace(TSS2_SYS_CONTEXT *sysContext,
                        TPMI_RH_PROVISION authHandle,
                        TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
                        TPM2B_AUTH *auth,
                        TPM2B_NV_PUBLIC *publicInfo,
                        TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    if (NULL == sysContext || NULL == cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    TSS2_RC ret = TSS2_RC_SUCCESS;

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);

    build_command_header(sys_context, TPM_CC_NV_DefineSpace, TPM_ST_SESSIONS);

    marshal_uint32(authHandle, &sys_context->ptr);

    ret = set_cmdauths(sys_context, cmdAuthsArray);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    marshal_tpm2b_auth(auth, &sys_context->ptr);

    marshal_tpm2b_nvpublic(publicInfo, &sys_context->ptr);

    set_command_size(sys_context);

    ret = Tss2_Sys_Execute(sys_context);
    if (ret)
        return ret;

    ret = get_rspauths(sys_context, rspAuthsArray);
    if (ret)
        return ret;

    assert(sys_context->remaining_response == 0);

    return ret;
}

TSS2_RC
Tss2_Sys_NV_UndefineSpace(TSS2_SYS_CONTEXT *sysContext,
                          TPMI_RH_PROVISION authHandle,
                          TPMI_RH_NV_INDEX nvIndex,
                          TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
                          TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    if (NULL == sysContext || NULL == cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    TSS2_RC ret = TSS2_RC_SUCCESS;

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);

    build_command_header(sys_context, TPM_CC_NV_UndefineSpace, TPM_ST_SESSIONS);

    marshal_uint32(authHandle, &sys_context->ptr);

    marshal_uint32(nvIndex, &sys_context->ptr);

    ret = set_cmdauths(sys_context, cmdAuthsArray);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    set_command_size(sys_context);

    ret = Tss2_Sys_Execute(sys_context);
    if (ret)
        return ret;

    ret = get_rspauths(sys_context, rspAuthsArray);
    if (ret)
        return ret;

    assert(sys_context->remaining_response == 0);

    return ret;
}

TSS2_RC
Tss2_Sys_NV_Write(TSS2_SYS_CONTEXT *sysContext,
                  TPMI_RH_NV_AUTH authHandle,
                  TPMI_RH_NV_INDEX nvIndex,
                  TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
                  TPM2B_MAX_NV_BUFFER *data,
                  uint16_t offset,
                  TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    if (NULL == sysContext || NULL == cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    TSS2_RC ret = TSS2_RC_SUCCESS;

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);

    build_command_header(sys_context, TPM_CC_NV_Write, TPM_ST_SESSIONS);

    marshal_uint32(authHandle, &sys_context->ptr);

    marshal_uint32(nvIndex, &sys_context->ptr);

    ret = set_cmdauths(sys_context, cmdAuthsArray);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    marshal_tpm2b_maxnvbuffer(data, &sys_context->ptr);

    marshal_uint16(offset, &sys_context->ptr);

    set_command_size(sys_context);

    ret = Tss2_Sys_Execute(sys_context);
    if (ret)
        return ret;

    ret = get_rspauths(sys_context, rspAuthsArray);
    if (ret)
        return ret;

    assert(sys_context->remaining_response == 0);

    return ret;
}

TSS2_RC
Tss2_Sys_NV_Read(TSS2_SYS_CONTEXT *sysContext,
                 TPMI_RH_NV_AUTH authHandle,
                 TPMI_RH_NV_INDEX nvIndex,
                 TSS2_SYS_CMD_AUTHS const *cmdAuthsArray,
                 uint16_t size,
                 uint16_t offset,
                 TPM2B_MAX_NV_BUFFER *data,
                 TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    if (NULL == sysContext || NULL == cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    TSS2_RC ret = TSS2_RC_SUCCESS;

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);

    build_command_header(sys_context, TPM_CC_NV_Read, TPM_ST_SESSIONS);

    marshal_uint32(authHandle, &sys_context->ptr);

    marshal_uint32(nvIndex, &sys_context->ptr);

    ret = set_cmdauths(sys_context, cmdAuthsArray);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    marshal_uint16(size, &sys_context->ptr);

    marshal_uint16(offset, &sys_context->ptr);

    set_command_size(sys_context);

    ret = Tss2_Sys_Execute(sys_context);
    if (ret)
        return ret;

    ret = get_rspauths(sys_context, rspAuthsArray);
    if (ret)
        return ret;

    if (0 != unmarshal_tpm2b_maxnvbuffer(&sys_context->ptr, &sys_context->remaining_response, data))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    assert(sys_context->remaining_response == 0);

    return ret;
}
