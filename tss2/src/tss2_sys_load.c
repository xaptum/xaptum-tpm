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
Tss2_Sys_Load(TSS2_SYS_CONTEXT *sysContext,
              TPMI_DH_OBJECT parentHandle,
              const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
              const TPM2B_PRIVATE *inPrivate,
              const TPM2B_PUBLIC *inPublic,
              TPM2_HANDLE *objectHandle,
              TPM2B_NAME *name,
              TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray)
{
    if (NULL == sysContext || NULL == cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    TSS2_RC ret = TSS2_RC_SUCCESS;

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);

    build_command_header(sys_context, TPM2_CC_Load, TPM2_ST_SESSIONS);

    marshal_uint32(parentHandle, &sys_context->ptr);

    ret = set_cmdauths(sys_context, cmdAuthsArray);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    marshal_tpm2b_private(inPrivate, &sys_context->ptr);

    marshal_tpm2b_public(inPublic, &sys_context->ptr);

    set_command_size(sys_context);

    ret = Tss2_Sys_Execute(sys_context);
    if (ret)
        return ret;

    if (0 != unmarshal_uint32(&sys_context->ptr, &sys_context->remaining_response, objectHandle))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    ret = get_rspauths(sys_context, rspAuthsArray);
    if (ret)
        return ret;

    if (0 != unmarshal_tpm2b_name(&sys_context->ptr, &sys_context->remaining_response, name))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    assert(sys_context->remaining_response == 0);

    return ret;
}
