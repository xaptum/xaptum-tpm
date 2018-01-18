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
Tss2_Sys_Create(TSS2_SYS_CONTEXT *sysContext,
                TPMI_DH_OBJECT parentHandle,
                const TSS2_SYS_CMD_AUTHS *cmdAuthsArray,
                const TPM2B_SENSITIVE_CREATE *inSensitive,
                const TPM2B_PUBLIC *inPublic,
                const TPM2B_DATA *outsideInfo,
                const TPML_PCR_SELECTION *creationPCR,
                TPM2B_PRIVATE *outPrivate,
                TPM2B_PUBLIC *outPublic,
                TPM2B_CREATION_DATA *creationData,
                TPM2B_DIGEST *creationHash,
                TPMT_TK_CREATION *creationTicket,
                TSS2_SYS_RSP_AUTHS *rspAuthsArray)
{
    if (NULL == sysContext || NULL == creationPCR || NULL == cmdAuthsArray)
        return TSS2_SYS_RC_BAD_REFERENCE;

    TSS2_RC ret = TSS2_RC_SUCCESS;

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);

    build_command_header(sys_context, TPM_CC_Create, TPM_ST_SESSIONS);

    marshal_uint32(parentHandle, &sys_context->ptr);

    ret = set_cmdauths(sys_context, cmdAuthsArray);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    marshal_tpm2b_sensitivecreate(inSensitive, &sys_context->ptr);

    marshal_tpm2b_public(inPublic, &sys_context->ptr);

    marshal_tpm2b_data(outsideInfo, &sys_context->ptr);

    marshal_tpml_pcrselection(creationPCR, &sys_context->ptr);

    set_command_size(sys_context);

    ret = Tss2_Sys_Execute(sys_context);
    if (ret)
        return ret;

    ret = get_rspauths(sys_context, rspAuthsArray);
    if (ret)
        return ret;

    if (0 != unmarshal_tpm2b_private(&sys_context->ptr, &sys_context->remaining_response, outPrivate))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    if (0 != unmarshal_tpm2b_public(&sys_context->ptr, &sys_context->remaining_response, outPublic))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    if (0 != unmarshal_tpm2b_creationdata(&sys_context->ptr, &sys_context->remaining_response, creationData))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    if (0 != unmarshal_tpm2b_digest(&sys_context->ptr, &sys_context->remaining_response, creationHash))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    if (0 != unmarshal_tpmt_tkcreation(&sys_context->ptr, &sys_context->remaining_response, creationTicket))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    assert(sys_context->remaining_response == 0);

    return ret;
}
