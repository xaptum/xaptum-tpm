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

#include "internal/sys_context_common.h"

size_t
Tss2_Sys_GetContextSize(size_t maxCommandResponseSize)
{
    if (maxCommandResponseSize == 0) {
        return sizeof(TSS2_SYS_CONTEXT_OPAQUE);
    } else {
        return TSS2_TCTI_RC_NOT_IMPLEMENTED;
    }
}

TSS2_RC
Tss2_Sys_Initialize(TSS2_SYS_CONTEXT *sysContext,
                    size_t contextSize,
                    TSS2_TCTI_CONTEXT *tctiContext,
                    TSS2_ABI_VERSION *abiVersion)
{
    if (!sysContext || !tctiContext || !abiVersion)
        return TSS2_SYS_RC_BAD_REFERENCE;

    if (contextSize < sizeof(TSS2_SYS_CONTEXT_OPAQUE))
        return TSS2_SYS_RC_INSUFFICIENT_CONTEXT;

    if (NULL == ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->transmit ||
            NULL == ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->receive) {
        return TSS2_SYS_RC_BAD_TCTI_STRUCTURE;
    }

    if (abiVersion->tssCreator != TSS2_ABI_CURRENT_VERSION.tssCreator ||
            abiVersion->tssFamily != TSS2_ABI_CURRENT_VERSION.tssFamily ||
            abiVersion->tssLevel != TSS2_ABI_CURRENT_VERSION.tssLevel ||
            abiVersion->tssVersion != TSS2_ABI_CURRENT_VERSION.tssVersion) {
        return TSS2_SYS_RC_ABI_MISMATCH;
    }

    TSS2_SYS_CONTEXT_OPAQUE *sys_context = down_cast(sysContext);
    sys_context->tcti_context = tctiContext;
    reset_sys_context(sys_context);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_Sys_Finalize(TSS2_SYS_CONTEXT *sysContext)
{
    (void)sysContext;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_Sys_GetTctiContext(TSS2_SYS_CONTEXT *sysContext,
                        TSS2_TCTI_CONTEXT **tctiContext)
{
    if (NULL == sysContext || NULL == tctiContext)
        return TSS2_SYS_RC_BAD_REFERENCE;

    *tctiContext = ((TSS2_SYS_CONTEXT_OPAQUE*)sysContext)->tcti_context;

    return TSS2_RC_SUCCESS;
}
