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
#include <tss2/tss2_tcti.h>

#include "sys_context_common.h"

#include "marshal.h"

#include <assert.h>

TSS2_RC
Tss2_Sys_Execute(TSS2_SYS_CONTEXT_OPAQUE *sys_context)
{
    TSS2_RC ret;

    ret = Tss2_Tcti_Transmit(sys_context->tcti_context,
                             sys_context->ptr - sys_context->buffer,
                             sys_context->buffer);
    if (ret)
        return ret;

    size_t response_size = sizeof(sys_context->buffer);
    assert(TPM2_MAX_COMMAND_SIZE == sizeof(sys_context->buffer));

    ret = Tss2_Tcti_Receive(sys_context->tcti_context,
                            &response_size,
                            sys_context->buffer,
                            TSS2_TCTI_TIMEOUT_BLOCK);
    if (ret)
        return ret;

    if (response_size < (sizeof(TPMI_ST_COMMAND_TAG) + sizeof(uint32_t) + sizeof(uint32_t)))
        return TSS2_SYS_RC_INSUFFICIENT_RESPONSE;

    sys_context->remaining_response = response_size;

    // Skip the response tag (it just echoes what was sent, unless there's an error, which we check anyhow).
    sys_context->ptr = sys_context->buffer + sizeof(TPMI_ST_COMMAND_TAG);
    sys_context->remaining_response -= sizeof(TPMI_ST_COMMAND_TAG);

    // Get the response size, and make sure it matches the length of buffer we just received.
    if (0 != unmarshal_uint32(&sys_context->ptr, &sys_context->remaining_response, &sys_context->response_length))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;
    if (sys_context->response_length != response_size)
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    // Get the response code.
    if (0 != unmarshal_uint32(&sys_context->ptr, &sys_context->remaining_response, &ret))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    return ret;
}
