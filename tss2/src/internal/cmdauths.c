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

#include "cmdauths.h"

#include <tss2/tss2_sys.h>

#include "marshal.h"

TSS2_RC
set_cmdauths(TSS2_SYS_CONTEXT_OPAQUE *sys_context,
             const TSS2L_SYS_AUTH_COMMAND *cmd_auths_array)
{
    sys_context->cmd_auths_count = cmd_auths_array->count;

    if (0 == cmd_auths_array->count)
        return TSS2_RC_SUCCESS;

    uint8_t *size_ptr = sys_context->ptr;

    sys_context->ptr += sizeof(uint32_t);   // Make room for the authorizationSize

    for (unsigned i=0; i < cmd_auths_array->count; i++) {
        marshal_tpms_authcommand(&cmd_auths_array->auths[i], &sys_context->ptr);
    }

    uint32_t authorizationSize = sys_context->ptr - size_ptr;
    authorizationSize -= sizeof(uint32_t);  // don't count authorizationSize itself
    marshal_uint32(authorizationSize, &size_ptr);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
get_rspauths(TSS2_SYS_CONTEXT_OPAQUE *sys_context,
             TSS2L_SYS_AUTH_RESPONSE *rsp_auths_array)
{
    if (rsp_auths_array->count != sys_context->cmd_auths_count)
        return TSS2_SYS_RC_INVALID_SESSIONS;

    // Get the 'parameter_size' (the length of the parameters after the handles and before the rsp_auths_array),
    // and make sure it's not too long for the response buffer.
    uint32_t parameter_size;
    if (0 != unmarshal_uint32(&sys_context->ptr, &sys_context->remaining_response, &parameter_size))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;
    if ((sys_context->ptr + parameter_size) > (sys_context->buffer + sys_context->response_length))
        return TSS2_SYS_RC_MALFORMED_RESPONSE;

    // Skip over the parameters, to the rsp_auths_array.
    uint8_t *rsp_auths_ptr = sys_context->ptr + parameter_size;

    // Read the rsp_auths_array
    for (unsigned i=0; i < rsp_auths_array->count; i++) {
        if (0 != unmarshal_tpms_authresponse(&rsp_auths_ptr, &sys_context->remaining_response, &rsp_auths_array->auths[i]))
            return TSS2_SYS_RC_MALFORMED_RESPONSE;
    }

    return TSS2_RC_SUCCESS;
}
