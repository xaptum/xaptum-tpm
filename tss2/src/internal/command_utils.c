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

#include "command_utils.h"

#include "marshal.h"

void
build_command_header(TSS2_SYS_CONTEXT_OPAQUE *sys_context,
                     TPM2_CC command_code,
                     TPMI_ST_COMMAND_TAG sessions_code)
{
    reset_sys_context(sys_context);

    marshal_uint16(sessions_code, &sys_context->ptr);
    sys_context->ptr += sizeof(uint32_t); // command size must be set later, so skip it
    marshal_uint32(command_code, &sys_context->ptr);
}

void
set_command_size(TSS2_SYS_CONTEXT_OPAQUE *sys_context)
{
    uint8_t *size_ptr = sys_context->buffer + sizeof(uint16_t); // command size is after command tag
    marshal_uint32(sys_context->ptr - sys_context->buffer, &size_ptr);
}
