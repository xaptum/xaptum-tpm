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

#ifndef XAPTUM_TSS2SYS_CONTEXT_COMMON_H
#define XAPTUM_TSS2SYS_CONTEXT_COMMON_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss2_sys.h>

typedef struct {
    uint8_t buffer[TPM2_MAX_COMMAND_SIZE];
    TSS2_TCTI_CONTEXT *tcti_context;
    uint8_t *ptr;
    TSS2_RC response_code;
    uint32_t response_length;
    uint32_t remaining_response;
    uint8_t cmd_auths_count;
} TSS2_SYS_CONTEXT_OPAQUE;

inline
TSS2_SYS_CONTEXT_OPAQUE* down_cast(TSS2_SYS_CONTEXT *sysContext)
{
    return (TSS2_SYS_CONTEXT_OPAQUE*)sysContext;
}

inline
void reset_sys_context(TSS2_SYS_CONTEXT_OPAQUE *sys_context)
{
    sys_context->ptr = sys_context->buffer;
    sys_context->response_code = TSS2_RC_SUCCESS;
    sys_context->response_length = 0;
    sys_context->remaining_response = 0;
    sys_context->cmd_auths_count = 0;
}

#ifdef __cplusplus
}
#endif

#endif

