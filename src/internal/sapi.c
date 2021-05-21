/******************************************************************************
 *
 * Copyright 2020 Xaptum, Inc.
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

#include "sapi.h"

#include <stdlib.h>

TSS2_RC
init_sapi(TSS2_SYS_CONTEXT **sapi_ctx, TSS2_TCTI_CONTEXT *tcti_ctx)
{
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);

    *sapi_ctx = malloc(sapi_ctx_size);
    if (NULL == *sapi_ctx) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    TSS2_RC init_ret = Tss2_Sys_Initialize(*sapi_ctx,
                                           sapi_ctx_size,
                                           tcti_ctx,
                                           &abi_version);

    if (TSS2_RC_SUCCESS != init_ret) {
        free(*sapi_ctx);
        *sapi_ctx = NULL;
    }

    return init_ret;
}
