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

#ifndef XAPTUM_TSS2INTERNAL_CMDAUTHS_H
#define XAPTUM_TSS2INTERNAL_CMDAUTHS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss2_sys.h>

#include "sys_context_common.h"

TSS2_RC
set_cmdauths(TSS2_SYS_CONTEXT_OPAQUE *sys_context,
             const TSS2L_SYS_AUTH_COMMAND *cmd_auths_array);

TSS2_RC
get_rspauths(TSS2_SYS_CONTEXT_OPAQUE *sys_context,
             TSS2L_SYS_AUTH_RESPONSE *rsp_auths_array);

#ifdef __cplusplus
}
#endif

#endif

