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

#ifndef XAPTUM_TSS2INTERNAL_COMMAND_UTILS_H
#define XAPTUM_TSS2INTERNAL_COMMAND_UTILS_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss2_sys.h>

#include "sys_context_common.h"

void
build_command_header(TSS2_SYS_CONTEXT_OPAQUE *sys_context,
                     TPM2_CC command_code,
                     TPMI_ST_COMMAND_TAG sessions_code);

void
set_command_size(TSS2_SYS_CONTEXT_OPAQUE *sys_context);

#ifdef __cplusplus
}
#endif

#endif

