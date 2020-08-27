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

/******************************************************************************
 *
 * This implementation is blocking ONLY.
 * Also, all buffers are assumed to be large enough,
 * and pointers are NOT checked for NULL.
 *
 *****************************************************************************/

#ifndef XAPTUM_TSS2_TCTI_MSSIM_H
#define XAPTUM_TSS2_TCTI_MSSIM_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss2_tcti.h>

#include <stddef.h>

TSS2_RC
Tss2_Tcti_Mssim_Init(TSS2_TCTI_CONTEXT *tcti_context,
                     size_t *size,
                     const char *conf);

#ifdef __cplusplus
}
#endif

#endif

