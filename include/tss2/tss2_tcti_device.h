/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
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

#ifndef XAPTUM_TPM_TSS2_TCTI_DEVICE_H
#define XAPTUM_TPM_TSS2_TCTI_DEVICE_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tss2/tss2_tcti.h>

#include <stddef.h>

size_t
tss2_tcti_getsize_device();

TSS2_RC
tss2_tcti_init_device(const char *dev_file_path,
                      size_t dev_file_path_length,
                      TSS2_TCTI_CONTEXT *tcti_context);

#ifdef __cplusplus
}
#endif

#endif

