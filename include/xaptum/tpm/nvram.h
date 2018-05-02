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

#ifndef XAPTUM_TPM_XAPTUMNVRAM_H
#define XAPTUM_TPM_XAPTUMNVRAM_H
#pragma once

#include <tss2/tss2_sys.h>

#ifdef __cplusplus
extern "C" {
#endif

enum xtpm_object_name {
    XTPM_GROUP_PUBLIC_KEY,
    XTPM_CREDENTIAL,
    XTPM_CREDENTIAL_SIGNATURE,
    XTPM_ROOT_ID,
    XTPM_ROOT_PUBKEY,
    XTPM_ROOT_ASN1_CERTIFICATE
};

TSS2_RC
xtpm_read_object(unsigned char* out_buffer,
                 uint16_t out_buffer_size,
                 uint16_t *out_length,
                 enum xtpm_object_name object_name,
                 TSS2_SYS_CONTEXT *sapi_context);

TSS2_RC
xtpm_read_nvram(unsigned char *out,
                uint16_t size,
                TPM_HANDLE index,
                TSS2_SYS_CONTEXT *sapi_context);


#ifdef __cplusplus
}
#endif

#endif

