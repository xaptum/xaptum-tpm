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

#ifndef XAPTUM_TPM_NVRAM_H
#define XAPTUM_TPM_NVRAM_H
#pragma once

#include <tss2/tss2_sys.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XTPM_ECDAA_KEY_HANDLE       0x81800000
#define XTPM_GPK_HANDLE             0x1410000
#define XTPM_CRED_HANDLE            0x1410001
#define XTPM_CRED_SIG_HANDLE        0x1410002
#define XTPM_ROOT_ASN1CERT_HANDLE   0x1410005
#define XTPM_BASENAME_HANDLE        0x1410007
#define XTPM_SERVER_ID_HANDLE       0x1410008
#define XTPM_ROOT_XTTCERT_HANDLE    0x1410009

TPM2_HANDLE xtpm_ecdaa_key_handle();
TPMI_RH_NV_INDEX xtpm_gpk_handle();
TPMI_RH_NV_INDEX xtpm_cred_handle();
TPMI_RH_NV_INDEX xtpm_cred_sig_handle();
TPMI_RH_NV_INDEX xtpm_root_asn1cert_handle();
TPMI_RH_NV_INDEX xtpm_basename_handle();
TPMI_RH_NV_INDEX xtpm_serverid_handle();
TPMI_RH_NV_INDEX xtpm_root_xttcert_handle();

enum xtpm_object_name {
    XTPM_GROUP_PUBLIC_KEY,
    XTPM_CREDENTIAL,
    XTPM_CREDENTIAL_SIGNATURE,
    XTPM_ROOT_ASN1_CERTIFICATE,
    XTPM_BASENAME,
    XTPM_SERVER_ID,
    XTPM_ROOT_XTT_CERTIFICATE,
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
                TPM2_HANDLE index,
                TSS2_SYS_CONTEXT *sapi_context);

TSS2_RC
xtpm_get_nvram_size(uint16_t *size_out,
                    TPM2_HANDLE index,
                    TSS2_SYS_CONTEXT *sapi_context);

#ifdef __cplusplus
}
#endif

#endif

