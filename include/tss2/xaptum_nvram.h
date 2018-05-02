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

#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tpm2_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GPK_LENGTH 258
#define CRED_LENGTH 260
#define CRED_SIG_LENGTH 64
#define ROOT_ID_LENGTH 16
#define ROOT_PUBKEY_LENGTH 32
#define ROOT_ASN1CERT_LENGTH 276

TPMI_RH_NV_INDEX xtpm_gpk_handle_g = 0x1410000;
TPMI_RH_NV_INDEX xtpm_cred_handle_g = 0x1410001;
TPMI_RH_NV_INDEX xtpm_cred_sig_handle_g = 0x1410002;
TPMI_RH_NV_INDEX xtpm_root_id_handle_g = 0x1410003;
TPMI_RH_NV_INDEX xtpm_root_pubkey_handle_g = 0x1410004;
TPMI_RH_NV_INDEX xtpm_root_asn1cert_handle_g = 0x1410005;

TSS2_RC
xtpm_read_nvram(unsigned char *out,
                uint16_t size,
                TPM_HANDLE index,
                TSS2_TCTI_CONTEXT *tcti_context);


#ifdef __cplusplus
}
#endif

#endif

