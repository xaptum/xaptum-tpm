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

#include <xaptum/tpm/nvram.h>

#include <tss2/tss2_sys.h>

#include <string.h>

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
xtpm_read_object(unsigned char* out_buffer,
                 uint16_t out_buffer_size,
                 uint16_t *out_length,
                 enum xtpm_object_name object_name,
                 TSS2_SYS_CONTEXT *sapi_context)
{
    uint16_t size;
    TPM_HANDLE index;

    switch (object_name) {
        case XTPM_GROUP_PUBLIC_KEY:
            index = xtpm_gpk_handle_g;
            size = GPK_LENGTH;
            break;
        case XTPM_CREDENTIAL:
            index = xtpm_cred_handle_g;
            size = CRED_LENGTH;
            break;
        case XTPM_CREDENTIAL_SIGNATURE:
            index = xtpm_cred_sig_handle_g;
            size = CRED_SIG_LENGTH;
            break;
        case XTPM_ROOT_ID:
            index = xtpm_root_id_handle_g;
            size = ROOT_ID_LENGTH;
            break;
        case XTPM_ROOT_PUBKEY:
            index = xtpm_root_pubkey_handle_g;
            size = ROOT_PUBKEY_LENGTH;
            break;
        case XTPM_ROOT_ASN1_CERTIFICATE:
            index = xtpm_root_asn1cert_handle_g;
            size = ROOT_ASN1CERT_LENGTH;
            break;
        default:
            return TSS2_BASE_RC_GENERAL_FAILURE;
    }

    if (out_buffer_size < size)
        return TSS2_BASE_RC_INSUFFICIENT_BUFFER;

    *out_length = size;

    return xtpm_read_nvram(out_buffer, size, index, sapi_context);
}

TSS2_RC
xtpm_read_nvram(unsigned char *out,
                uint16_t size,
                TPM_HANDLE index,
                TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    // We (Xaptum) set AUTHREAD and no password.
    //  This means anyone can read,
    //  by using an empty password and passing the index itself as the auth handle.
    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    uint16_t data_offset = 0;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        ret = Tss2_Sys_NV_Read(sapi_context,
                               index,
                               index,
                               &sessionsData,
                               bytes_to_read,
                               data_offset,
                               &nv_data,
                               &sessionsDataOut);

        if (ret != TSS2_RC_SUCCESS) {
            return ret;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

    return ret;
}

