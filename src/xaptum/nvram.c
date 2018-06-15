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

uint16_t xtpm_gpk_length()
{
    return XTPM_GPK_LENGTH;
}

uint16_t xtpm_cred_length()
{
    return XTPM_CRED_LENGTH;
}

uint16_t xtpm_cred_sig_length()
{
    return XTPM_CRED_SIG_LENGTH;
}

uint16_t xtpm_root_id_length()
{
    return XTPM_ROOT_ID_LENGTH;
}

uint16_t xtpm_root_pubkey_length()
{
    return XTPM_ROOT_PUBKEY_LENGTH;
}

uint16_t xtpm_root_asn1cert_length()
{
    return XTPM_ROOT_ASN1CERT_LENGTH;
}

TPMI_RH_NV_INDEX xtpm_gpk_handle()
{
    return XTPM_GPK_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_cred_handle()
{
    return XTPM_CRED_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_cred_sig_handle()
{
    return XTPM_CRED_SIG_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_root_id_handle()
{
    return XTPM_ROOT_ID_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_root_pubkey_handle()
{
    return XTPM_ROOT_PUBKEY_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_root_asn1cert_handle()
{
    return XTPM_ROOT_ASN1CERT_HANDLE;
}

TSS2_RC
xtpm_read_object(unsigned char* out_buffer,
                 uint16_t out_buffer_size,
                 uint16_t *out_length,
                 enum xtpm_object_name object_name,
                 TSS2_SYS_CONTEXT *sapi_context)
{
    uint16_t size = 0;
    TPM_HANDLE index = 0;

    switch (object_name) {
        case XTPM_GROUP_PUBLIC_KEY:
            index = XTPM_GPK_HANDLE;
            size = XTPM_GPK_LENGTH;
            break;
        case XTPM_CREDENTIAL:
            index = XTPM_CRED_HANDLE;
            size = XTPM_CRED_LENGTH;
            break;
        case XTPM_CREDENTIAL_SIGNATURE:
            index = XTPM_CRED_SIG_HANDLE;
            size = XTPM_CRED_SIG_LENGTH;
            break;
        case XTPM_ROOT_ID:
            index = XTPM_ROOT_ID_HANDLE;
            size = XTPM_ROOT_ID_LENGTH;
            break;
        case XTPM_ROOT_PUBKEY:
            index = XTPM_ROOT_PUBKEY_HANDLE;
            size = XTPM_ROOT_PUBKEY_LENGTH;
            break;
        case XTPM_ROOT_ASN1_CERTIFICATE:
            index = XTPM_ROOT_ASN1CERT_HANDLE;
            size = XTPM_ROOT_ASN1CERT_LENGTH;
            break;
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

