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

#include <xaptum-tpm/nvram.h>

#include <tss2/tss2_sys.h>

#include <string.h>

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

TPMI_RH_NV_INDEX xtpm_root_asn1cert_handle()
{
    return XTPM_ROOT_ASN1CERT_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_basename_handle()
{
    return XTPM_BASENAME_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_serverid_handle()
{
    return XTPM_SERVER_ID_HANDLE;
}

TPMI_RH_NV_INDEX xtpm_root_xttcert_handle()
{
    return XTPM_ROOT_XTTCERT_HANDLE;
}

TSS2_RC
xtpm_read_object(unsigned char* out_buffer,
                 uint16_t out_buffer_size,
                 uint16_t *out_length,
                 enum xtpm_object_name object_name,
                 TSS2_SYS_CONTEXT *sapi_context)
{
    TPM2_HANDLE index = 0;

    switch (object_name) {
        case XTPM_GROUP_PUBLIC_KEY:
            index = XTPM_GPK_HANDLE;
            break;
        case XTPM_CREDENTIAL:
            index = XTPM_CRED_HANDLE;
            break;
        case XTPM_CREDENTIAL_SIGNATURE:
            index = XTPM_CRED_SIG_HANDLE;
            break;
        case XTPM_ROOT_ASN1_CERTIFICATE:
            index = XTPM_ROOT_ASN1CERT_HANDLE;
            break;
        case XTPM_BASENAME:
            index = XTPM_BASENAME_HANDLE;
            break;
        case XTPM_SERVER_ID:
            index = XTPM_SERVER_ID_HANDLE;
            break;
        case XTPM_ROOT_XTT_CERTIFICATE:
            index = XTPM_ROOT_XTTCERT_HANDLE;
            break;
    }

    uint16_t size = 0;
    TSS2_RC ret = xtpm_get_nvram_size(&size, index, sapi_context);
    if (TSS2_RC_SUCCESS != ret)
        return ret;

    if (out_buffer_size < size)
        return TSS2_BASE_RC_INSUFFICIENT_BUFFER;

    *out_length = size;

    return xtpm_read_nvram(out_buffer, size, index, sapi_context);
}

TSS2_RC
xtpm_read_nvram(unsigned char *out,
                uint16_t size,
                TPM2_HANDLE index,
                TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    // Assume no password required.
    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .auths[0] = {.sessionHandle = TPM2_RS_PW,
            .nonce = {.size = 0},
            .sessionAttributes = 0,
            .hmac = {.size = 0}
        },
        .count = 1
    };

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    sessionsDataOut.count = 1;

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

TSS2_RC
xtpm_get_nvram_size(uint16_t *size_out,
                    TPM2_HANDLE index,
                    TSS2_SYS_CONTEXT *sapi_context)
{
    TPM2B_NV_PUBLIC nv_public = {0};

    TPM2B_NAME nv_name = {0};

    TSS2_RC rval = Tss2_Sys_NV_ReadPublic(sapi_context,
                                          index,
                                          NULL,
                                          &nv_public,
                                          &nv_name,
                                          NULL);

    if (rval == TSS2_RC_SUCCESS) {
        *size_out = nv_public.nvPublic.dataSize;
    }

    return rval;
}
