/******************************************************************************
 *
 * Copyright 2017-2020 Xaptum, Inc.
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

#include "test-utils.h"

int define_nv(TSS2_SYS_CONTEXT *sapi_ctx, int index, uint16_t size);

int undefine_nv(TSS2_SYS_CONTEXT *sapi_ctx, int index);

int write_to_nv(TSS2_SYS_CONTEXT *sapi_ctx,
                uint32_t index,
                uint8_t *data,
                uint32_t data_size);

void constants_test(void);

void read_object_test(TSS2_TCTI_CONTEXT *tcti_ctx);

int main()
{
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    init_tcti(&tcti_ctx);

    constants_test();

    clear(tcti_ctx);
    read_object_test(tcti_ctx);

    clear(tcti_ctx);
    free_tcti(tcti_ctx);
}

void read_object_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In nvram-test::read_object_test...\n");

    TSS2_SYS_CONTEXT *sapi_ctx;
    init_sapi(tcti_ctx, &sapi_ctx);

    // Since we're creating in the platform hierarchy
    //  (which doesn't get CLEARed), allow for the index to already be defined
    undefine_nv(sapi_ctx, XTPM_GPK_HANDLE);

    uint8_t data[] = {'f', 'o', 'o', 'b', 'a', 'r'};

    int define_ret = define_nv(sapi_ctx, XTPM_GPK_HANDLE, sizeof(data));

    TEST_ASSERT(define_ret == 0);

    int write_ret = write_to_nv(sapi_ctx, XTPM_GPK_HANDLE, data, sizeof(data));
    TEST_ASSERT(write_ret == sizeof(data));

    unsigned char buf[sizeof(data)];
    uint16_t len;
    TSS2_RC read_ret = xtpm_read_object(buf, sizeof(buf), &len, XTPM_GROUP_PUBLIC_KEY, sapi_ctx);
    TEST_ASSERT(read_ret == TSS2_RC_SUCCESS);

    free_sapi(sapi_ctx);

    printf("ok\n");
}

void constants_test(void)
{
    printf("In nvram-test::constants_test...\n");

    TEST_ASSERT(XTPM_ECDAA_KEY_HANDLE == xtpm_ecdaa_key_handle());

    TEST_ASSERT(XTPM_GPK_HANDLE == xtpm_gpk_handle());

    TEST_ASSERT(XTPM_CRED_HANDLE == xtpm_cred_handle());

    TEST_ASSERT(XTPM_CRED_SIG_HANDLE == xtpm_cred_sig_handle());

    TEST_ASSERT(XTPM_ROOT_ASN1CERT_HANDLE == xtpm_root_asn1cert_handle());

    TEST_ASSERT(XTPM_BASENAME_HANDLE == xtpm_basename_handle());

    TEST_ASSERT(XTPM_SERVER_ID_HANDLE == xtpm_serverid_handle());

    TEST_ASSERT(XTPM_ROOT_XTTCERT_HANDLE == xtpm_root_xttcert_handle());

    printf("ok\n");
}

int define_nv(TSS2_SYS_CONTEXT *sapi_ctx, int index, uint16_t size)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_NV_PUBLIC public_info = {0};
    public_info.nvPublic.nvIndex = index;
    public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;
    public_info.nvPublic.attributes = TPMA_NV_PPWRITE | TPMA_NV_AUTHREAD | TPMA_NV_PLATFORMCREATE;
    public_info.nvPublic.authPolicy.size = 0;
    public_info.nvPublic.dataSize = size;

    uint32_t auth_handle = TPM2_RH_PLATFORM;

    TPM2B_AUTH nvAuth = {.size=0};

    TSS2_RC rval = Tss2_Sys_NV_DefineSpace(sapi_ctx,
                                           auth_handle,
                                           &sessionsData,
                                           &nvAuth,
                                           &public_info,
                                           &sessionsDataOut);

    return rval;
}

int undefine_nv(TSS2_SYS_CONTEXT *sapi_ctx, int index)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPMI_RH_NV_INDEX nvIndex = index;

    uint32_t auth_handle = TPM2_RH_PLATFORM;

    TSS2_RC rval = Tss2_Sys_NV_UndefineSpace(sapi_ctx,
                                             auth_handle,
                                             nvIndex,
                                             &sessionsData,
                                             &sessionsDataOut);

    return rval;
}

int write_to_nv(TSS2_SYS_CONTEXT *sapi_ctx,
                uint32_t index,
                uint8_t *data,
                uint32_t data_size)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    uint32_t auth_handle = TPM2_RH_PLATFORM;

    TPM2B_MAX_NV_BUFFER nv_write_data;

    uint32_t size = data_size;
    uint16_t data_offset = 0;

    while (size > 0) {
        nv_write_data.size = size;

        memcpy(nv_write_data.buffer, &data[data_offset], nv_write_data.size);

        TSS2_RC rval = Tss2_Sys_NV_Write(sapi_ctx,
                                         auth_handle,
                                         index,
                                         &sessionsData,
                                         &nv_write_data,
                                         data_offset,
                                         &sessionsDataOut);
        if (rval != TSS2_RC_SUCCESS) {
            return -1;
        }

        size -= nv_write_data.size;
        data_offset += nv_write_data.size;
    }

    return data_size;
}
