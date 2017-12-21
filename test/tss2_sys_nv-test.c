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

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_socket.h>

#include "test-utils.h"

#include <stdlib.h>
#include <string.h>

struct test_context {
    TSS2_SYS_CONTEXT *sapi_ctx;
};

static void initialize(struct test_context *ctx);
static void cleanup(struct test_context *ctx);

static void full_test();

int main(int argc, char *argv[])
{
    parse_cmd_args(argc, argv);

    full_test();
}

void initialize(struct test_context *ctx)
{
    size_t tcti_ctx_size = tss2_tcti_getsize_socket();

    TSS2_TCTI_CONTEXT *tcti_ctx = malloc(tcti_ctx_size);
    TEST_EXPECT(NULL != tcti_ctx);
    
    TSS2_RC init_ret;

    init_ret = tss2_tcti_init_socket(hostname_g, port_g, tcti_ctx);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);

    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);

    ctx->sapi_ctx = malloc(sapi_ctx_size);
    TEST_EXPECT(NULL != ctx->sapi_ctx);
    
    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    init_ret = Tss2_Sys_Initialize(ctx->sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);
}

void cleanup(struct test_context *ctx)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    if (ctx->sapi_ctx != NULL) {
        rc = Tss2_Sys_GetTctiContext(ctx->sapi_ctx, &tcti_context);
        TEST_ASSERT(TSS2_RC_SUCCESS == rc);

        tss2_tcti_finalize(tcti_context);
        free(tcti_context);

        Tss2_Sys_Finalize(ctx->sapi_ctx);
        free(ctx->sapi_ctx);
    }
}

int define(struct test_context *ctx, int index, uint16_t size)
{
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

    TPM2B_NV_PUBLIC public_info = {0};
    public_info.nvPublic.nvIndex = index;
    public_info.nvPublic.nameAlg = TPM_ALG_SHA256;
    // TODO
    public_info.nvPublic.attributes.TPMA_OWNERWRITE = 1;
    public_info.nvPublic.attributes.TPMA_POLICYWRITE = 1;
    public_info.nvPublic.attributes.TPMA_OWNERREAD = 1;
    public_info.nvPublic.authPolicy.size = 0;
    public_info.nvPublic.dataSize = size;

    uint32_t auth_handle = TPM_RH_OWNER;

    TPM2B_AUTH nvAuth = {.size=0};

    TSS2_RC rval = Tss2_Sys_NV_DefineSpace(ctx->sapi_ctx,
                                           auth_handle,
                                           &sessionsData,
                                           &nvAuth,
                                           &public_info,
                                           &sessionsDataOut);

    return rval;
}

int undefine(struct test_context *ctx, int index)
{
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

    TPMI_RH_NV_INDEX nvIndex = index;

    uint32_t auth_handle = TPM_RH_OWNER;

    TSS2_RC rval = Tss2_Sys_NV_UndefineSpace(ctx->sapi_ctx,
                                              auth_handle,
                                              nvIndex,
                                              &sessionsData,
                                              &sessionsDataOut);

    return rval;
}

int write(struct test_context *ctx,
          uint32_t index,
          uint8_t *data,
          uint32_t data_size)
{
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

    uint32_t auth_handle = TPM_RH_OWNER;

    TPM2B_MAX_NV_BUFFER nv_write_data;

    uint32_t size = data_size;
    uint16_t data_offset = 0;

    while (size > 0) {
        nv_write_data.size = size;

        memcpy(nv_write_data.buffer, &data[data_offset], nv_write_data.size);

        TSS2_RC rval = Tss2_Sys_NV_Write(ctx->sapi_ctx,
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

int read(struct test_context *ctx,
         uint32_t index,
         uint8_t *data,
         uint32_t data_size)
{
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
    uint32_t size = data_size;

    uint32_t auth_handle = TPM_RH_OWNER;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        TSS2_RC rval = Tss2_Sys_NV_Read(ctx->sapi_ctx,
                                        auth_handle,
                                        index,
                                        &sessionsData,
                                        bytes_to_read,
                                        data_offset,
                                        &nv_data,
                                        &sessionsDataOut);

        if (rval != TSS2_RC_SUCCESS) {
            return -1;
        }

        size -= nv_data.size;

        memcpy(data + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

    return data_size;
}
void full_test()
{
    printf("In tss2_sys_nv-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    uint32_t index = 0x1600001;
    uint32_t size = 32;
    const char *data = "test data"; // less than size, so it will fit
    uint32_t data_size = strlen(data);

    int undefine_ret = undefine(&ctx, index);
    TEST_ASSERT(0 == undefine_ret || 0x28b == undefine_ret);    // 28b is returned if index wasn't defined already

    int define_ret = define(&ctx, index, size);
    TEST_ASSERT(0 == define_ret);

    int write_ret = write(&ctx, index, (uint8_t*)data, data_size);
    TEST_ASSERT((int)data_size == write_ret);

    char output_data[1024];
    int read_ret = read(&ctx, index, (uint8_t*)output_data, data_size);
    TEST_ASSERT((int)data_size == read_ret);

    TEST_ASSERT(0 == memcmp(data, output_data, data_size));

    cleanup(&ctx);

    printf("ok\n");
}

