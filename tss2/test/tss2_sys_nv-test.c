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
    init_sapi(&ctx->sapi_ctx);
}

void cleanup(struct test_context *ctx)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;

    if (ctx->sapi_ctx != NULL) {
        TSS2_RC rc = Tss2_Sys_GetTctiContext(ctx->sapi_ctx, &tcti_context);
        TEST_ASSERT(TSS2_RC_SUCCESS == rc);

        Tss2_Tcti_Finalize(tcti_context);
        free(tcti_context);

        Tss2_Sys_Finalize(ctx->sapi_ctx);
        free(ctx->sapi_ctx);
    }
}

int define(struct test_context *ctx, int index, uint16_t size)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_NV_PUBLIC public_info = {0};
    public_info.nvPublic.nvIndex = index;
    public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;
    // TODO
    public_info.nvPublic.attributes = TPMA_NV_OWNERWRITE | TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD;
    public_info.nvPublic.authPolicy.size = 0;
    public_info.nvPublic.dataSize = size;

    uint32_t auth_handle = TPM2_RH_OWNER;

    TPM2B_AUTH nvAuth = {.size=0};

    TSS2_RC rval = Tss2_Sys_NV_DefineSpace(ctx->sapi_ctx,
                                           auth_handle,
                                           &sessionsData,
                                           &nvAuth,
                                           &public_info,
                                           &sessionsDataOut);

    return rval;
}

int get_public(struct test_context *ctx, int index, uint16_t *size_from_public)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {.count = 0};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 0};

    TPM2B_NV_PUBLIC nv_public = {0};

    TPM2B_NAME nv_name = {0};

    TSS2_RC rval = Tss2_Sys_NV_ReadPublic(ctx->sapi_ctx,
                                          index,
                                          &sessionsData,
                                          &nv_public,
                                          &nv_name,
                                          &sessionsDataOut);

    if (rval == TSS2_RC_SUCCESS) {
        *size_from_public = nv_public.nvPublic.dataSize;
    }

    return rval;
}

int undefine(struct test_context *ctx, int index)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPMI_RH_NV_INDEX nvIndex = index;

    uint32_t auth_handle = TPM2_RH_OWNER;

    TSS2_RC rval = Tss2_Sys_NV_UndefineSpace(ctx->sapi_ctx,
                                              auth_handle,
                                              nvIndex,
                                              &sessionsData,
                                              &sessionsDataOut);

    return rval;
}

int write_to_nv(struct test_context *ctx,
          uint32_t index,
          uint8_t *data,
          uint32_t data_size)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    uint32_t auth_handle = TPM2_RH_OWNER;

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

int read_from_nv(struct test_context *ctx,
         uint32_t index,
         uint8_t *data,
         uint32_t data_size)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    uint16_t data_offset = 0;
    uint32_t size = data_size;

    uint32_t auth_handle = TPM2_RH_OWNER;

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

    uint16_t size_from_public;
    int public_ret = get_public(&ctx, index, &size_from_public);
    TEST_ASSERT(0 == public_ret);
    TEST_ASSERT(size == size_from_public);

    int write_ret = write_to_nv(&ctx, index, (uint8_t*)data, data_size);
    TEST_ASSERT((int)data_size == write_ret);

    char output_data[1024];
    int read_ret = read_from_nv(&ctx, index, (uint8_t*)output_data, data_size);
    TEST_ASSERT((int)data_size == read_ret);

    TEST_ASSERT(0 == memcmp(data, output_data, data_size));

    cleanup(&ctx);

    printf("ok\n");
}

