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
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>

#include "test-utils.h"

#include <stdlib.h>

struct test_context {
    TSS2_SYS_CONTEXT *sapi_ctx;
};

static void initialize(struct test_context *ctx);
static void cleanup(struct test_context *ctx);

static void init_test();

int main(int argc, char *argv[])
{
    parse_cmd_args(argc, argv);

    init_test();
}

void initialize(struct test_context *ctx)
{
    TSS2_RC init_ret;

#ifdef USE_TCP_TPM
    size_t ctx_size;
    init_ret = Tss2_Tcti_Mssim_Init(NULL, &ctx_size, mssim_conf_g);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);

    TSS2_TCTI_CONTEXT * tcti_ctx = malloc(ctx_size);
    TEST_ASSERT(NULL != tcti_ctx);

    init_ret = Tss2_Tcti_Mssim_Init(tcti_ctx, &ctx_size, mssim_conf_g);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);
#else
    size_t ctx_size;
    init_ret = Tss2_Tcti_Device_Init(NULL, &ctx_size, mssim_conf_g);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);

    TSS2_TCTI_CONTEXT * tcti_ctx = malloc(ctx_size);
    TEST_ASSERT(NULL != tcti_ctx);

    init_ret = Tss2_Tcti_Device_Init(tcti_ctx, &ctx_size, dev_file_path_g);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);
#endif

    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);

    ctx->sapi_ctx = malloc(sapi_ctx_size);
    TEST_EXPECT(NULL != ctx->sapi_ctx);

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    init_ret = Tss2_Sys_Initialize(ctx->sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);
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

void init_test()
{
    printf("In tss2_sys_context-test::init_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    cleanup(&ctx);

    printf("ok\n");
}

