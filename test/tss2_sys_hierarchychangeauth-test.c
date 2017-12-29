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
#include <stdio.h>
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

void full_test()
{
    printf("In tss2_sys_hierarchychangeauth-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TPMI_RH_HIERARCHY hierarchy = TPM_RH_ENDORSEMENT;

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

    const char* new_password = "pass";
    size_t new_password_length = strlen(new_password);
    TPM2B_AUTH newAuth = {.size=new_password_length};
    memcpy(newAuth.buffer, new_password, new_password_length);

    TSS2_RC ret = Tss2_Sys_HierarchyChangeAuth(ctx.sapi_ctx,
                                               hierarchy,
                                               &sessionsData,
                                               &newAuth,
                                               &sessionsDataOut);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    // Now, change password back to empty (in case other tests get run after this).
    session_data.hmac.size = new_password_length;
    memcpy(session_data.hmac.buffer, new_password, new_password_length);
    newAuth.size = 0;
    ret = Tss2_Sys_HierarchyChangeAuth(ctx.sapi_ctx,
                                       hierarchy,
                                       &sessionsData,
                                       &newAuth,
                                       &sessionsDataOut);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    cleanup(&ctx);

    printf("ok\n");
}

