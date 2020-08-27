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

void full_test()
{
    printf("In tss2_sys_hierarchychangeauth-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_ENDORSEMENT;

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

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
    sessionsData.auths[0].hmac.size = new_password_length;
    memcpy(sessionsData.auths[0].hmac.buffer, new_password, new_password_length);
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

