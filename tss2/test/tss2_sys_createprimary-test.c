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
static int clear(struct test_context *ctx);

static void full_test();

int main(int argc, char *argv[])
{
    parse_cmd_args(argc, argv);

    full_test(pub_key_filename_g, handle_filename_g);
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

void full_test(const char* pub_key_filename, const char* handle_filename)
{
    printf("In tss2_sys_createprimary-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TEST_ASSERT(0 == clear(&ctx));

    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_ENDORSEMENT;

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_SENSITIVE_CREATE inSensitive = {.sensitive={.data.size = 0,
                                                      .userAuth.size = 0}};

    TPMA_OBJECT obj_attrs = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT;
    TPM2B_PUBLIC in_public = {.publicArea = {.type=TPM2_ALG_ECC,
                                             .nameAlg=TPM2_ALG_SHA256,
                                             .objectAttributes=obj_attrs}};
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDAA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM2_ALG_SHA256;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.count = 1;
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_BN_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    in_public.publicArea.unique.ecc.x.size = 0;
    in_public.publicArea.unique.ecc.y.size = 0;

    TPM2B_DATA outsideInfo = {.size=0};

    TPML_PCR_SELECTION creationPCR = {.count=0};

    TPM2B_CREATION_DATA creationData = {.size=0};
    TPM2B_DIGEST creationHash = {.size=sizeof(TPMU_HA)};
    TPMT_TK_CREATION creationTicket = {.tag=0,
		                               .hierarchy=0,
		                               .digest={.size=0}};

    TPM2B_NAME name = {.size=sizeof(TPMU_NAME)};

    TPM2_HANDLE key_handle;
    TPM2B_PUBLIC public_key; 

    TSS2_RC ret = Tss2_Sys_CreatePrimary(ctx.sapi_ctx,
                                                           hierarchy,
                                                           &sessionsData,
                                                           &inSensitive,
                                                           &in_public,
                                                           &outsideInfo,
                                                           &creationPCR,
                                                           &key_handle,
                                                           &public_key,
                                                           &creationData,
                                                           &creationHash,
                                                           &creationTicket,
                                                           &name,
                                                           &sessionsDataOut);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    int write_ret = 0;

    FILE *pub_key_file_ptr = fopen(pub_key_filename, "w");
    if (NULL == pub_key_file_ptr)
        return;
    do {
        if (fprintf(pub_key_file_ptr, "%02X", 4) != 2)
            break;

        for (unsigned i=0; i < public_key.publicArea.unique.ecc.x.size; i++) {
            if (fprintf(pub_key_file_ptr, "%02X", public_key.publicArea.unique.ecc.x.buffer[i]) != 2) {
                write_ret = -1;
                break;
            }
        }
        if (0 != write_ret)
            break;

        for (unsigned i=0; i < public_key.publicArea.unique.ecc.y.size; i++) {
            if (fprintf(pub_key_file_ptr, "%02X", public_key.publicArea.unique.ecc.y.buffer[i]) != 2) {
                write_ret = -1;
                break;
            }
        }
        if (0 != write_ret)
            break;
    } while(0);
    (void)fclose(pub_key_file_ptr);

    (void)handle_filename;
    FILE *handle_file_ptr = fopen(handle_filename, "w");
    if (NULL == handle_file_ptr)
        return;
    write_ret = 0;
    do {
        for (int i=(sizeof(key_handle)-1); i >= 0; i--) {
            if (fprintf(handle_file_ptr, "%02X", (key_handle >> i*8) & 0xFF) != 2) {
                write_ret = -1;
                break;
            }
        }
        if (0 != write_ret)
            break;
    } while(0);
    (void)fclose(handle_file_ptr);

    cleanup(&ctx);

    TEST_ASSERT(0 == write_ret);

    printf("ok\n");
}

int clear(struct test_context *ctx)
{
    TPMI_RH_CLEAR auth_handle = TPM2_RH_LOCKOUT;

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TSS2_RC ret = Tss2_Sys_Clear(ctx->sapi_ctx,
                                 auth_handle,
                                 &sessionsData,
                                 &sessionsDataOut);

    printf("Clear ret=%#X\n", ret);

    return ret;
}
