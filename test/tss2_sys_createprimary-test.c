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
#include <tss2/tss2_tcti_device.h>

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
    TSS2_RC init_ret;

#ifdef USE_TCP_TPM
    size_t tcti_ctx_size = tss2_tcti_getsize_socket();

    TSS2_TCTI_CONTEXT *tcti_ctx = malloc(tcti_ctx_size);
    TEST_EXPECT(NULL != tcti_ctx);

    init_ret = tss2_tcti_init_socket(hostname_g, port_g, tcti_ctx);
#else
    size_t tcti_ctx_size = tss2_tcti_getsize_device();

    TSS2_TCTI_CONTEXT *tcti_ctx = malloc(tcti_ctx_size);
    TEST_EXPECT(NULL != tcti_ctx);

    init_ret = tss2_tcti_init_device(dev_file_path_g, dev_file_path_length_g, tcti_ctx);
#endif
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

void full_test(const char* pub_key_filename, const char* handle_filename)
{
    printf("In tss2_sys_createprimary-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TEST_ASSERT(0 == clear(&ctx));

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

    TPM2B_SENSITIVE_CREATE inSensitive = {.sensitive={.data.size = 0,
                                                      .userAuth.size = 0}};

    TPMA_OBJECT obj_attrs = {.fixedTPM=1, .fixedParent=1, .sensitiveDataOrigin=1, .userWithAuth=1, .sign=1};
    TPM2B_PUBLIC in_public = {.publicArea = {.type=TPM_ALG_ECC,
                                             .nameAlg=TPM_ALG_SHA256,
                                             .objectAttributes=obj_attrs}};
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdaa.count = 1;
    in_public.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
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

    TPM_HANDLE key_handle;
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
   TPMI_RH_CLEAR auth_handle = TPM_RH_LOCKOUT;

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

    TSS2_RC ret = Tss2_Sys_Clear(ctx->sapi_ctx,
                                 auth_handle,
                                 &sessionsData,
                                 &sessionsDataOut);

    printf("Clear ret=%#X\n", ret);

    return ret;
}
