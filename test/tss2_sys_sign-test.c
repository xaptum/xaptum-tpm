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
    TPM_HANDLE key_handle;
    uint16_t counter;
};

static void initialize(struct test_context *ctx);
static void cleanup(struct test_context *ctx);
static int clear(struct test_context *ctx);
static int createprimary(struct test_context *ctx);

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

    TEST_ASSERT(0 == createprimary(ctx));
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

int createprimary(struct test_context *ctx)
{
    printf("In tss2_sys_createprimary-test::full_test...\n");

    TEST_ASSERT(0 == clear(ctx));

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

    TPM2B_PUBLIC public_key; 

    TSS2_RC ret = Tss2_Sys_CreatePrimary(ctx->sapi_ctx,
                                                           hierarchy,
                                                           &sessionsData,
                                                           &inSensitive,
                                                           &in_public,
                                                           &outsideInfo,
                                                           &creationPCR,
                                                           &ctx->key_handle,
                                                           &public_key,
                                                           &creationData,
                                                           &creationHash,
                                                           &creationTicket,
                                                           &name,
                                                           &sessionsDataOut);

    if (TSS2_RC_SUCCESS != ret)
        return -1;

    return 0;
}

int commit(struct test_context *ctx)
{
    TPM2B_ECC_POINT P1_tpm = {.size=0};
    TPM2B_SENSITIVE_DATA s2_tpm = {.size=0};
    TPM2B_ECC_PARAMETER y2_tpm = {.size=0};
    TPM2B_ECC_POINT K_tpm = {.size=0};
    TPM2B_ECC_POINT L_tpm = {.size=0};
    TPM2B_ECC_POINT E_tpm = {.size=0};

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

    TSS2_RC ret = Tss2_Sys_Commit(ctx->sapi_ctx,
                                  ctx->key_handle,
                                  &sessionsData,
                                  &P1_tpm,
                                  &s2_tpm,
                                  &y2_tpm,
                                  &K_tpm,
                                  &L_tpm,
                                  &E_tpm,
                                  &ctx->counter,
                                  &sessionsDataOut);

    printf("After call to TPM2_Commit, counter=%u\n", ctx->counter);

    if (TSS2_RC_SUCCESS == ret) {
        return 0;
    } else {
        return -1;
    }
}

void full_test()
{
    printf("In tss2_sys_commit-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TEST_ASSERT(0 == commit(&ctx));

    // Nb. digest == 0
    TPM2B_DIGEST digest = {.size=32, .buffer={0}};

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

    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM_ALG_ECDAA;
	inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
	inScheme.details.ecdaa.count = ctx.counter;

    TPMT_TK_HASHCHECK validation;
	validation.tag = TPM_ST_HASHCHECK;
	validation.hierarchy = TPM_RH_NULL;
	validation.digest.size = 0;

    TPMT_SIGNATURE signature;

    TSS2_RC ret = Tss2_Sys_Sign(ctx.sapi_ctx,
                  ctx.key_handle,
                  &sessionsData,
                  &digest,
                  &inScheme,
                  &validation,
                  &signature,
                  &sessionsDataOut);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    TEST_ASSERT(digest.size != 0);
    TEST_ASSERT(digest.size == signature.signature.ecdaa.signatureR.size);
    TEST_ASSERT(memcmp(digest.buffer, signature.signature.ecdaa.signatureR.buffer, digest.size) == 0);

    TEST_ASSERT(signature.signature.ecdaa.signatureS.size != 0);
    uint8_t zeroes[64];
    memset(zeroes, 0, sizeof(zeroes));
    TEST_ASSERT(memcmp(zeroes, signature.signature.ecdaa.signatureS.buffer, signature.signature.ecdaa.signatureS.size) != 0);

    printf("After TPM2_Sign, signatureS={");
    for (uint16_t i=0; i < signature.signature.ecdaa.signatureS.size; i++) {
        printf("%#X", signature.signature.ecdaa.signatureS.buffer[i]);
        if (i != (signature.signature.ecdaa.signatureS.size - 1)) {
            printf(", ");
        } else {
            printf("}\n");
        }
    }

    cleanup(&ctx);

    printf("ok\n");
}

int clear(struct test_context *ctx)
{
   TPMI_RH_CLEAR auth_handle = TPM_RH_PLATFORM;

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
