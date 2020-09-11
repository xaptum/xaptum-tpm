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
    TPM2_HANDLE key_handle;
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
    init_sapi(&ctx->sapi_ctx);

    TEST_ASSERT(0 == createprimary(ctx));
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

int createprimary(struct test_context *ctx)
{
    printf("In tss2_sys_createprimary-test::full_test...\n");

    TEST_ASSERT(0 == clear(ctx));

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

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

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

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM2_ALG_ECDAA;
	inScheme.details.ecdaa.hashAlg = TPM2_ALG_SHA256;
	inScheme.details.ecdaa.count = ctx.counter;

    TPMT_TK_HASHCHECK validation;
	validation.tag = TPM2_ST_HASHCHECK;
	validation.hierarchy = TPM2_RH_NULL;
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

    TEST_ASSERT(signature.signature.ecdaa.signatureR.size != 0);

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
