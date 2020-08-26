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
    printf("In tss2_sys_sign-secp256-test::createprimary...\n");

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
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
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

    printf("public_key=04");
    for (unsigned i=0; i < public_key.publicArea.unique.ecc.x.size; i++) {
        printf("%02X", public_key.publicArea.unique.ecc.x.buffer[i]);
    }

    for (unsigned i=0; i < public_key.publicArea.unique.ecc.y.size; i++) {
        printf("%02X", public_key.publicArea.unique.ecc.y.buffer[i]);
    }
    printf("\n");

    return 0;
}

void full_test()
{
    printf("In tss2_sys_sign-secp256-test::full_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    // digest = sha-256("foo")
    TPM2B_DIGEST digest = {.size=32, .buffer={0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}};

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM2_ALG_ECDSA;
	inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;

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

    printf("Tss2_Sys_Sign ret = %#02X\n", ret);
    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    uint8_t zeroes[64] = {};

    TEST_ASSERT(digest.size != 0);
    TEST_ASSERT(digest.size == signature.signature.ecdsa.signatureR.size);
    TEST_ASSERT(memcmp(zeroes, signature.signature.ecdsa.signatureR.buffer, signature.signature.ecdsa.signatureR.size) != 0);

    TEST_ASSERT(signature.signature.ecdsa.signatureS.size != 0);
    memset(zeroes, 0, sizeof(zeroes));
    TEST_ASSERT(memcmp(zeroes, signature.signature.ecdsa.signatureS.buffer, signature.signature.ecdsa.signatureS.size) != 0);

    printf("After TPM2_Sign, signatureR=");
    for (uint16_t i=0; i < signature.signature.ecdsa.signatureR.size; i++) {
        printf("%02X", signature.signature.ecdsa.signatureR.buffer[i]);
    }
    printf("\n");

    printf("After TPM2_Sign, signatureS=");
    for (uint16_t i=0; i < signature.signature.ecdsa.signatureS.size; i++) {
        printf("%02X", signature.signature.ecdsa.signatureS.buffer[i]);
    }
    printf("\n");

    // Do another signature, and make sure they're different
    //  (the randomized value in the signature must be truly random, so this is a poor test of a very important aspect of ECDSA).
    TPMT_SIGNATURE signature2;

    ret = Tss2_Sys_Sign(ctx.sapi_ctx,
                  ctx.key_handle,
                  &sessionsData,
                  &digest,
                  &inScheme,
                  &validation,
                  &signature2,
                  &sessionsDataOut);
    TEST_ASSERT(TSS2_RC_SUCCESS == ret);
    TEST_ASSERT(0 != memcmp(signature2.signature.ecdsa.signatureR.buffer, signature.signature.ecdsa.signatureR.buffer, signature.signature.ecdsa.signatureR.size));
    TEST_ASSERT(0 != memcmp(signature2.signature.ecdsa.signatureS.buffer, signature.signature.ecdsa.signatureS.buffer, signature.signature.ecdsa.signatureS.size));

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
