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

struct test_context {
    TSS2_SYS_CONTEXT *sapi_ctx;
    TPM2_HANDLE primary_key_handle;
    TPM2_HANDLE signing_key_handle;
    TPM2_HANDLE persistent_key_handle;
    TPM2B_PUBLIC out_public;
    TPM2B_PRIVATE out_private;
    unsigned char tcti_buffer[256];
    unsigned char sapi_buffer[4200];

};

static void initialize(struct test_context *ctx);
static void cleanup(struct test_context *ctx);

static int clear(struct test_context *ctx);
static int create_primary(struct test_context *ctx);
static int create(struct test_context *ctx);
static int load(struct test_context *ctx);
static int evict_control(struct test_context *ctx);

int main()
{
    struct test_context ctx;
    initialize(&ctx);

    int ret = 0;

    ret = clear(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = create_primary(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = create(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = load(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = evict_control(&ctx);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    cleanup(&ctx);
}

void initialize(struct test_context *ctx)
{
    const char *mssim_conf = "host=localhost,port=2321";
    const char *device_conf = "/dev/tpm0";

    int init_ret;

    TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT*)ctx->tcti_buffer;
#ifdef USE_TCP_TPM
    (void)device_conf;
    size_t size;
    init_ret = Tss2_Tcti_Mssim_Init(NULL, &size, mssim_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: failed to get allocation size for tcti context\n");
        exit(1);
    }
    if (size > sizeof(ctx->tcti_buffer)) {
        printf("Error: socket TCTI context size larger than pre-allocated buffer\n");
        exit(1);
    }
    init_ret = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, mssim_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: Unable to initialize socket TCTI context\n");
        exit(1);
    }
#else
    (void)mssim_conf;
    size_t size;
    init_ret = Tss2_Tcti_Device_Init(NULL, &size, device_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Failed to get allocation size for tcti context\n");
        exit(1);
    }
    if (size > sizeof(ctx->tcti_buffer)) {
        printf("Error: device TCTI context size larger than pre-allocated buffer\n");
        exit(1);
    }
    init_ret = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_conf);
    if (TSS2_RC_SUCCESS != init_ret) {
        printf("Error: Unable to initialize device TCTI context\n");
        exit(1);
    }
#endif

    ctx->sapi_ctx = (TSS2_SYS_CONTEXT*)ctx->sapi_buffer;
    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TEST_ASSERT(sizeof(ctx->sapi_buffer) >= sapi_ctx_size);

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    init_ret = Tss2_Sys_Initialize(ctx->sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);

    ctx->out_public.size = 0;
    ctx->out_private.size = 0;
}

void cleanup(struct test_context *ctx)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;

    if (ctx->sapi_ctx != NULL) {
        TSS2_RC rc = Tss2_Sys_GetTctiContext(ctx->sapi_ctx, &tcti_context);
        TEST_ASSERT(TSS2_RC_SUCCESS == rc);

        Tss2_Tcti_Finalize(tcti_context);

        Tss2_Sys_Finalize(ctx->sapi_ctx);
    }
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

int create_primary(struct test_context *ctx)
{
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_ENDORSEMENT;

    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_SENSITIVE_CREATE inSensitive = {.sensitive={.data.size = 0,
                                                     .userAuth.size = 0}};

    TPMA_OBJECT obj_attrs = TPMA_OBJECT_FIXEDTPM |
                            TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                            TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_DECRYPT |
                            TPMA_OBJECT_RESTRICTED;
    TPM2B_PUBLIC in_public = {.publicArea = {.type=TPM2_ALG_ECC,
                                            .nameAlg=TPM2_ALG_SHA256,
                                            .objectAttributes=obj_attrs}};
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    in_public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_CFB;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
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
                                        &ctx->primary_key_handle,
                                        &public_key,
                                        &creationData,
                                        &creationHash,
                                        &creationTicket,
                                        &name,
                                        &sessionsDataOut);

    printf("CreatePrimary ret=%#X\n", ret);

    return ret;
}

int create(struct test_context *ctx)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_SENSITIVE_CREATE inSensitive = {.sensitive={.data.size = 0,
                                                      .userAuth.size = 0}};

    TPMA_OBJECT obj_attrs = TPMA_OBJECT_FIXEDTPM |
                            TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                            TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_SIGN_ENCRYPT;
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

    TSS2_RC ret = Tss2_Sys_Create(ctx->sapi_ctx,
                                  ctx->primary_key_handle,
                                  &sessionsData,
                                  &inSensitive,
                                  &in_public,
                                  &outsideInfo,
                                  &creationPCR,
                                  &ctx->out_private,
                                  &ctx->out_public,
                                  &creationData,
                                  &creationHash,
                                  &creationTicket,
                                  &sessionsDataOut);

    printf("Create ret=%#X\n", ret);

    return ret;
}

int load(struct test_context *ctx)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_NAME name = {.size=sizeof(TPMU_NAME)};

    int ret = Tss2_Sys_Load(ctx->sapi_ctx,
                            ctx->primary_key_handle,
                            &sessionsData,
                            &ctx->out_private,
                            &ctx->out_public,
                            &ctx->signing_key_handle,
                            &name,
                            &sessionsDataOut);

    printf("Load ret=%#X\n", ret);

    return ret;
}

int evict_control(struct test_context *ctx)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = EMPTY_AUTH_COMMAND;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    ctx->persistent_key_handle = 0x81010000;

    TSS2_RC ret = Tss2_Sys_EvictControl(ctx->sapi_ctx,
                                        TPM2_RH_OWNER,
                                        ctx->signing_key_handle,
                                        &sessionsData,
                                        ctx->persistent_key_handle,
                                        &sessionsDataOut);

    printf("EvictControl ret=%#X\n", ret);

    return ret;
}
