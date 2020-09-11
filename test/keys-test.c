/******************************************************************************
 *
 * Copyright 2020 Xaptum, Inc.
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

#include <xaptum-tpm/keys.h>

#include "test-utils.h"

#include <stdbool.h>

void default_parent_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void get_pub_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void write_key_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void authd_parent_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void load_created_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void flush_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void sign_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void multiple_gens_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void multiple_gens_diffparent_test(TSS2_TCTI_CONTEXT *tcti_ctx);

void multiple_signs_test(TSS2_TCTI_CONTEXT *tcti_ctx);

int main()
{
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    init_tcti(&tcti_ctx);

    clear(tcti_ctx);
    default_parent_test(tcti_ctx);

    clear(tcti_ctx);
    get_pub_test(tcti_ctx);

    clear(tcti_ctx);
    write_key_test(tcti_ctx);

    clear(tcti_ctx);
    authd_parent_test(tcti_ctx);

    clear(tcti_ctx);
    load_created_test(tcti_ctx);

    clear(tcti_ctx);
    sign_test(tcti_ctx);

    clear(tcti_ctx);
    flush_test(tcti_ctx);

    clear(tcti_ctx);
    multiple_gens_test(tcti_ctx);

    clear(tcti_ctx);
    multiple_gens_diffparent_test(tcti_ctx);

    clear(tcti_ctx);
    multiple_signs_test(tcti_ctx);

    clear(tcti_ctx);
    Tss2_Tcti_Finalize(tcti_ctx);
    free(tcti_ctx);
}

void default_parent_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::default_parent_test...\n");

    struct xtpm_key out = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &out);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("ok\n");
}

void get_pub_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::get_pub_test...\n");

    struct xtpm_key out = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &out);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    uint8_t pub_key[XTPM_PUB_KEY_SIZE];
    ret = xtpm_get_public_key(&out, pub_key);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("ok\n");
}

void write_key_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::default_parent_test...\n");

    struct xtpm_key out = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &out);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = xtpm_write_key(&out, "key.pem");

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("ok\n");
}

void authd_parent_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::authd_parent_test...\n");

    struct xtpm_key out = {};

    const char* auth_password = "foo";
    size_t password_size = strlen(auth_password);

    set_password(tcti_ctx, auth_password);

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, auth_password, password_size, &out);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("ok\n");
}

void load_created_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::load_created_test...\n");

    struct xtpm_key key = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &key);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    TPM2_HANDLE handle;
    ret = xtpm_load_key(tcti_ctx, &key, &handle);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("ok\n");
}

void sign_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::sign_test...\n");

    struct xtpm_key key = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &key);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    // digest = sha-256("foo")
    TPM2B_DIGEST digest = {.size=32,
                           .buffer={0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc,
                                    0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}};
    TPMT_SIGNATURE signature;
    ret = xtpm_sign(tcti_ctx, &key, &digest, &signature);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    TEST_ASSERT(signature.sigAlg == TPM2_ALG_ECDSA);
    TEST_ASSERT(signature.signature.ecdsa.hash == TPM2_ALG_SHA256);
    TEST_ASSERT(signature.signature.ecdsa.signatureR.size == 32);
    TEST_ASSERT(signature.signature.ecdsa.signatureS.size == 32);

    printf("ok\n");
}

void flush_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::flush_test...\n");

    struct xtpm_key key = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &key);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    TPM2_HANDLE handle;
    bool hit_failure = false;
    for (int i=0; i<10; i++) {
        ret = xtpm_load_key(tcti_ctx, &key, &handle);
        if (TSS2_RC_SUCCESS != ret) {
            hit_failure = true;
            break;
        }
    }
    TEST_ASSERT(hit_failure);

    ret = xtpm_flush_key(tcti_ctx, handle);
    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    ret = xtpm_load_key(tcti_ctx, &key, &handle);
    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("ok\n");
}

void multiple_gens_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::multiple_gens_test...\n");

    for (int i=0; i<10; i++) {
        struct xtpm_key key = {};

        TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &key);

        TEST_ASSERT(TSS2_RC_SUCCESS == ret);
    }

    printf("ok\n");
}

void multiple_gens_diffparent_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::multiple_gens_diffparent_test...\n");

    TPM2_HANDLE parent_handle = 0x81000001;
    for (int i=0; i<5; i++) {   // can only store a limited-number of parents
        struct xtpm_key key = {};

        TSS2_RC ret = xtpm_gen_key(tcti_ctx, parent_handle, 0, NULL, 0, &key);

        ++parent_handle;

        TEST_ASSERT(TSS2_RC_SUCCESS == ret);
    }

    printf("ok\n");
}

void multiple_signs_test(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    printf("In keys-test::multiple_signs_test...\n");

    struct xtpm_key key = {};

    TSS2_RC ret = xtpm_gen_key(tcti_ctx, 0, 0, NULL, 0, &key);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    // digest = sha-256("foo")
    TPM2B_DIGEST digest = {.size=32,
                           .buffer={0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc,
                                    0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}};

    TPMT_SIGNATURE signature;
    for (int i=0; i<10; i++) {
        ret = xtpm_sign(tcti_ctx, &key, &digest, &signature);

        TEST_ASSERT(TSS2_RC_SUCCESS == ret);
    }

    printf("ok\n");
}
