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

#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_sys.h>

char *mssim_conf_g = "host=localhost,port=2321";
const char* dev_file_path_g = NULL;   // indicates to use default
const size_t dev_file_path_length_g = 0;
char *pub_key_filename_g = "pub_key.txt";
char *handle_filename_g = "handle.txt";

#define TEST_ASSERT(cond) \
    do \
    { \
        if (!(cond)) { \
            printf("Condition \'%s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #cond,__FILE__,  __func__, __LINE__); \
            printf("exiting\n"); \
            exit(1); \
        } \
    } while(0)

#define TEST_EXPECT(cond) \
    do \
    { \
        if (!(cond)) { \
            printf("Condition \'%s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #cond,__FILE__,  __func__, __LINE__); \
            printf("continuing\n"); \
        } \
    } while(0)

#define parse_cmd_args(argc, argv) \
    do \
    { \
        if (argc >= 2) { \
            mssim_conf_g = argv[1]; \
        } \
        if (argc == 4) { \
            pub_key_filename_g = argv[2]; \
            handle_filename_g = argv[3]; \
        } \
        printf("Saving public key to %s and handle to %s\n", pub_key_filename_g, handle_filename_g);\
    } while(0)

#define RETRY_FOR_SUCCESS(op) \
    {   \
        int ret;    \
        do {    \
            ret = op;   \
        } while (ret == TPM_RC_RETRY);    \
        TEST_ASSERT(TSS2_RC_SUCCESS == ret); \
    }

#define EMPTY_AUTH_COMMAND {            \
    .auths[0] = {                       \
        .sessionHandle = TPM2_RS_PW,    \
        .nonce = {.size = 0},           \
        .sessionAttributes = 0,         \
        .hmac = {.size = 0},            \
    },                                  \
    .count = 1                          \
}

static inline
void init_sapi(TSS2_SYS_CONTEXT **sapi_ctx)
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

    *sapi_ctx = malloc(sapi_ctx_size);
    TEST_EXPECT(NULL != *sapi_ctx);

    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
    init_ret = Tss2_Sys_Initialize(*sapi_ctx,
                                   sapi_ctx_size,
                                   tcti_ctx,
                                   &abi_version);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);
}
