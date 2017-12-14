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

#include <tss2/tss2_tcti_socket.h>

#include "../src/internal/tcti_common.h"

#include "test-utils.h"

#include <stdlib.h>

struct test_context {
    TSS2_TCTI_CONTEXT *tcti_ctx;
};

static void initialize(struct test_context *ctx);
static void cleanup(struct test_context *ctx);

static void init_test();
static void getpollhandles_test();
static void setlocality_test();
static void startup_test();
static void getrandom_test();

int main(int argc, char *argv[])
{
    parse_cmd_args(argc, argv);

    init_test();
    getpollhandles_test();
    setlocality_test();
    startup_test();
    getrandom_test();
}

void initialize(struct test_context *ctx)
{
    ctx->tcti_ctx = NULL;

    size_t ctx_size = tss2_tcti_getsize_socket();

    ctx->tcti_ctx = malloc(ctx_size);
    TEST_EXPECT(NULL != ctx->tcti_ctx);
    
    TSS2_RC init_ret = tss2_tcti_init_socket(hostname_g, port_g, ctx->tcti_ctx);
    TEST_ASSERT(TSS2_RC_SUCCESS == init_ret);
}

void cleanup(struct test_context *ctx)
{
    if (NULL != ctx->tcti_ctx) {
        tss2_tcti_finalize(ctx->tcti_ctx);
        free(ctx->tcti_ctx);
    }
}

void init_test()
{
    printf("In tss2_tcti_socket-test::init_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TEST_EXPECT(TCTI_MAGIC == ((TSS2_TCTI_CONTEXT_VERSION *)ctx.tcti_ctx)->magic);
    TEST_EXPECT(TCTI_VERSION == ((TSS2_TCTI_CONTEXT_VERSION *)ctx.tcti_ctx)->version);

    cleanup(&ctx);

    printf("ok\n");
}

void getpollhandles_test()
{
    printf("In tss2_tcti_socket-test::getpollhandles_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TSS2_RC ret = tss2_tcti_getPollHandles(ctx.tcti_ctx, NULL, NULL);
    TEST_ASSERT(TSS2_TCTI_RC_NOT_IMPLEMENTED == ret);

    cleanup(&ctx);

    printf("ok\n");
}

void setlocality_test()
{
    printf("In tss2_tcti_socket-test::setlocality_test...\n");

    struct test_context ctx;
    initialize(&ctx);

    TSS2_RC ret = tss2_tcti_setLocality(ctx.tcti_ctx, 0);
    TEST_ASSERT(TSS2_TCTI_RC_NOT_IMPLEMENTED == ret);

    cleanup(&ctx);

    printf("ok\n");
}

void startup_test()
{
    printf("In tss2_tcti_socket-test::startup_test...\n");

    TSS2_RC ret;

    struct test_context ctx;
    initialize(&ctx);

    uint8_t startup_command[] = {0x80, 0x01,    // TPM_ST_NO_SESSION
                                 0x00, 0x00, 0x00, 0x0C,    // Size = 12 = 0x0C
                                 0x00, 0x00, 0x01, 0x44,    // Command code = 0x144 = startup
                                 0x00, 0x00};

    ret = tss2_tcti_transmit(ctx.tcti_ctx,
                             sizeof(startup_command),
                             startup_command);
    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    uint8_t response[1024];
    size_t response_size = sizeof(response);
    ret = tss2_tcti_receive(ctx.tcti_ctx,
                            &response_size,
                            response,
                            TSS2_TCTI_TIMEOUT_BLOCK);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("Got response from startup command, of size %zu, with code ", response_size);
    uint8_t *response_code = &response[sizeof(uint16_t) + sizeof(uint32_t)];
    printf("(%#X, ", *response_code);
    ++response_code;
    printf("%#X, ", *response_code);
    ++response_code;
    printf("%#X, ", *response_code);
    ++response_code;
    printf("%#X)", *response_code);
    printf("\n");

    cleanup(&ctx);

    printf("ok\n");
}

void getrandom_test()
{
    printf("In tss2_tcti_socket-test::getrandom_test...\n");

    TSS2_RC ret;

    struct test_context ctx;
    initialize(&ctx);

    uint8_t getrandom_command[] = {0x80, 0x01,    // TPM_ST_NO_SESSION
                                   0x00, 0x00, 0x00, 0x0C,    // Size = 12 = 0x0C
                                   0x00, 0x00, 0x01, 0x7B,    // Command code = 0x17B = getrandom
                                   0x00, 0x02};

    ret = tss2_tcti_transmit(ctx.tcti_ctx,
                             sizeof(getrandom_command),
                             getrandom_command);
    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    uint8_t response[1024];
    size_t response_size = sizeof(response);
    ret = tss2_tcti_receive(ctx.tcti_ctx,
                            &response_size,
                            response,
                            TSS2_TCTI_TIMEOUT_BLOCK);

    TEST_ASSERT(TSS2_RC_SUCCESS == ret);

    printf("Got response from getrandom command, of size %zu\n", response_size);

    uint32_t response_code;
    ((uint8_t*)&response_code)[3] = response[sizeof(uint16_t) + sizeof(uint32_t)];
    ((uint8_t*)&response_code)[2] = response[sizeof(uint16_t) + sizeof(uint32_t) + 1];
    ((uint8_t*)&response_code)[1] = response[sizeof(uint16_t) + sizeof(uint32_t) + 2];
    ((uint8_t*)&response_code)[0] = response[sizeof(uint16_t) + sizeof(uint32_t) + 3];

    TEST_ASSERT(response_code == 0);

    cleanup(&ctx);

    printf("ok\n");
}
