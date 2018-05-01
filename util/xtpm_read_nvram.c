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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_NVRAM_SIZE 768

#define GPK_LENGTH 258
#define CRED_LENGTH 260
#define CRED_SIG_LENGTH 64
#define ROOT_ID_LENGTH 16
#define ROOT_PUBKEY_LENGTH 32
#define ROOT_ASN1CERT_LENGTH 276
TPMI_RH_NV_INDEX gpk_handle_g = 0x1410000;
TPMI_RH_NV_INDEX cred_handle_g = 0x1410001;
TPMI_RH_NV_INDEX cred_sig_handle_g = 0x1410002;
TPMI_RH_NV_INDEX root_id_handle_g = 0x1410003;
TPMI_RH_NV_INDEX root_pubkey_handle_g = 0x1410004;
TPMI_RH_NV_INDEX root_asn1cert_handle_g = 0x1410005;

struct nvram_context {
    const char *tpm_hostname;
    const char *tpm_port;
    const char *out_filename;
    uint32_t index;
    uint32_t size;
    unsigned char tcti_context_buffer[128];
    TSS2_TCTI_CONTEXT *tcti_context;
};

static
void
init_socket_tcti(struct nvram_context *ctx);

static
TSS2_RC
read_nvram(unsigned char *out,
           uint16_t size,
           TPM_HANDLE index,
           TSS2_TCTI_CONTEXT *tcti_context);

static
void
parse_cli_args(int argc,
               char *argv[],
               struct nvram_context *ctx);

static
void
dump_binary_to_file(const char *output_file,
                    unsigned char *binary,
                    size_t size);

int main(int argc, char *argv[])
{
    struct nvram_context ctx;
    parse_cli_args(argc, argv, &ctx);

    init_socket_tcti(&ctx);

    unsigned char output_data[MAX_NVRAM_SIZE];
    if (ctx.size > sizeof(output_data)) {
        fprintf(stderr, "Requested size is larger than allocated buffer\n");
        exit(1);
    }
    printf("Reading from index %#X of size %u...", ctx.index, ctx.size);
    TSS2_RC read_ret = read_nvram(output_data, ctx.size, ctx.index, ctx.tcti_context);
    if (TSS2_RC_SUCCESS != read_ret) {
        fprintf(stderr, "Bad read_ret: %#X\n", read_ret);
        exit(1);
    }

    dump_binary_to_file(ctx.out_filename, output_data, ctx.size);

    printf("\tok\n");
}

void
init_socket_tcti(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (tss2_tcti_getsize_socket() >= sizeof(ctx->tcti_context_buffer)) {
        fprintf(stderr, "TCTI context larger than allocated buffer\n");
        exit(1);
    }
    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_context_buffer;

    ret = tss2_tcti_init_socket(ctx->tpm_hostname, ctx->tpm_port, ctx->tcti_context);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TCTI socket\n");
        exit(1);
    }
}

TSS2_RC
read_nvram(unsigned char *out,
           uint16_t size,
           TPM_HANDLE index,
           TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    // 1) Create SAPI context
    unsigned char sapi_context_buffer[5120];
    if (Tss2_Sys_GetContextSize(0) > sizeof(sapi_context_buffer)) {
        fprintf(stderr, "SAPI context is larger than allocated buffer\n");
        exit(1);
    }
    TSS2_SYS_CONTEXT *sapi_context = (TSS2_SYS_CONTEXT*)sapi_context_buffer;

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    ret = Tss2_Sys_Initialize(sapi_context,
                              Tss2_Sys_GetContextSize(0),
                              tcti_context,
                              &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TPM SAPI context\n");
        exit(1);
    }

    // We (Xaptum) set AUTHREAD and no password.
    //  This means anyone can read,
    //  by using an empty password and passing the index itself as the auth handle.
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

    uint16_t data_offset = 0;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        ret = Tss2_Sys_NV_Read(sapi_context,
                               index,
                               index,
                               &sessionsData,
                               bytes_to_read,
                               data_offset,
                               &nv_data,
                               &sessionsDataOut);

        if (ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error reading from NVRAM\n");
            goto finish;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

finish:
    Tss2_Sys_Finalize(sapi_context);
    tss2_tcti_finalize(tcti_context);

    return ret;
}

void
parse_cli_args(int argc,
               char *argv[],
               struct nvram_context *ctx)
{
    const char *usage_str = "usage: %s <index-name> <output file> [tpm hostname = 'localhost'] [tpm port = '2321']\n"
                            "\twhere index-name:\n"
                            "\t\tgpk\n"
                            "\t\tcred\n"
                            "\t\tcred_sig\n"
                            "\t\troot_id\n"
                            "\t\troot_pubkey\n"
                            "\t\troot_cert\n";

    ctx->tpm_hostname = "localhost";
    ctx->tpm_port = "2321";

    const char *type = NULL;
    if (3 == argc) {
        type = argv[1];
        ctx->out_filename = argv[2];
    } else if (4 == argc) {
        type = argv[1];
        ctx->out_filename = argv[2];
        ctx->tpm_hostname = argv[3];
    } else if (5 == argc) {
        type = argv[1];
        ctx->out_filename = argv[2];
        ctx->tpm_hostname = argv[3];
        ctx->tpm_port = argv[4];
    } else {
        fprintf(stderr, "Error parsing command line arguments\n");
        fprintf(stderr, usage_str, argv[0]);
        exit(1);
    }

    if (0 == strcmp(type, "gpk")) {
        ctx->index = gpk_handle_g;
        ctx->size = GPK_LENGTH;
    } else if (0 == strcmp(type, "cred")) {
        ctx->index = cred_handle_g;
        ctx->size = CRED_LENGTH;
    } else if (0 == strcmp(type, "cred_sig")) {
        ctx->index = cred_sig_handle_g;
        ctx->size = CRED_SIG_LENGTH;
    } else if (0 == strcmp(type, "root_id")) {
        ctx->index = root_id_handle_g;
        ctx->size = ROOT_ID_LENGTH;
    } else if (0 == strcmp(type, "root_pubkey")) {
        ctx->index = root_pubkey_handle_g;
        ctx->size = ROOT_PUBKEY_LENGTH;
    } else if (0 == strcmp(type, "root_cert")) {
        ctx->index = root_asn1cert_handle_g;
        ctx->size = ROOT_ASN1CERT_LENGTH;
    } else {
        fprintf(stderr, "Unrecognized index type '%s'\n", type);
        exit(1);
    }
}

void
dump_binary_to_file(const char *output_file,
                    unsigned char *binary,
                    size_t size)
{
    FILE *file_ptr = fopen(output_file, "wb");
    if (NULL == file_ptr) {
        fprintf(stderr, "Error opening output file '%s'\n", output_file);
        exit(1);
    }

    size_t write_ret = fwrite(binary, 1, size, file_ptr);
    if (size != write_ret) {
        fprintf(stderr, "Error writing to file\n");
        exit(1);
    }

    fclose(file_ptr);
}
