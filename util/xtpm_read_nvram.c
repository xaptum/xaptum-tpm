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

#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tcti_socket.h>
#include <xaptum/tpm/nvram.h>

#include <getopt.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_NVRAM_SIZE 768

enum tcti_type {
    TCTI_SOCKET,
    TCTI_DEVICE,
};

struct nvram_context {
    enum tcti_type tcti;
    const char *tpm_dev_file;
    const char *tpm_hostname;
    const char *tpm_port;
    const char *out_filename;
    enum xtpm_object_name obj_name;
    unsigned char tcti_context_buffer[256];
    TSS2_TCTI_CONTEXT *tcti_context;
    unsigned char sapi_context_buffer[5120];
    TSS2_SYS_CONTEXT *sapi_context;
};

static
void
init_device_tcti(struct nvram_context *ctx);

static
void
init_socket_tcti(struct nvram_context *ctx);

static
void
init_sapi(struct nvram_context *ctx);

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

    switch (ctx.tcti) {
        case TCTI_DEVICE:
            init_device_tcti(&ctx);
            break;
        case TCTI_SOCKET:
            init_socket_tcti(&ctx);
    }

    init_sapi(&ctx);

    unsigned char output_data[MAX_NVRAM_SIZE];
    uint16_t output_length;
    printf("Reading object from NVRAM...");
    TSS2_RC read_ret = xtpm_read_object(output_data, sizeof(output_data), &output_length, ctx.obj_name, ctx.sapi_context);
    if (TSS2_RC_SUCCESS != read_ret) {
        fprintf(stderr, "Bad read_ret: %#X\n", read_ret);
        exit(1);
    }

    dump_binary_to_file(ctx.out_filename, output_data, output_length);

    Tss2_Sys_Finalize(ctx.sapi_context);
    tss2_tcti_finalize(ctx.tcti_context);

    printf("\tok\n");
}

void
init_device_tcti(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (tss2_tcti_getsize_device() >= sizeof(ctx->tcti_context_buffer)) {
        fprintf(stderr, "TCTI device context larger than allocated buffer\n");
        exit(1);
    }
    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_context_buffer;

    ret = tss2_tcti_init_device(ctx->tpm_dev_file, strlen(ctx->tpm_dev_file), ctx->tcti_context);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TCTI device\n");
        exit(1);
    }
}

void
init_socket_tcti(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (tss2_tcti_getsize_socket() >= sizeof(ctx->tcti_context_buffer)) {
        fprintf(stderr, "TCTI socket context larger than allocated buffer\n");
        exit(1);
    }
    ctx->tcti_context = (TSS2_TCTI_CONTEXT*)ctx->tcti_context_buffer;

    ret = tss2_tcti_init_socket(ctx->tpm_hostname, ctx->tpm_port, ctx->tcti_context);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing TCTI socket\n");
        exit(1);
    }
}

void
init_sapi(struct nvram_context *ctx)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    if (Tss2_Sys_GetContextSize(0) > sizeof(ctx->sapi_context_buffer)) {
        fprintf(stderr, "SAPI context larger than allocated buffer\n");
        exit(1);
    }
    ctx->sapi_context = (TSS2_SYS_CONTEXT*)ctx->sapi_context_buffer;

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    ret = Tss2_Sys_Initialize(ctx->sapi_context,
                              Tss2_Sys_GetContextSize(0),
                              ctx->tcti_context,
                              &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        fprintf(stderr, "Error initializing SAPI context\n");
        exit(1);
    }
}

void
parse_cli_args(int argc,
               char *argv[],
               struct nvram_context *ctx)
{
    const char *usage_str = "Dump to file an NVRAM object provisioned on a Xaptum TPM.\n\n"
        "Usage: %s [-h] [-t device|socket] [-d <path>] [-a <ip>] [-p <port>] [-o <file>] <object-name>\n"
        "\tOptions:\n"
        "\t\t-h --help              Display this message.\n"
        "\t\t-t --tcti              TPM TCTI type (device|socket) [default: device].\n"
        "\t\t-d --tpm-device-file   TCTI device file, if tcti==device [default: '/dev/tpm0'].\n"
        "\t\t-a --tpm-ip-address    IP hostname of TPM TCP server, if tcti==socket [default: 'localhost'].\n"
        "\t\t-p --tpm-port          TCP port of TPM TCP server, if tcti==socket [default: 2321].\n"
        "\t\t-o --output-file       Output file. [default: '<object-name>.bin']\n"
        "\tArguments:\n"
        "\t\tobject-name\tOne of gpk, cred, cred_sig, root_id, root_pubkey, root_asn1_cert, basename, or server_id\n"
        ;

    ctx->tcti = TCTI_DEVICE;
    ctx->tpm_dev_file = "/dev/tpm0";
    ctx->tpm_hostname = "localhost";
    ctx->tpm_port = "2321";
    ctx->out_filename = NULL;

    static struct option cli_options[] =
    {
        {"tcti", required_argument, NULL, 't'},
        {"tpm-device-file", required_argument, NULL, 'd'},
        {"tpm-ip-address", required_argument, NULL, 'a'},
        {"tpm-port", required_argument, NULL, 'p'},
        {"output-file", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "t:d:a:p:o:h", cli_options, NULL)) != -1) {
        switch (c) {
            case 't':
                if (0 == strcmp(optarg, "device")) {
                    ctx->tcti = TCTI_DEVICE;
                } else if (0 == strcmp(optarg, "socket")) {
                    ctx->tcti = TCTI_SOCKET;
                } else {
                    fprintf(stderr, "Unrecognized TCTI type '%s'\n", optarg);
                    exit(1);
                }
                break;
            case 'd':
                ctx->tpm_dev_file = optarg;
                break;
            case 'a':
                ctx->tpm_hostname = optarg;
                break;
            case 'p':
                ctx->tpm_port = optarg;
                break;
            case 'o':
                ctx->out_filename = optarg;
                break;
            case 'h':
                fprintf(stderr, usage_str, argv[0]);
                exit(1);
        }
    }
    if (argv[optind] != NULL) {
        if (0 == strcmp(argv[optind], "gpk")) {
            ctx->obj_name = XTPM_GROUP_PUBLIC_KEY;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "gpk.bin";
        } else if (0 == strcmp(argv[optind], "cred")) {
            ctx->obj_name = XTPM_CREDENTIAL;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "cred.bin";
        } else if (0 == strcmp(argv[optind], "cred_sig")) {
            ctx->obj_name = XTPM_CREDENTIAL_SIGNATURE;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "cred_sig.bin";
        } else if (0 == strcmp(argv[optind], "root_id")) {
            ctx->obj_name = XTPM_ROOT_ID;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "root_id.bin";
        } else if (0 == strcmp(argv[optind], "root_pubkey")) {
            ctx->obj_name = XTPM_ROOT_PUBKEY;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "root_pubkey.bin";
        } else if (0 == strcmp(argv[optind], "root_asn1_cert")) {
            ctx->obj_name = XTPM_ROOT_ASN1_CERTIFICATE;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "root_asn1_cert.bin";
        } else if (0 == strcmp(argv[optind], "basename")) {
            ctx->obj_name = XTPM_BASENAME;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "basename.bin";
        } else if (0 == strcmp(argv[optind], "server_id")) {
            ctx->obj_name = XTPM_SERVER_ID;
            if (ctx->out_filename == NULL)
                ctx->out_filename = "server_id.bin";
        } else {
            fprintf(stderr, "Unrecognized object name '%s'\n", argv[optind]);
            exit(1);
        }
    } else {
        fprintf(stderr, "Must specify object name\n");
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
