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
#include <tss2/xaptum_nvram.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_NVRAM_SIZE 768

struct nvram_context {
    const char *tpm_hostname;
    const char *tpm_port;
    const char *out_filename;
    unsigned char tcti_context_buffer[128];
    enum xtpm_object_name obj_name;
    TSS2_TCTI_CONTEXT *tcti_context;
};

static
void
init_socket_tcti(struct nvram_context *ctx);

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
    uint16_t output_length;
    printf("Reading object from NVRAM...");
    TSS2_RC read_ret = xtpm_read_object(output_data, sizeof(output_data), &output_length, ctx.obj_name, ctx.tcti_context);
    if (TSS2_RC_SUCCESS != read_ret) {
        fprintf(stderr, "Bad read_ret: %#X\n", read_ret);
        exit(1);
    }

    dump_binary_to_file(ctx.out_filename, output_data, output_length);

    tss2_tcti_finalize(ctx.tcti_context);

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

void
parse_cli_args(int argc,
               char *argv[],
               struct nvram_context *ctx)
{
    const char *usage_str = "usage: %s <object-name> <output file> [tpm hostname = 'localhost'] [tpm port = '2321']\n"
                            "\twhere object-name:\n"
                            "\t\tgpk\n"
                            "\t\tcred\n"
                            "\t\tcred_sig\n"
                            "\t\troot_id\n"
                            "\t\troot_pubkey\n"
                            "\t\troot_asn1_cert\n";

    ctx->tpm_hostname = "localhost";
    ctx->tpm_port = "2321";

    const char *obj_name = NULL;
    if (3 == argc) {
        obj_name = argv[1];
        ctx->out_filename = argv[2];
    } else if (4 == argc) {
        obj_name = argv[1];
        ctx->out_filename = argv[2];
        ctx->tpm_hostname = argv[3];
    } else if (5 == argc) {
        obj_name = argv[1];
        ctx->out_filename = argv[2];
        ctx->tpm_hostname = argv[3];
        ctx->tpm_port = argv[4];
    } else {
        fprintf(stderr, "Error parsing command line arguments\n");
        fprintf(stderr, usage_str, argv[0]);
        exit(1);
    }

    if (0 == strncmp(obj_name, "gpk", sizeof("gpk"))) {
        ctx->obj_name = XTPM_GROUP_PUBLIC_KEY;
    } else if (0 == strncmp(obj_name, "cred", sizeof("cred"))) {
        ctx->obj_name = XTPM_CREDENTIAL;
    } else if (0 == strncmp(obj_name, "cred_sig", sizeof("cred_sig"))) {
        ctx->obj_name = XTPM_CREDENTIAL_SIGNATURE;
    } else if (0 == strncmp(obj_name, "root_id", sizeof("root_id"))) {
        ctx->obj_name = XTPM_ROOT_ID;
    } else if (0 == strncmp(obj_name, "root_pubkey", sizeof("root_pubkey"))) {
        ctx->obj_name = XTPM_ROOT_PUBKEY;
    } else if (0 == strncmp(obj_name, "root_asn1_cert", sizeof("root_asn1_cert"))) {
        ctx->obj_name = XTPM_ROOT_ASN1_CERTIFICATE;
    } else {
        fprintf(stderr, "Unrecognized object name '%s'\n", obj_name);
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
