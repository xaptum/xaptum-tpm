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

#include "internal/asn1.h"
#include "internal/keys-impl.h"
#include "internal/pem.h"
#include "internal/sapi.h"

#include <xaptum-tpm/keys.h>

#include <stdlib.h>
#include <string.h>

#define DEFAULT_PARENT_KEY 0x81000001
#define DEFAULT_HIERARCHY TPM2_RH_OWNER

TSS2_RC
xtpm_gen_key(TSS2_TCTI_CONTEXT *tcti_ctx,
             TPM2_HANDLE parent_handle_in,
             TPMI_RH_HIERARCHY hierarchy_in,
             const char *hierarchy_password,
             size_t hierarchy_password_length,
             struct xtpm_key *out)
{
    TSS2_RC ret;

    TPMI_RH_HIERARCHY hierarchy;
    if (0 == hierarchy_in) {
        hierarchy = DEFAULT_HIERARCHY;
    } else {
        hierarchy = hierarchy_in;
    }

    TPM2_HANDLE parent_handle;
    if (0 == parent_handle_in) {
        parent_handle = DEFAULT_PARENT_KEY;
    } else {
        parent_handle = parent_handle_in;
    }

    TSS2_SYS_CONTEXT *sapi_ctx = NULL;
    ret = init_sapi(&sapi_ctx, tcti_ctx);
    if (TSS2_RC_SUCCESS != ret)
        goto finish;

    if (TSS2_RC_SUCCESS != check_parent(sapi_ctx, parent_handle)) {
        ret = create_primary(sapi_ctx,
                             hierarchy,
                             parent_handle,
                             hierarchy_password,
                             hierarchy_password_length);
        if (TSS2_RC_SUCCESS != ret)
            goto finish;
    }

    out->parent_handle = parent_handle;
    ret = create_child(sapi_ctx,
                       parent_handle,
                       &out->public_key,
                       &out->private_key_blob);
    if (TSS2_RC_SUCCESS != ret)
        goto finish;

finish:
    if (sapi_ctx) {
        Tss2_Sys_Finalize(sapi_ctx);
        free(sapi_ctx);
    }

    return ret;
}

TSS2_RC
xtpm_load_key(TSS2_TCTI_CONTEXT *tcti_ctx,
              const struct xtpm_key *key,
              TPM2_HANDLE *handle_out)
{
    TSS2_RC ret;

    TSS2_SYS_CONTEXT *sapi_ctx = NULL;
    ret = init_sapi(&sapi_ctx, tcti_ctx);
    if (TSS2_RC_SUCCESS != ret)
        goto finish;

    ret = load_key(sapi_ctx,
                   key->parent_handle,
                   &key->public_key,
                   &key->private_key_blob,
                   handle_out);

finish:
    if (sapi_ctx) {
        Tss2_Sys_Finalize(sapi_ctx);
        free(sapi_ctx);
    }

    return ret;
}

TSS2_RC
xtpm_flush_key(TSS2_TCTI_CONTEXT *tcti_ctx,
               TPM2_HANDLE handle)
{
    TSS2_RC ret;

    TSS2_SYS_CONTEXT *sapi_ctx = NULL;
    ret = init_sapi(&sapi_ctx, tcti_ctx);
    if (TSS2_RC_SUCCESS != ret)
        goto finish;

    ret = Tss2_Sys_FlushContext(sapi_ctx,
                                handle);

finish:
    if (sapi_ctx) {
        Tss2_Sys_Finalize(sapi_ctx);
        free(sapi_ctx);
    }

    return ret;
}

TSS2_RC
xtpm_write_key(const struct xtpm_key *key,
               const char *filename)
{
    uint8_t buf[ASN1_LOADABLE_KEY_MIN_BUF];

    size_t total_size = 0;

    build_asn1_from_key(key, buf, &total_size);

    int write_ret = write_pem(filename, buf, total_size);
    if (0 != write_ret)
        return TSS2_BASE_RC_IO_ERROR;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
xtpm_get_public_key(const struct xtpm_key *key,
                    uint8_t *buf)
{
    buf[0] = 0x04;  // indicates uncompressed format

    if (32 != key->public_key.publicArea.unique.ecc.x.size)
        return TSS2_BASE_RC_BAD_VALUE;

    memcpy(buf + 1, key->public_key.publicArea.unique.ecc.x.buffer, 32);

    if (32 != key->public_key.publicArea.unique.ecc.y.size)
        return TSS2_BASE_RC_BAD_VALUE;

    memcpy(buf + 1 + 32, key->public_key.publicArea.unique.ecc.y.buffer, 32);

    return TSS2_RC_SUCCESS;
}

TSS2_RC
xtpm_sign(TSS2_TCTI_CONTEXT *tcti_ctx,
          const struct xtpm_key *key,
          const TPM2B_DIGEST *digest,
          TPMT_SIGNATURE *signature_out)
{
    TSS2_RC ret;

    TSS2_SYS_CONTEXT *sapi_ctx = NULL;
    ret = init_sapi(&sapi_ctx, tcti_ctx);
    if (TSS2_RC_SUCCESS != ret)
        goto finish;

    TPM2_HANDLE loaded_key;
    ret = load_key(sapi_ctx,
                   key->parent_handle,
                   &key->public_key,
                   &key->private_key_blob,
                   &loaded_key);

    if (TSS2_RC_SUCCESS != ret)
        goto finish;

    ret = sign(sapi_ctx,
               loaded_key,
               digest,
               signature_out);

    TSS2_RC flush_ret = Tss2_Sys_FlushContext(sapi_ctx,
                                              loaded_key);
    if (TSS2_RC_SUCCESS != ret)
        ret = flush_ret;

finish:
    if (sapi_ctx) {
        Tss2_Sys_Finalize(sapi_ctx);
        free(sapi_ctx);
    }

    return ret;
}
