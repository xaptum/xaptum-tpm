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

#ifndef XAPTUM_TPM_KEYS_H
#define XAPTUM_TPM_KEYS_H
#pragma once

#include <tss2/tss2_tcti.h>
#include <tss2/tss2_sys.h>

#define XTPM_PUB_KEY_SIZE 65

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Child key information.
 *
 * NOTE: The parent and child keys are assumed to have *no auth* set.
 */
struct xtpm_key {
    TPM2_HANDLE parent_handle;
    TPM2B_PUBLIC public_key;
    TPM2B_PRIVATE private_key_blob;
};

/*
 * Create new child key.
 *
 * If the specified parent doesn't exist, it is created.
 *
 * See `src/internal/keys-impl.c` for parameters used in key creation.
 *
 * No auth is set on the key.
 *
 * Key is *not* loaded or persisted.
 * However, parent key *will* be persisted, if created.
 *
 * Default parameters:
 *  - parent_handle = 0x81000001 (set to 0 to use default)
 *  - hierarchy = TPM2_RH_OWNER (set to 0 to use default)
 *  - hierarchy_password = empty auth
 *  - hierarchy_password_length = 0 (set to 0 to use default password)
 */
TSS2_RC
xtpm_gen_key(TSS2_TCTI_CONTEXT *tcti_ctx,
             TPM2_HANDLE parent_handle,
             TPMI_RH_HIERARCHY hierarchy,
             const char *hierarchy_password,
             size_t hierarchy_password_length,
             struct xtpm_key *out);

/*
 * Load the `xtpm_key` into the TPM, so it's usable for signing.
 *
 * The handle of the loaded key is returned in `handle_out`.
 */
TSS2_RC
xtpm_load_key(TSS2_TCTI_CONTEXT *tcti_ctx,
              const struct xtpm_key *key,
              TPM2_HANDLE *handle_out);

/*
 * Flush a memory-resident key (at `handle`) from the TPM.
 */
TSS2_RC
xtpm_flush_key(TSS2_TCTI_CONTEXT *tcti_ctx,
               TPM2_HANDLE handle);

/*
 * Write key to PEM file.
 */
TSS2_RC
xtpm_write_key(const struct xtpm_key *key,
               const char *filename);

/*
 * Retrieve the public key from a `xtpm_key` in x9.62 uncompressed format
 *
 * The key is written to `buf` (and always has length `XTPM_PUB_KEY_SIZE` bytes).
 */
TSS2_RC
xtpm_get_public_key(const struct xtpm_key *key,
                    uint8_t *buf);

/*
 * Generate signature over `digest` using `key`.
 *
 * The signature is returned in `signature_out`.
 *
 * Note that this takes a *digest*,
 * so a message to be signed must first be hashed.
 */
TSS2_RC
xtpm_sign(TSS2_TCTI_CONTEXT *tcti_ctx,
          const struct xtpm_key *key,
          const TPM2B_DIGEST *digest,
          TPMT_SIGNATURE *signature_out);

#ifdef __cplusplus
}
#endif

#endif

