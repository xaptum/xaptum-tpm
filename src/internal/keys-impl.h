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

#ifndef XAPTUM_TPM_INTERNAL_KEYSIMPL_H
#define XAPTUM_TPM_INTERNAL_KEYSIMPL_H
#pragma once

#include <tss2/tss2_tcti.h>
#include <tss2/tss2_sys.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Check if `parent_handle` is loaded and is usable as a parent key.
 *
 * Returns TSS2_RC_SUCCESS if key is OK,
 * or other is not.
 */
TSS2_RC
check_parent(TSS2_SYS_CONTEXT *sapi_ctx,
             TPM2_HANDLE parent_handle);

/*
 * Create (and persist at `primary_handle`) a new primary key in `hierarchy`.
 *
 * New primary key has *no* auth set.
 *
 * If a password has been set for `hierarchy`, this must be provided as `hierarchy_password`.
 */
TSS2_RC
create_primary(TSS2_SYS_CONTEXT *sapi_ctx,
               TPMI_RH_HIERARCHY hierarchy,
               TPM2_HANDLE primary_handle,
               const char *hierarchy_password,
               size_t hierarchy_password_length);

/*
 * Create a new key under `parent_handle`.
 *
 * The public information is returned in `public_key_out`,
 * and the encrypted private blob is returned in `private_key_blob_out`.
 *
 * The new key has *no* auth set.
 */
TSS2_RC
create_child(TSS2_SYS_CONTEXT *sapi_ctx,
             TPM2_HANDLE parent_handle,
             TPM2B_PUBLIC *public_key_out,
             TPM2B_PRIVATE *private_key_blob_out);

/*
 * Make the given key available for signing.
 *
 * The key is specified via `public_key` and `private_key_blob`,
 * and is assumed to have been created under `parent_handle`.
 *
 * The handle where the key is available will be returned in `handle_out`.
 */
TSS2_RC
load_key(TSS2_SYS_CONTEXT *sapi_ctx,
         TPM2_HANDLE parent_handle,
         const TPM2B_PUBLIC *public_key,
         const TPM2B_PRIVATE *private_key_blob,
         TPM2_HANDLE *handle_out);

/*
 * Persist the object at `current_handle` to `persistent_handle`.
 *
 * If a password has been set for `hierarchy`, this must be provided as `hierarchy_password`.
 */
TSS2_RC
evict_control(TSS2_SYS_CONTEXT *sapi_ctx,
              TPMI_RH_HIERARCHY hierarchy,
              TPM2_HANDLE current_handle,
              TPM2_HANDLE persistent_handle,
              const char *hierarchy_password,
              size_t hierarchy_password_length);

/*
 * Create signature over `digest` using `key_handle`.
 *
 * NOTE: This currently assumes this is a ECDSA-with-SHA256 key.
 *
 * The key is assumed to have no auth set.
 */
TSS2_RC
sign(TSS2_SYS_CONTEXT *sapi_ctx,
     TPM2_HANDLE key_handle,
     const TPM2B_DIGEST *digest,
     TPMT_SIGNATURE *signature_out);

#ifdef __cplusplus
}
#endif

#endif
