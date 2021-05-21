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

#include "keys-impl.h"

#include <string.h>


TSS2_RC
check_parent(TSS2_SYS_CONTEXT *sapi_ctx,
             TPM2_HANDLE parent_handle)
{
    TPM2B_PUBLIC outPublic = {};
    TPM2B_NAME name = {};
    TPM2B_NAME qualifiedName = {};

    TSS2_RC ret = Tss2_Sys_ReadPublic(sapi_ctx,
                                      parent_handle,
                                      NULL,
                                      &outPublic,
                                      &name,
                                      &qualifiedName,
                                      NULL);

    if (TSS2_RC_SUCCESS != ret)
        return ret;

    if (!(outPublic.publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED) ||
        !(outPublic.publicArea.objectAttributes & TPMA_OBJECT_DECRYPT))
        return TSS2_SYS_RC_NO_DECRYPT_PARAM;

    return ret;
}

TSS2_RC
create_primary(TSS2_SYS_CONTEXT *sapi_ctx,
               TPMI_RH_HIERARCHY hierarchy,
               TPM2_HANDLE primary_handle,
               const char *hierarchy_password,
               size_t hierarchy_password_length)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.count = 1;

    if (0 != hierarchy_password_length) {
        if (hierarchy_password_length > sizeof(sessionsData.auths[0].hmac.buffer))
            return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
        sessionsData.auths[0].hmac.size = hierarchy_password_length;
        memcpy(sessionsData.auths[0].hmac.buffer, hierarchy_password, hierarchy_password_length);
    }

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    // Nb. no auth set for key
    TPM2B_SENSITIVE_CREATE inSensitive = {};

    TPM2B_PUBLIC in_public = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {},
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.sym = TPM2_ALG_CFB,
                  },
                 .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                 },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                 },
             },
            .unique.ecc = {}
         }
    };

    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {};
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};
    TPM2B_NAME name = {};

    TPM2B_PUBLIC public_key = {};

    TPM2_HANDLE tmp_primary_handle;

    TSS2_RC ret = Tss2_Sys_CreatePrimary(sapi_ctx,
                                         hierarchy,
                                         &sessionsData,
                                         &inSensitive,
                                         &in_public,
                                         &outsideInfo,
                                         &creationPCR,
                                         &tmp_primary_handle,
                                         &public_key,
                                         &creationData,
                                         &creationHash,
                                         &creationTicket,
                                         &name,
                                         &sessionsDataOut);

    if (TSS2_RC_SUCCESS != ret)
        return ret;

    // Persist primary key
    ret = evict_control(sapi_ctx,
                        hierarchy,
                        tmp_primary_handle,
                        primary_handle,
                        hierarchy_password,
                        hierarchy_password_length);

    if (TSS2_RC_SUCCESS != ret)
        return ret;

    ret = Tss2_Sys_FlushContext(sapi_ctx,
                                tmp_primary_handle);

    return ret;
}

TSS2_RC
create_child(TSS2_SYS_CONTEXT *sapi_ctx,
             TPM2_HANDLE parent_handle,
             TPM2B_PUBLIC *public_key_out,
             TPM2B_PRIVATE *private_key_blob_out)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    // Nb. No auth set on key
    TPM2B_SENSITIVE_CREATE inSensitive = {};

    TPM2B_PUBLIC in_public = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {},
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                  },
                 .scheme = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                 },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {
                    .scheme = TPM2_ALG_NULL,
                    .details = {}
                 },
             },
            .unique.ecc = {}
         }
    };

    TPM2B_DATA outsideInfo = {};

    TPML_PCR_SELECTION creationPCR = {};

    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {};
    TPMT_TK_CREATION creationTicket = {};

    return Tss2_Sys_Create(sapi_ctx,
                           parent_handle,
                           &sessionsData,
                           &inSensitive,
                           &in_public,
                           &outsideInfo,
                           &creationPCR,
                           private_key_blob_out,
                           public_key_out,
                           &creationData,
                           &creationHash,
                           &creationTicket,
                           &sessionsDataOut);
}

TSS2_RC
load_key(TSS2_SYS_CONTEXT *sapi_ctx,
         TPM2_HANDLE parent_handle,
         const TPM2B_PUBLIC *public_key,
         const TPM2B_PRIVATE *private_key_blob,
         TPM2_HANDLE *handle_out)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPM2B_NAME name = {};

    return Tss2_Sys_Load(sapi_ctx,
                         parent_handle,
                         &sessionsData,
                         private_key_blob,
                         public_key,
                         handle_out,
                         &name,
                         &sessionsDataOut);
}

TSS2_RC
evict_control(TSS2_SYS_CONTEXT *sapi_ctx,
              TPMI_RH_HIERARCHY hierarchy,
              TPM2_HANDLE current_handle,
              TPM2_HANDLE persistent_handle,
              const char *hierarchy_password,
              size_t hierarchy_password_length)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.count = 1;
    if (0 != hierarchy_password_length) {
        if (hierarchy_password_length > sizeof(sessionsData.auths[0].hmac.buffer))
            return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
        sessionsData.auths[0].hmac.size = hierarchy_password_length;
        memcpy(sessionsData.auths[0].hmac.buffer, hierarchy_password, hierarchy_password_length);
    }

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    return Tss2_Sys_EvictControl(sapi_ctx,
                                 hierarchy,
                                 current_handle,
                                 &sessionsData,
                                 persistent_handle,
                                 &sessionsDataOut);
}

TSS2_RC
sign(TSS2_SYS_CONTEXT *sapi_ctx,
     TPM2_HANDLE key_handle,
     const TPM2B_DIGEST *digest,
     TPMT_SIGNATURE *signature_out)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = {};
    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    sessionsData.count = 1;

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {.count = 1};

    TPMT_SIG_SCHEME inScheme = {};
    inScheme.scheme = TPM2_ALG_ECDSA;
	inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;

    // Hash was *not* generated by TPM,
    // so tell TPM not to check it (i.e. pass a "NULL ticket").
    TPMT_TK_HASHCHECK validation = {};
	validation.tag = TPM2_ST_HASHCHECK;
	validation.hierarchy = TPM2_RH_NULL;

    return Tss2_Sys_Sign(sapi_ctx,
                         key_handle,
                         &sessionsData,
                         digest,
                         &inScheme,
                         &validation,
                         signature_out,
                         &sessionsDataOut);
}
