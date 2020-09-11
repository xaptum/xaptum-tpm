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

#ifndef XAPTUM_TSS2_SYS_H
#define XAPTUM_TSS2_SYS_H
#pragma once

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tcti.h>

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _TSS2_SYS_OPAQUE_CONTEXT_BLOB TSS2_SYS_CONTEXT;

#define TSS2_SYS_MAX_SESSIONS 3

typedef struct {
    uint16_t count;
    TPMS_AUTH_COMMAND auths[TSS2_SYS_MAX_SESSIONS];
} TSS2L_SYS_AUTH_COMMAND;

typedef struct {
    uint16_t count;
    TPMS_AUTH_RESPONSE auths[TSS2_SYS_MAX_SESSIONS];
} TSS2L_SYS_AUTH_RESPONSE;

//
// Command context allocation functions
//

size_t
Tss2_Sys_GetContextSize(size_t maxCommandResponseSize);

TSS2_RC
Tss2_Sys_Initialize(TSS2_SYS_CONTEXT *sysContext,
                    size_t contextSize,
                    TSS2_TCTI_CONTEXT *tctiContext,
                    TSS2_ABI_VERSION *abiVersion);

TSS2_RC
Tss2_Sys_Finalize(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC
Tss2_Sys_GetTctiContext(TSS2_SYS_CONTEXT *sysContext,
                        TSS2_TCTI_CONTEXT **tctiContext);

//
// Part 3 Functions
//

TSS2_RC
Tss2_Sys_CreatePrimary(TSS2_SYS_CONTEXT *sysContext,
                       TPMI_RH_HIERARCHY primaryHandle,
                       const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                       const TPM2B_SENSITIVE_CREATE *inSensitive,
                       const TPM2B_PUBLIC *inPublic,
                       const TPM2B_DATA *outsideInfo,
                       const TPML_PCR_SELECTION *creationPCR,
                       TPM2_HANDLE *objectHandle,
                       TPM2B_PUBLIC *outPublic,
                       TPM2B_CREATION_DATA *creationData,
                       TPM2B_DIGEST *creationHash,
                       TPMT_TK_CREATION *creationTicket,
                       TPM2B_NAME *name,
                       TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_Create(TSS2_SYS_CONTEXT *sysContext,
                TPMI_DH_OBJECT parentHandle,
                const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                const TPM2B_SENSITIVE_CREATE *inSensitive,
                const TPM2B_PUBLIC *inPublic,
                const TPM2B_DATA *outsideInfo,
                const TPML_PCR_SELECTION *creationPCR,
                TPM2B_PRIVATE *outPrivate,
                TPM2B_PUBLIC *outPublic,
                TPM2B_CREATION_DATA *creationData,
                TPM2B_DIGEST *creationHash,
                TPMT_TK_CREATION *creationTicket,
                TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_Commit(TSS2_SYS_CONTEXT *sysContext,
                TPMI_DH_OBJECT signHandle,
                const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                const TPM2B_ECC_POINT *P1,
                const TPM2B_SENSITIVE_DATA *s2,
                const TPM2B_ECC_PARAMETER *y2,
                TPM2B_ECC_POINT *K,
                TPM2B_ECC_POINT *L,
                TPM2B_ECC_POINT *E,
                uint16_t *counter,
                TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_Sign(TSS2_SYS_CONTEXT *sysContext,
              TPMI_DH_OBJECT keyHandle,
              const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
              const TPM2B_DIGEST *digest,
              const TPMT_SIG_SCHEME *inScheme,
              const TPMT_TK_HASHCHECK *validation,
              TPMT_SIGNATURE *signature,
              TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_NV_DefineSpace(TSS2_SYS_CONTEXT *sysContext,
                        TPMI_RH_PROVISION authHandle,
                        const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                        const TPM2B_AUTH *auth,
                        const TPM2B_NV_PUBLIC *publicInfo,
                        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_NV_Write(TSS2_SYS_CONTEXT *sysContext,
                  TPMI_RH_NV_AUTH authHandle,
                  TPMI_RH_NV_INDEX nvIndex,
                  const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                  const TPM2B_MAX_NV_BUFFER *data,
                  uint16_t offset,
                  TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_NV_Read(TSS2_SYS_CONTEXT *sysContext,
                 TPMI_RH_NV_AUTH authHandle,
                 TPMI_RH_NV_INDEX nvIndex,
                 const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                 uint16_t size,
                 uint16_t offset,
                 TPM2B_MAX_NV_BUFFER *data,
                 TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_NV_ReadPublic(TSS2_SYS_CONTEXT *sysContext,
                       TPMI_RH_NV_INDEX nvIndex,
                       const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                       TPM2B_NV_PUBLIC *nvPublic,
                       TPM2B_NAME *nvName,
                       TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_NV_UndefineSpace(TSS2_SYS_CONTEXT *sysContext,
                          TPMI_RH_PROVISION authHandle,
                          TPMI_RH_NV_INDEX nvIndex,
                          const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                          TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_HierarchyChangeAuth(TSS2_SYS_CONTEXT *sysContext,
                             TPMI_RH_HIERARCHY_AUTH authHandle,
                             const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                             TPM2B_AUTH *newAuth,
                             TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_Load(TSS2_SYS_CONTEXT *sysContext,
              TPMI_DH_OBJECT parentHandle,
              const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
              const TPM2B_PRIVATE *inPrivate,
              const TPM2B_PUBLIC *inPublic,
              TPM2_HANDLE *objectHandle,
              TPM2B_NAME *name,
              TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_EvictControl(TSS2_SYS_CONTEXT *sysContext,
                      TPMI_RH_PROVISION auth,
                      TPMI_DH_OBJECT objectHandle,
                      const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                      TPMI_DH_PERSISTENT persistentHandle,
                      TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_Clear(TSS2_SYS_CONTEXT *sysContext,
               TPMI_RH_CLEAR authHandle,
               const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
               TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_ReadPublic(TSS2_SYS_CONTEXT *sysContext,
                    TPMI_DH_OBJECT objectHandle,
                    const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                    TPM2B_PUBLIC *outPublic,
                    TPM2B_NAME *name,
                    TPM2B_NAME *qualifiedName,
                    TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray);

TSS2_RC
Tss2_Sys_FlushContext(TSS2_SYS_CONTEXT *sysContext,
                      TPMI_DH_CONTEXT flushHandle);

#ifdef __cplusplus
}
#endif

#endif

