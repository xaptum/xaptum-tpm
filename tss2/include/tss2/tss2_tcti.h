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

#ifndef XAPTUM_TSS2_TCTI_H
#define XAPTUM_TSS2_TCTI_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "tss2_common.h"

#include <stdint.h>
#include <stddef.h>

// Polling is _not_ supported in this implementation.
typedef void TSS2_TCTI_POLL_HANDLE;

// The following are used to configure timeout characteristics.
#define TSS2_TCTI_TIMEOUT_BLOCK -1
#define TSS2_TCTI_TIMEOUT_NONE 0

typedef struct TSS2_TCTI_OPAQUE_CONTEXT_BLOB TSS2_TCTI_CONTEXT;

/* superclass to get the version */
typedef struct {
    uint64_t magic;
    uint32_t version;
} TSS2_TCTI_CONTEXT_VERSION;

/* current version #1 known to this implementation */
typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_RC (*transmit)( TSS2_TCTI_CONTEXT *tctiContext, size_t size,
            uint8_t *command);
    TSS2_RC (*receive) (TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
            uint8_t *response, int32_t timeout);
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
            TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
} TSS2_TCTI_CONTEXT_COMMON_V1;
typedef TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT_COMMON_CURRENT;

#define Tss2_Tcti_Transmit(tctiContext, size, command) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
     (((TSS2_TCTI_CONTEXT_VERSION *)tctiContext)->version < 1) ? \
     TSS2_TCTI_RC_ABI_MISMATCH: \
     (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->transmit == NULL) ? \
     TSS2_TCTI_RC_NOT_IMPLEMENTED: \
     ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->transmit(tctiContext, size, command))

#define Tss2_Tcti_Receive(tctiContext, size, response, timeout) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
     (((TSS2_TCTI_CONTEXT_VERSION *)tctiContext)->version < 1) ? \
     TSS2_TCTI_RC_ABI_MISMATCH: \
     (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->receive == NULL) ? \
     TSS2_TCTI_RC_NOT_IMPLEMENTED: \
     ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->receive(tctiContext, size, response, timeout))

#define Tss2_Tcti_Finalize(tctiContext) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
     (((TSS2_TCTI_CONTEXT_VERSION *)tctiContext)->version < 1) ? \
     TSS2_TCTI_RC_ABI_MISMATCH: \
     (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->finalize == NULL) ? \
     TSS2_TCTI_RC_NOT_IMPLEMENTED: \
     ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->finalize(tctiContext))

#define Tss2_Tcti_Cancel(tctiContext) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
     (((TSS2_TCTI_CONTEXT_VERSION *)tctiContext)->version < 1) ? \
     TSS2_TCTI_RC_ABI_MISMATCH: \
     (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel == NULL) ? \
     TSS2_TCTI_RC_NOT_IMPLEMENTED: \
     ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->cancel(tctiContext))

#define Tss2_Tcti_GetPollHandles(tctiContext, handles, num_handles) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
     (((TSS2_TCTI_CONTEXT_VERSION *)tctiContext)->version < 1) ? \
     TSS2_TCTI_RC_ABI_MISMATCH: \
     (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->getPollHandles == NULL) ? \
     TSS2_TCTI_RC_NOT_IMPLEMENTED: \
     ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->getPollHandles(tctiContext, handles, num_handles))

#define Tss2_Tcti_SetLocality(tctiContext, locality) \
    ((tctiContext == NULL) ? TSS2_TCTI_RC_BAD_CONTEXT: \
     (((TSS2_TCTI_CONTEXT_VERSION *)tctiContext)->version < 1) ? \
     TSS2_TCTI_RC_ABI_MISMATCH: \
     (((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->setLocality == NULL) ? \
     TSS2_TCTI_RC_NOT_IMPLEMENTED: \
     ((TSS2_TCTI_CONTEXT_COMMON_V1 *)tctiContext)->setLocality(tctiContext, locality))

#ifdef __cplusplus
}
#endif

#endif

