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

/*
 * TSS serialization, adapted from `tss2/src/internal/marshal`.
 */

#ifndef XAPTUM_TPM_INTERNAL_MARSHAL_H
#define XAPTUM_TPM_INTERNAL_MARSHAL_H
#pragma once

#include <tss2/tss2_tpm2_types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void marshal_uint32(uint32_t in, uint8_t **out);

void marshal_tpm2b_public(const TPM2B_PUBLIC *in, uint8_t **out);

void marshal_tpm2b_private(const TPM2B_PRIVATE *in, uint8_t **out);

#ifdef __cplusplus
}
#endif

#endif

