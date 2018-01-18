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

#ifndef XAPTUM_TPM_INTERNAL_MARSHAL_H
#define XAPTUM_TPM_INTERNAL_MARSHAL_H
#pragma once

#include <tss2/tss2_tpm2_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int unmarshal_uint32(uint8_t **in, uint32_t *in_max_length, uint32_t *out);
void marshal_uint32(uint32_t in, uint8_t **out);

int unmarshal_uint16(uint8_t **in, uint32_t *in_max_length, uint16_t *out);
void marshal_uint16(uint16_t in, uint8_t **out);

void marshal_tpms_ecc_point(const TPMS_ECC_POINT *in, uint8_t **out);

int unmarshal_tpm2b_public(uint8_t **in, uint32_t *in_max_length, TPM2B_PUBLIC *out);
void marshal_tpm2b_public(const TPM2B_PUBLIC *in, uint8_t **out);

void marshal_tpm2b_data(const TPM2B_DATA *in, uint8_t **out);

void marshal_tpml_pcrselection(const TPML_PCR_SELECTION *in, uint8_t **out);

void marshal_tpms_authcommand(const TPMS_AUTH_COMMAND *in, uint8_t **out);

int unmarshal_tpms_authresponse(uint8_t **in, uint32_t *in_max_length, TPMS_AUTH_RESPONSE *out);

void marshal_tpm2b_sensitivecreate(const TPM2B_SENSITIVE_CREATE *in, uint8_t **out);

int unmarshal_tpm2b_creationdata(uint8_t **in, uint32_t *in_max_length, TPM2B_CREATION_DATA *out);

void marshal_tpm2b_digest(const TPM2B_DIGEST *in, uint8_t **out);

int unmarshal_tpm2b_digest(uint8_t **in, uint32_t *in_max_length, TPM2B_DIGEST *out);

int unmarshal_tpmt_tkcreation(uint8_t **in, uint32_t *in_max_length, TPMT_TK_CREATION *out);

int unmarshal_tpm2b_name(uint8_t **in, uint32_t *in_max_length, TPM2B_NAME *out);

void marshal_tpm2b_eccpoint(const TPM2B_ECC_POINT *in, uint8_t **out);

int unmarshal_tpm2b_eccpoint(uint8_t **in, uint32_t *in_max_length, TPM2B_ECC_POINT *out);

void marshal_tpm2b_sensitivedata(const TPM2B_SENSITIVE_DATA *in, uint8_t **out);

void marshal_tpm2b_eccparameter(const TPM2B_ECC_PARAMETER *in, uint8_t **out);

void marshal_tpmt_sigscheme(const TPMT_SIG_SCHEME *in, uint8_t **out);

void marshal_tpmt_tkhashcheck(const TPMT_TK_HASHCHECK *in, uint8_t **out);

int unmarshal_tpmt_signature(uint8_t **in, uint32_t *in_max_length, TPMT_SIGNATURE *out);

void marshal_tpm2b_auth(const TPM2B_AUTH *in, uint8_t **out);

void marshal_tpm2b_nvpublic(const TPM2B_NV_PUBLIC *in, uint8_t **out);

void marshal_tpm2b_maxnvbuffer(const TPM2B_MAX_NV_BUFFER *in, uint8_t **out);

int unmarshal_tpm2b_maxnvbuffer(uint8_t **in, uint32_t *in_max_length, TPM2B_MAX_NV_BUFFER *out);

void marshal_tpm2b_private(const TPM2B_PRIVATE *in, uint8_t **out);

int unmarshal_tpm2b_private(uint8_t **in, uint32_t *in_max_length, TPM2B_PRIVATE *out);

#ifdef __cplusplus
}
#endif

#endif

