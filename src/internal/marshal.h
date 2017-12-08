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

void marshal_tpms_ecc_point(TPMS_ECC_POINT *in, uint8_t **out);

int unmarshal_tpm2b_public(uint8_t **in, uint32_t *in_max_length, TPM2B_PUBLIC *out);
void marshal_tpm2b_public(TPM2B_PUBLIC *in, uint8_t **out);

void marshal_tpm2b_data(TPM2B_DATA *in, uint8_t **out);

void marshal_tpml_pcrselection(TPML_PCR_SELECTION *in, uint8_t **out);

void marshal_tpms_authcommand(TPMS_AUTH_COMMAND *in, uint8_t **out);

int unmarshal_tpms_authresponse(uint8_t **in, uint32_t *in_max_length, TPMS_AUTH_RESPONSE *out);

void marshal_tpm2b_sensitivecreate(TPM2B_SENSITIVE_CREATE *in, uint8_t **out);

int unmarshal_tpm2b_creationdata(uint8_t **in, uint32_t *in_max_length, TPM2B_CREATION_DATA *out);

void marshal_tpm2b_digest(TPM2B_DIGEST *in, uint8_t **out);

int unmarshal_tpm2b_digest(uint8_t **in, uint32_t *in_max_length, TPM2B_DIGEST *out);

int unmarshal_tpmt_tkcreation(uint8_t **in, uint32_t *in_max_length, TPMT_TK_CREATION *out);

int unmarshal_tpm2b_name(uint8_t **in, uint32_t *in_max_length, TPM2B_NAME *out);

void marshal_tpm2b_eccpoint(TPM2B_ECC_POINT *in, uint8_t **out);

int unmarshal_tpm2b_eccpoint(uint8_t **in, uint32_t *in_max_length, TPM2B_ECC_POINT *out);

void marshal_tpm2b_sensitivedata(TPM2B_SENSITIVE_DATA *in, uint8_t **out);

void marshal_tpm2b_eccparameter(TPM2B_ECC_PARAMETER *in, uint8_t **out);

void marshal_tpmt_sigscheme(TPMT_SIG_SCHEME *in, uint8_t **out);

void marshal_tpmt_tkhashcheck(TPMT_TK_HASHCHECK *in, uint8_t **out);

int unmarshal_tpmt_signature(uint8_t **in, uint32_t *in_max_length, TPMT_SIGNATURE *out);

#ifdef __cplusplus
}
#endif

#endif

