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

#include "marshal.h"

#include <string.h>

#define BIT_ZERO 1
#define BIT_ONE 2
#define BIT_TWO 4
#define BIT_THREE 8
#define BIT_FOUR 16
#define BIT_FIVE 32
#define BIT_SIX 64
#define BIT_SEVEN 128

#include <assert.h>

typedef struct {
    uint16_t size;
    uint8_t buffer[TPM2_SHA512_DIGEST_SIZE];
} TPM2B_SIMPLE;

static
void marshal_uint16(uint16_t in, uint8_t **out);

static
void marshal_tpms_ecc_point(const TPMS_ECC_POINT *in, uint8_t **out);

static
void marshal_tpm2b_simple(const TPM2B_SIMPLE *in, uint8_t **out);

static
void marshal_tpmi_alg_id(TPM2_ALG_ID in, uint8_t **out);

static
void  marshal_tpma_object(const TPMA_OBJECT *in, uint8_t **out);

static
void marshal_tpmt_sym_def_object(const TPMT_SYM_DEF_OBJECT *in, uint8_t **out);

static
void marshal_tpmt_ecc_scheme(const TPMT_ECC_SCHEME * in, uint8_t **out);

static
void marshal_tpms_ecc_parms(const TPMS_ECC_PARMS *in, uint8_t **out);

void marshal_uint32(uint32_t in, uint8_t **out)
{
    (*out)[0] = (unsigned char)(in >> 24);  /* 3*8 */
    (*out)[1] = (unsigned char)(in >> 16);  /* 2*8 */
    (*out)[2] = (unsigned char)(in >> 8);   /* 1*8 */
    (*out)[3] = (unsigned char)(in);        /* 0*8 */

    *out += sizeof(uint32_t);
}

void marshal_tpm2b_public(const TPM2B_PUBLIC *in, uint8_t **out)
{
    uint8_t *size_ptr = *out;
    *out += sizeof(uint16_t);

    marshal_tpmi_alg_id(in->publicArea.type, out);

    marshal_tpmi_alg_id(in->publicArea.nameAlg, out);

    marshal_tpma_object(&in->publicArea.objectAttributes, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->publicArea.authPolicy, out);

    switch (in->publicArea.type) {
        case TPM2_ALG_ECC:
            marshal_tpms_ecc_parms(&in->publicArea.parameters.eccDetail, out);
            marshal_tpms_ecc_point(&in->publicArea.unique.ecc, out);
            break;
    }

    uint16_t size = *out - size_ptr - sizeof(uint16_t);
    marshal_uint16(size, &size_ptr);
}

void marshal_tpm2b_private(const TPM2B_PRIVATE *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

/*
 * Private functions
 */

void marshal_uint16(uint16_t in, uint8_t **out)
{
    (*out)[0] = (unsigned char)(in >> 8);   /* 1*8 */
    (*out)[1] = (unsigned char)(in);        /* 0*8 */

    *out += sizeof(uint16_t);
}

void marshal_tpms_ecc_point(const TPMS_ECC_POINT *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->x, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->y, out);
}

void marshal_tpm2b_simple(const TPM2B_SIMPLE *in, uint8_t **out)
{
    marshal_uint16(in->size, out);
    memcpy(*out, in->buffer, in->size);
    *out += in->size;
}

void marshal_tpmi_alg_id(TPM2_ALG_ID in, uint8_t **out)
{
    marshal_uint16(in, out);
}

void  marshal_tpma_object(const TPMA_OBJECT *in, uint8_t **out)
{
    memset(*out, 0, 4);  // clear all

    // bit zero is reserved
    if (*in & TPMA_OBJECT_FIXEDTPM)
        (*out)[3] |= BIT_ONE;
    if (*in & TPMA_OBJECT_STCLEAR)
        (*out)[3] |= BIT_TWO;
    // bit three is reserved
    if (*in & TPMA_OBJECT_FIXEDPARENT)
        (*out)[3] |= BIT_FOUR;
    if (*in & TPMA_OBJECT_SENSITIVEDATAORIGIN)
        (*out)[3] |= BIT_FIVE;
    if (*in & TPMA_OBJECT_USERWITHAUTH)
        (*out)[3] |= BIT_SIX;
    if (*in & TPMA_OBJECT_ADMINWITHPOLICY)
        (*out)[3] |= BIT_SEVEN;
    // bit 8 is reserved
    // bit 9 is reserved
    if (*in & TPMA_OBJECT_NODA)
        (*out)[2] |= BIT_TWO;
    if (*in & TPMA_OBJECT_ENCRYPTEDDUPLICATION)
        (*out)[2] |= BIT_THREE;
    // bit 12 is reserved
    // bit 13 is reserved
    // bit 14 is reserved
    // bit 15 is reserved
    if (*in & TPMA_OBJECT_RESTRICTED)
        (*out)[1] |= BIT_ZERO;
    if (*in & TPMA_OBJECT_DECRYPT)
        (*out)[1] |= BIT_ONE;
    if (*in & TPMA_OBJECT_SIGN_ENCRYPT)
        (*out)[1] |= BIT_TWO;
    // bits 19-31 are reserved

    *out += 4;
}

void marshal_tpmt_sym_def_object(const TPMT_SYM_DEF_OBJECT *in, uint8_t **out)
{
    switch (in->algorithm) {
        case TPM2_ALG_NULL:
            marshal_uint16(TPM2_ALG_NULL, out);
            break;
        case TPM2_ALG_AES:
            marshal_uint16(TPM2_ALG_AES, out);
            marshal_uint16(in->keyBits.aes, out);
            marshal_tpmi_alg_id(in->mode.sym, out);
            break;
    }
}

void marshal_tpmt_ecc_scheme(const TPMT_ECC_SCHEME * in, uint8_t **out)
{
    marshal_tpmi_alg_id(in->scheme, out);

    switch (in->scheme) {
        case TPM2_ALG_ECDAA:
            marshal_tpmi_alg_id(in->details.ecdaa.hashAlg, out);
            marshal_uint16(in->details.ecdaa.count, out);
            break;
        case TPM2_ALG_ECDSA:
            marshal_tpmi_alg_id(in->details.ecdsa.hashAlg, out);
            break;
    }
}

void marshal_tpms_ecc_parms(const TPMS_ECC_PARMS *in, uint8_t **out)
{
    marshal_tpmt_sym_def_object(&in->symmetric, out);

    marshal_tpmt_ecc_scheme(&in->scheme, out);

    marshal_tpmi_alg_id(in->curveID, out);

    marshal_tpmi_alg_id(in->kdf.scheme, out);

    assert(in->kdf.scheme == TPM2_ALG_NULL);
}

