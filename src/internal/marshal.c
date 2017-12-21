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
    uint8_t buffer[MAX_ECC_KEY_BYTES];
} TPM2B_SIMPLE;

int unmarshal_uint32(uint8_t **in, uint32_t *in_max_length, uint32_t *out)
{
    if (*in_max_length < sizeof(uint32_t))
        return -1;

    *out = (uint32_t)((*in)[3]);
    *out |= (uint32_t)((*in)[2]) << 8;
    *out |= (uint32_t)((*in)[1]) << 16;
    *out |= (uint32_t)((*in)[0]) << 24;

    *in += sizeof(uint32_t);
    *in_max_length -= sizeof(uint32_t);

    return 0;
}

void marshal_uint32(uint32_t in, uint8_t **out)
{
    (*out)[0] = (unsigned char)(in >> 24);  /* 3*8 */
    (*out)[1] = (unsigned char)(in >> 16);  /* 2*8 */
    (*out)[2] = (unsigned char)(in >> 8);   /* 1*8 */
    (*out)[3] = (unsigned char)(in);        /* 0*8 */

    *out += sizeof(uint32_t);
}

int unmarshal_uint16(uint8_t **in, uint32_t *in_max_length, uint16_t *out)
{
    if (*in_max_length < sizeof(uint16_t))
        return -1;

    *out = (uint16_t)((*in)[1]);
    *out |= (uint16_t)((*in)[0]) << 8;

    *in += sizeof(uint16_t);
    *in_max_length -= sizeof(uint16_t);

    return 0;
}

void marshal_uint16(uint16_t in, uint8_t **out)
{
    (*out)[0] = (unsigned char)(in >> 8);   /* 1*8 */
    (*out)[1] = (unsigned char)(in);        /* 0*8 */

    *out += sizeof(uint16_t);
}

void marshal_tpmi_alg_id(TPM_ALG_ID in, uint8_t **out)
{
    marshal_uint16(in, out);
}

int unmarshal_tpmi_alg_id(uint8_t **in, uint32_t *in_max_length, TPM_ALG_ID *out)
{
    return unmarshal_uint16(in, in_max_length, out);
}

void  marshal_tpma_object(TPMA_OBJECT *in, uint8_t **out)
{
    memset(*out, 0, 4);  // clear all

    // bit zero is reserved
    if (in->fixedTPM)
        (*out)[3] |= BIT_ONE;
    if (in->stClear)
        (*out)[3] |= BIT_TWO;
    // bit three is reserved
    if (in->fixedParent)
        (*out)[3] |= BIT_FOUR;
    if (in->sensitiveDataOrigin)
        (*out)[3] |= BIT_FIVE;
    if (in->userWithAuth)
        (*out)[3] |= BIT_SIX;
    if (in->adminWithPolicy)
        (*out)[3] |= BIT_SEVEN;
    // bit 8 is reserved
    // bit 9 is reserved
    if (in->noDA)
        (*out)[2] |= BIT_TWO;
    if (in->encryptedDuplication)
        (*out)[2] |= BIT_THREE;
    // bit 12 is reserved
    // bit 13 is reserved
    // bit 14 is reserved
    // bit 15 is reserved
    if (in->restricted)
        (*out)[1] |= BIT_ZERO;
    if (in->decrypt)
        (*out)[1] |= BIT_ONE;
    if (in->sign)
        (*out)[1] |= BIT_TWO;
    // bits 19-31 are reserved

    *out += 4;
}

int  unmarshal_tpma_object(uint8_t **in, uint32_t *in_max_length, TPMA_OBJECT *out)
{
    memset(out, 0, sizeof(TPMA_OBJECT));  // clear all

    // bit zero is reserved
    if ((*in)[3] & BIT_ONE)
        out->fixedTPM = 1;
    if ((*in)[3] & BIT_TWO)
        out->stClear = 1;
    // bit three is reserved
    if ((*in)[3] & BIT_FOUR)
        out->fixedParent = 1;
    if ((*in)[3] & BIT_FIVE)
        out->sensitiveDataOrigin = 1;
    if ((*in)[3] & BIT_SIX)
        out->userWithAuth = 1;
    if ((*in)[3] & BIT_SEVEN)
        out->adminWithPolicy = 1;
    // bit 8 is reserved
    // bit 9 is reserved
    if ((*in)[2] & BIT_TWO)
        out->noDA = 1;
    if ((*in)[2] & BIT_THREE)
        out->encryptedDuplication = 1;
    // bit 12 is reserved
    // bit 13 is reserved
    // bit 14 is reserved
    // bit 15 is reserved
    if ((*in)[1] & BIT_ZERO)
        out->restricted = 1;
    if ((*in)[1] & BIT_ONE)
        out->decrypt = 1;
    if ((*in)[1] & BIT_TWO)
        out->sign = 1;
    // bits 19-31 are reserved

    *in += 4;
    *in_max_length -= 4;

    return 0;
}

void marshal_tpm2b_simple(TPM2B_SIMPLE *in, uint8_t **out)
{
    marshal_uint16(in->size, out);
    memcpy(*out, in->buffer, in->size);
    *out += in->size;
}

int unmarshal_tpm2b_simple(uint8_t **in, uint32_t *in_max_length, TPM2B_SIMPLE *out)
{
    if (0 != unmarshal_uint16(in, in_max_length, &out->size))
        return -1;
    
    if (*in_max_length < out->size)
        return -1;
    memcpy(out->buffer, *in, out->size);

    *in += out->size;
    *in_max_length -= out->size;

    return 0;
}

void marshal_tpmt_sym_def_object(TPMT_SYM_DEF_OBJECT *in, uint8_t **out)
{
    switch (in->algorithm) {
        case TPM_ALG_NULL:
            marshal_uint16(TPM_ALG_NULL, out);
    }
}

int unmarshal_tpmt_sym_def_object(uint8_t **in, uint32_t *in_max_length, TPMT_SYM_DEF_OBJECT *out)
{
    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->algorithm))
        return -1;

    switch (out->algorithm) {
        case TPM_ALG_NULL:
            // Don't do anything
            (void)in;
            (void)in_max_length;
            (void)out;
            break;
        default:
            return -2;
    }

    return 0;
}

void marshal_tpmt_ecc_scheme(TPMT_ECC_SCHEME * in, uint8_t **out)
{
    marshal_tpmi_alg_id(in->scheme, out);

    switch (in->scheme) {
        case TPM_ALG_ECDAA:
            marshal_tpmi_alg_id(in->details.ecdaa.hashAlg, out);
            marshal_uint16(in->details.ecdaa.count, out);
            break;
    }
}

int unmarshal_tpmt_ecc_scheme(uint8_t **in, uint32_t *in_max_length, TPMT_ECC_SCHEME *out)
{
    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->scheme))
        return -1;

    switch (out->scheme) {
        case TPM_ALG_ECDAA:
            if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->details.ecdaa.hashAlg))
                return -1;

            if (0 != unmarshal_uint16(in, in_max_length, &out->details.ecdaa.count))
                return -1;

            break;
        default:
            return -2;
    }

    return 0;
}

void marshal_tpms_ecc_parms(TPMS_ECC_PARMS *in, uint8_t **out)
{
    marshal_tpmt_sym_def_object(&in->symmetric, out);

    marshal_tpmt_ecc_scheme(&in->scheme, out);

    marshal_tpmi_alg_id(in->curveID, out);

    marshal_tpmi_alg_id(in->kdf.scheme, out);

    assert(in->kdf.scheme == TPM_ALG_NULL);
}

int unmarshal_tpms_ecc_parms(uint8_t **in, uint32_t *in_max_length, TPMS_ECC_PARMS *out)
{
    if (0 != unmarshal_tpmt_sym_def_object(in, in_max_length, &out->symmetric))
        return -1;

    if (0 != unmarshal_tpmt_ecc_scheme(in, in_max_length, &out->scheme))
        return -1;

    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->curveID))
        return -1;

    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->kdf.scheme))
        return -1;
    assert(out->kdf.scheme == TPM_ALG_NULL);

    return 0;
}

void marshal_tpms_ecc_point(TPMS_ECC_POINT *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->x, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->y, out);
}

int unmarshal_tpms_ecc_point(uint8_t **in, uint32_t *in_max_length, TPMS_ECC_POINT *out)
{
    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->x))
        return -1;

    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->y))
        return -1;

    return 0;
}

void marshal_tpm2b_public(TPM2B_PUBLIC *in, uint8_t **out)
{
    uint8_t *size_ptr = *out;
    *out += sizeof(uint16_t);

    marshal_tpmi_alg_id(in->publicArea.type, out);

    marshal_tpmi_alg_id(in->publicArea.nameAlg, out);

    marshal_tpma_object(&in->publicArea.objectAttributes, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->publicArea.authPolicy, out);

    switch (in->publicArea.type) {
        case TPM_ALG_ECC:
            marshal_tpms_ecc_parms(&in->publicArea.parameters.eccDetail, out);
            marshal_tpms_ecc_point(&in->publicArea.unique.ecc, out);
            break;
    }

    uint16_t size = *out - size_ptr - sizeof(uint16_t);
    marshal_uint16(size, &size_ptr);
}

int unmarshal_tpm2b_public(uint8_t **in, uint32_t *in_max_length, TPM2B_PUBLIC *out)
{
    if (0 != unmarshal_uint16(in, in_max_length, &out->size))
        return -1;
    if (*in_max_length < out->size)
        return -1;

    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->publicArea.type))
        return -1;

    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->publicArea.nameAlg))
        return -1;

    if (0 != unmarshal_tpma_object(in, in_max_length, &out->publicArea.objectAttributes))
        return -1;

    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->publicArea.authPolicy))
        return -1;

    switch (out->publicArea.type) {
        case TPM_ALG_ECC:
            if (0 != unmarshal_tpms_ecc_parms(in, in_max_length, &out->publicArea.parameters.eccDetail))
                return -1;

            if (0 != unmarshal_tpms_ecc_point(in, in_max_length, &out->publicArea.unique.ecc))
                return -1;
            break;
        default:
            return -2;
    }

    return 0;
}

void marshal_tpm2b_data(TPM2B_DATA *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

void marshal_tpml_pcrselection(TPML_PCR_SELECTION *in, uint8_t **out)
{
    marshal_uint32(in->count, out);

    for (unsigned i=0; i < in->count; i++) {
        marshal_tpmi_alg_id(in->pcrSelections[i].hash, out);

        **out = in->pcrSelections[i].sizeofSelect;
        *out += 1;

        memcpy(*out, in->pcrSelections[i].pcrSelect, in->pcrSelections[i].sizeofSelect);
        *out += in->pcrSelections[i].sizeofSelect;
    }
}

int unmarshal_tpml_pcrselection(uint8_t **in, uint32_t *in_max_length, TPML_PCR_SELECTION *out)
{
    if (0 != unmarshal_uint32(in, in_max_length, &out->count))
        return -1;

    for (unsigned i=0; i < out->count; i++) {
        if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->pcrSelections[i].hash))
            return -1;

        if (*in_max_length < 1)
            return -1;
        out->pcrSelections[i].sizeofSelect = **in;
        *in += 1;
        *in_max_length -= 1;

        if (*in_max_length < out->pcrSelections[i].sizeofSelect)
            return -1;
        memcpy(out->pcrSelections[i].pcrSelect, *in, out->pcrSelections[i].sizeofSelect);
        *in += out->pcrSelections[i].sizeofSelect;
        *in_max_length -= out->pcrSelections[i].sizeofSelect;
    }

    return 0;
}

void marshal_tpma_session(TPMA_SESSION *in, uint8_t **out)
{
    memset(*out, 0, 1);  // clear all

    if (in->continueSession)
        (*out)[0] |= BIT_ZERO;
    if (in->auditExclusive)
        (*out)[0] |= BIT_ONE;
    if (in->auditReset)
        (*out)[0] |= BIT_TWO;
    // bit three is reserved
    // bit four is reserved
    if (in->decrypt)
        (*out)[0] |= BIT_FIVE;
    if (in->encrypt)
        (*out)[0] |= BIT_SIX;
    if (in->audit)
        (*out)[0] |= BIT_SEVEN;

    *out += 1;
}

int unmarshal_tpma_session(uint8_t **in, uint32_t *in_max_length, TPMA_SESSION *out)
{
    if (*in_max_length < 1)
        return -1;

    memset(out, 0, sizeof(TPMA_SESSION));  // clear all

    if ((*in[0]) & BIT_ZERO)
        out->continueSession = 1;
    if ((*in[0]) & BIT_ONE)
        out->auditExclusive = 1;
    if ((*in[0]) & BIT_TWO)
        out->auditReset = 1;
    // bit three is reserved
    // bit four is reserved
    if ((*in[0]) & BIT_FIVE)
        out->decrypt = 1;
    if ((*in[0]) & BIT_SIX)
        out->encrypt = 1;
    if ((*in[0]) & BIT_SEVEN)
        out->audit = 1;

    *in += 1;
    *in_max_length -= 1;

    return 0;
}

void marshal_tpms_authcommand(TPMS_AUTH_COMMAND *in, uint8_t **out)
{
    marshal_uint32(in->sessionHandle, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->nonce, out);

    marshal_tpma_session(&in->sessionAttributes, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->hmac, out);
}

int unmarshal_tpms_authresponse(uint8_t **in, uint32_t *in_max_length, TPMS_AUTH_RESPONSE *out)
{
    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->nonce))
        return -1;

    if (0 != unmarshal_tpma_session(in, in_max_length, &out->sessionAttributes))
        return -1;

    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->hmac))
        return -1;

    return 0;
}

void marshal_tpm2b_sensitivecreate(TPM2B_SENSITIVE_CREATE *in, uint8_t **out)
{
    uint8_t *size_ptr = *out;
    *out += sizeof(uint16_t);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->sensitive.userAuth, out);

    marshal_tpm2b_simple((TPM2B_SIMPLE*)&in->sensitive.data, out);

    uint16_t size = *out - size_ptr - sizeof(uint16_t);
    marshal_uint16(size, &size_ptr);
}

int unmarshal_tpm2b_creationdata(uint8_t **in, uint32_t *in_max_length, TPM2B_CREATION_DATA *out)
{
    if (0 != unmarshal_uint16(in, in_max_length, &out->size))
        return -1;
    if (*in_max_length < out->size)
        return -1;
    
    if (0 != unmarshal_tpml_pcrselection(in, in_max_length, &out->creationData.pcrSelect))
        return -1;

    if (0 != unmarshal_tpm2b_digest(in, in_max_length, &out->creationData.pcrDigest))
        return -1;

    if (*in_max_length < 1)
        return -1;
    out->creationData.locality = **in;
    *in += 1;
    *in_max_length -= 1;

    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->creationData.parentNameAlg))
        return -1;

    if (0 != unmarshal_tpm2b_name(in, in_max_length, &out->creationData.parentName))
        return -1;
    
    if (0 != unmarshal_tpm2b_name(in, in_max_length, &out->creationData.parentQualifiedName))
        return -1;

    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->creationData.outsideInfo))
        return -1;

    return 0;
}

void marshal_tpm2b_digest(TPM2B_DIGEST *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

int unmarshal_tpm2b_digest(uint8_t **in, uint32_t *in_max_length, TPM2B_DIGEST *out)
{
    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)out))
        return -1;

    return 0;
}

int unmarshal_tpmt_tkcreation(uint8_t **in, uint32_t *in_max_length, TPMT_TK_CREATION *out)
{
    if (0 != unmarshal_uint16(in, in_max_length, &out->tag))
        return -1;

    if (0 != unmarshal_uint32(in, in_max_length, &out->hierarchy))
        return -1;

    if (0 != unmarshal_tpm2b_digest(in, in_max_length, &out->digest))
        return -1;

    return 0;
}

int unmarshal_tpm2b_name(uint8_t **in, uint32_t *in_max_length, TPM2B_NAME *out)
{
    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)out))
        return -1;

    return 0;
}

void marshal_tpm2b_eccpoint(TPM2B_ECC_POINT *in, uint8_t **out)
{
    uint8_t *size_ptr = *out;
    *out += sizeof(uint16_t);

    marshal_tpms_ecc_point(&in->point, out);

    uint16_t size = *out - size_ptr - sizeof(uint16_t);
    marshal_uint16(size, &size_ptr);
}

int unmarshal_tpm2b_eccpoint(uint8_t **in, uint32_t *in_max_length, TPM2B_ECC_POINT *out)
{
    if (0 != unmarshal_uint16(in, in_max_length, &out->size))
        return -1;
    if (*in_max_length < out->size)
        return -1;

    if (0 != unmarshal_tpms_ecc_point(in, in_max_length, &out->point))
        return -1;

    return 0;
}

void marshal_tpm2b_sensitivedata(TPM2B_SENSITIVE_DATA *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

void marshal_tpm2b_eccparameter(TPM2B_ECC_PARAMETER *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

void marshal_tpmt_sigscheme(TPMT_SIG_SCHEME *in, uint8_t **out)
{
    marshal_tpmi_alg_id(in->scheme, out);

    switch (in->scheme) {
        case TPM_ALG_ECDAA:
            marshal_tpmi_alg_id(in->details.ecdaa.hashAlg, out);
            marshal_uint16(in->details.ecdaa.count, out);
    }
}

void marshal_tpmt_tkhashcheck(TPMT_TK_HASHCHECK *in, uint8_t **out)
{
    marshal_uint16(in->tag, out);

    marshal_uint32(in->hierarchy, out);

    marshal_tpm2b_digest(&in->digest, out);
}

int unmarshal_tpmt_signature(uint8_t **in, uint32_t *in_max_length, TPMT_SIGNATURE *out)
{
    if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->sigAlg))
        return -1;

    switch (out->sigAlg) {
        case TPM_ALG_ECDAA:
            if (0 != unmarshal_tpmi_alg_id(in, in_max_length, &out->signature.ecdaa.hash))
                return -1;

            if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->signature.ecdaa.signatureR))
                return -1;

            if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)&out->signature.ecdaa.signatureS))
                return -1;

            break;
            
        default:
            return -2;
    }

    return 0;
}

void marshal_tpm2b_auth(TPM2B_AUTH *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

void marshal_tpmanv(TPMA_NV *in, uint8_t **out)
{
    memset(*out, 0, 4);  // clear all

    if (in->TPMA_NV_PPWRITE)
        (*out)[3] |= BIT_ZERO;
    if (in->TPMA_OWNERWRITE)
        (*out)[3] |= BIT_ONE;
    if (in->TPMA_AUTHWRITE)
        (*out)[3] |= BIT_TWO;
    if (in->TPMA_POLICYWRITE)
        (*out)[3] |= BIT_THREE;
    if (in->TPMA_COUNTER)
        (*out)[3] |= BIT_FOUR;
    if (in->TPMA_BITS)
        (*out)[3] |= BIT_FIVE;
    if (in->TPMA_EXTEND)
        (*out)[3] |= BIT_SIX;
    // bit 7 reserved
    // bit 8 reserved
    // bit 9 reserved
    if (in->TPMA_POLICY_DELETE)
        (*out)[2] |= BIT_TWO;
    if (in->TPMA_WRITELOCKED)
        (*out)[2] |= BIT_THREE;
    if (in->TPMA_WRITEALL)
        (*out)[2] |= BIT_FOUR;
    if (in->TPMA_WRITEDEFINE)
        (*out)[2] |= BIT_FIVE;
    if (in->TPMA_WRITE_STCLEAR)
        (*out)[2] |= BIT_SIX;
    if (in->TPMA_GLOBALLOCK)
        (*out)[2] |= BIT_SEVEN;
    if (in->TPMA_PPREAD)
        (*out)[1] |= BIT_ZERO;
    if (in->TPMA_OWNERREAD)
        (*out)[1] |= BIT_ONE;
    if (in->TPMA_AUTHREAD)
        (*out)[1] |= BIT_TWO;
    if (in->TPMA_POLICYREAD)
        (*out)[1] |= BIT_THREE;
    // bit 20 is reserved
    // bit 21 is reserved
    // bit 22 is reserved
    // bit 23 is reserved
    // bit 24 is reserved
    if (in->TPMA_NO_DA)
        (*out)[0] |= BIT_ONE;
    if (in->TPMA_ORDERLY)
        (*out)[0] |= BIT_TWO;
    if (in->TPMA_CLEAR_STCLEAR)
        (*out)[0] |= BIT_THREE;
    if (in->TPMA_READLOCKED)
        (*out)[0] |= BIT_FOUR;
    if (in->TPMA_WRITTEN)
        (*out)[0] |= BIT_FIVE;
    if (in->TPMA_PLATFORMCREATE)
        (*out)[0] |= BIT_SIX;
    if (in->TPMA_READ_STCLEAR)
        (*out)[0] |= BIT_SEVEN;

    *out += 4;
}

void marshal_tpm2b_nvpublic(TPM2B_NV_PUBLIC *in, uint8_t **out)
{
    uint8_t *size_ptr = *out;
    *out += sizeof(uint16_t);

    marshal_uint32(in->nvPublic.nvIndex, out);

    marshal_tpmi_alg_id(in->nvPublic.nameAlg, out);

    marshal_tpmanv(&in->nvPublic.attributes, out);

    marshal_tpm2b_digest(&in->nvPublic.authPolicy, out);

    marshal_uint16(in->nvPublic.dataSize, out);

    uint16_t size = *out - size_ptr - sizeof(uint16_t);
    marshal_uint16(size, &size_ptr);
}

void marshal_tpm2b_maxnvbuffer(TPM2B_MAX_NV_BUFFER *in, uint8_t **out)
{
    marshal_tpm2b_simple((TPM2B_SIMPLE*)in, out);
}

int unmarshal_tpm2b_maxnvbuffer(uint8_t **in, uint32_t *in_max_length, TPM2B_MAX_NV_BUFFER *out)
{
    if (0 != unmarshal_tpm2b_simple(in, in_max_length, (TPM2B_SIMPLE*)out))
        return -1;

    return 0;
}
