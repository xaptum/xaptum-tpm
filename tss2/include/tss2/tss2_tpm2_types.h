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

#ifndef XAPTUM_TSS2_TPM2_TYPES_H
#define XAPTUM_TSS2_TPM2_TYPES_H
#pragma once

#include <tss2/tss2_common.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: Make sure these make sense (they should work well with an Infineon SLB9670)
//  MAX_[COMMAND,RESPONSE]_SIZE are probably too big. SLB9670 has an I/O buffer of 1280 B
#define TPM2_MAX_COMMAND_SIZE  4096
#define TPM2_MAX_RESPONSE_SIZE 4096
#define TPM2_MAX_SYM_DATA 128
#define TPM2_MAX_ECC_KEY_BYTES 32
#define TPM2_MAX_NV_BUFFER_SIZE 768
#define TPM2_NUM_PCR_BANKS 1
#define TPM2_PCR_SELECT_MAX 1

#define TPM2_SHA256_DIGEST_SIZE 32
#define TPM2_SHA512_DIGEST_SIZE 64

typedef	uint16_t TPM2_ST;
#define TPM2_ST_CREATION 0x8021
#define TPM2_ST_HASHCHECK 0x8024

typedef TPM2_ST TPMI_ST_COMMAND_TAG;
#define TPM2_ST_NO_SESSIONS 0x8001
#define TPM2_ST_SESSIONS 0x8002

typedef uint32_t TPM2_HANDLE;

typedef uint16_t TPM2_KEY_BITS;

typedef uint32_t TPM2_CC;
#define TPM2_CC_NV_UndefineSpace 0x00000122
#define TPM2_CC_HierarchyChangeAuth 0x00000129
#define TPM2_CC_NV_DefineSpace 0x0000012A
#define TPM2_CC_CreatePrimary 0x00000131
#define TPM2_CC_NV_Write 0x00000137
#define TPM2_CC_NV_Read 0x0000014E
#define TPM2_CC_Create 0x00000153
#define TPM2_CC_Load 0x00000157
#define TPM2_CC_Sign 0x0000015D
#define TPM2_CC_NV_ReadPublic 0x00000169
#define TPM2_CC_ReadPublic 0x00000173
#define TPM2_CC_GetCapability 0x0000017A
#define TPM2_CC_Commit 0x0000018B
#define TPM2_CC_EvictControl 0x00000120
#define TPM2_CC_Clear 0x00000126
#define TPM2_CC_ClearControl 0x00000127

// Only password-authorizations are supported
typedef	TPM2_HANDLE TPMI_SH_AUTH_SESSION;
#define TPM2_RS_PW 0x40000009

typedef TPM2_HANDLE TPMI_DH_OBJECT;
typedef TPM2_HANDLE TPMI_DH_PERSISTENT;

typedef	TPM2_HANDLE TPMI_RH_HIERARCHY;
typedef	TPM2_HANDLE TPMI_RH_PROVISION;
typedef TPM2_HANDLE TPMI_RH_NV_INDEX;
typedef TPM2_HANDLE TPMI_RH_NV_AUTH;
typedef	TPM2_HANDLE TPMI_RH_HIERARCHY_AUTH;
typedef	TPM2_HANDLE TPMI_RH_CLEAR;
#define TPM2_RH_OWNER 0x40000001
#define TPM2_RH_ENDORSEMENT 0x4000000B
#define TPM2_RH_PLATFORM 0x4000000C
#define TPM2_RH_NULL 0x40000007
#define TPM2_RH_LOCKOUT 0x4000000A

typedef uint16_t TPM2_ALG_ID;
typedef	TPM2_ALG_ID TPMI_ALG_PUBLIC;
typedef	TPM2_ALG_ID TPMI_ALG_HASH;
typedef	TPM2_ALG_ID TPMI_ALG_SYM_OBJECT;
typedef TPM2_ALG_ID TPMI_ALG_ECC_SCHEME;
typedef TPM2_ALG_ID TPMI_ALG_KDF;
typedef TPM2_ALG_ID TPMI_ALG_SIG_SCHEME;
typedef TPM2_ALG_ID TPMI_ALG_SYM_MODE;
#define TPM2_ALG_AES 0x0006
#define TPM2_ALG_SHA256 0x000B
#define TPM2_ALG_SHA512 0x000D
#define TPM2_ALG_NULL 0x0010
#define TPM2_ALG_ECDSA 0x0018
#define TPM2_ALG_ECDAA 0x001A
#define TPM2_ALG_KDF1_SP800_108 0x0022
#define TPM2_ALG_ECC 0x0023
#define TPM2_ALG_CFB 0x0043

typedef uint16_t TPM2_ECC_CURVE;
typedef TPM2_ECC_CURVE TPMI_ECC_CURVE;
#define TPM2_ECC_BN_P256 0x0010
#define TPM2_ECC_NIST_P256 0x0003

typedef uint8_t TPMA_LOCALITY;
#define TPMA_LOCALITY_TPM2_LOC_ZERO 1
#define TPMA_LOCALITY_TPM2_LOC_ONE 2
#define TPMA_LOCALITY_TPM2_LOC_TWO 4
#define TPMA_LOCALITY_TPM2_LOC_THREE 8
#define TPMA_LOCALITY_TPM2_LOC_FOUR 16

typedef struct {
    TPMI_ALG_HASH hashAlg;
} TPMS_SCHEME_HASH;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_ECDSA;

typedef struct {
    TPMI_ALG_HASH hashAlg;
    uint16_t count;
} TPMS_SCHEME_ECDAA;
typedef TPMS_SCHEME_ECDAA TPMS_SIG_SCHEME_ECDAA;

typedef union {
    TPMS_SIG_SCHEME_ECDAA ecdaa;
    TPMS_SIG_SCHEME_ECDSA ecdsa;
} TPMU_SIG_SCHEME;

typedef struct {
    TPMI_ALG_SIG_SCHEME scheme;
    TPMU_SIG_SCHEME details;
} TPMT_SIG_SCHEME;

typedef	union {
	uint8_t sha256[TPM2_SHA256_DIGEST_SIZE];
	uint8_t sha512[TPM2_SHA512_DIGEST_SIZE];
} TPMU_HA;

typedef struct {
    TPMI_ALG_HASH hashAlg;
    TPMU_HA digest;
} TPMT_HA;

typedef struct {
    uint16_t size;
    uint8_t buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

typedef	TPM2B_DIGEST TPM2B_NONCE;

typedef TPM2B_DIGEST TPM2B_AUTH;

typedef uint8_t TPMA_SESSION;

#define TPMA_SESSION_CONTINUESESSION 0x01
#define TPMA_SESSION_AUDITEXCLUSIVE  0x02
#define TPMA_SESSION_AUDITRESET      0x04
#define TPMA_SESSION_DECRYPT         0x20
#define TPMA_SESSION_ENCRYPT         0x40
#define TPMA_SESSION_AUDIT           0x80

typedef uint32_t TPMA_OBJECT;

#define TPMA_OBJECT_FIXEDTPM             0x00000002
#define TPMA_OBJECT_STCLEAR              0x00000004

#define TPMA_OBJECT_FIXEDPARENT          0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN  0x00000020
#define TPMA_OBJECT_USERWITHAUTH         0x00000040
#define TPMA_OBJECT_ADMINWITHPOLICY      0x00000080

#define TPMA_OBJECT_NODA                 0x00000400
#define TPMA_OBJECT_ENCRYPTEDDUPLICATION 0x00000800

#define TPMA_OBJECT_RESTRICTED           0x00010000
#define TPMA_OBJECT_DECRYPT              0x00020000
#define TPMA_OBJECT_SIGN_ENCRYPT         0x00040000

typedef	struct {
	TPMI_SH_AUTH_SESSION sessionHandle;
	TPM2B_NONCE nonce;
	TPMA_SESSION sessionAttributes;
	TPM2B_AUTH hmac;
} TPMS_AUTH_COMMAND;

typedef	struct {
	TPM2B_NONCE nonce;
	TPMA_SESSION sessionAttributes;
	TPM2B_AUTH hmac;
} TPMS_AUTH_RESPONSE;

typedef struct {
    uint16_t size;
    uint8_t buffer[TPM2_MAX_SYM_DATA];
} TPM2B_SENSITIVE_DATA;

typedef union {
    TPM2B_SENSITIVE_DATA bits;
} TPMU_SENSITIVE_COMPOSITE;

typedef struct {
    TPMI_ALG_PUBLIC sensitiveType;
    TPM2B_AUTH authValue;
    TPM2B_DIGEST seedValue;
    TPMU_SENSITIVE_COMPOSITE sensitive;
} TPMT_SENSITIVE;

typedef struct {
    uint16_t size;
    TPMT_SENSITIVE sensitiveArea;
} TPM2B_SENSITIVE;

typedef struct {
    TPM2B_AUTH userAuth;
    TPM2B_SENSITIVE_DATA data;
} TPMS_SENSITIVE_CREATE;

typedef struct {
    uint16_t size;
    TPMS_SENSITIVE_CREATE sensitive;
} TPM2B_SENSITIVE_CREATE;

typedef union {
    TPM2_KEY_BITS aes;
} TPMU_SYM_KEY_BITS;

typedef union {
    TPMI_ALG_SYM_MODE sym;
} TPMU_SYM_MODE;

typedef struct {
    TPMI_ALG_SYM_OBJECT algorithm;
    TPMU_SYM_KEY_BITS keyBits;
    TPMU_SYM_MODE mode;
} TPMT_SYM_DEF_OBJECT;

typedef union {
    TPMS_SIG_SCHEME_ECDAA ecdaa;
    TPMS_SIG_SCHEME_ECDSA ecdsa;
} TPMU_ASYM_SCHEME;

typedef struct {
    TPMI_ALG_ECC_SCHEME scheme;
    TPMU_ASYM_SCHEME details;
} TPMT_ECC_SCHEME;

typedef union {
    uint8_t null;
} TPMU_KDF_SCHEME;

typedef struct {
    TPMI_ALG_KDF scheme;
    TPMU_KDF_SCHEME details;
} TPMT_KDF_SCHEME;

typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ECC_SCHEME scheme;
    TPMI_ECC_CURVE curveID;
    TPMT_KDF_SCHEME kdf;
} TPMS_ECC_PARMS;

typedef union {
    TPMS_ECC_PARMS eccDetail;
} TPMU_PUBLIC_PARMS;

typedef struct {
    uint16_t size;
    uint8_t buffer[TPM2_MAX_ECC_KEY_BYTES];
} TPM2B_ECC_PARAMETER;

typedef struct {
    TPM2B_ECC_PARAMETER x;
    TPM2B_ECC_PARAMETER y;
} TPMS_ECC_POINT;

typedef union {
    TPMS_ECC_POINT ecc;
} TPMU_PUBLIC_ID;

typedef struct {
    uint16_t size;
    TPMS_ECC_POINT point;
} TPM2B_ECC_POINT;

typedef struct {
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMA_OBJECT objectAttributes;
    TPM2B_DIGEST authPolicy;
    TPMU_PUBLIC_PARMS parameters;
    TPMU_PUBLIC_ID unique;
} TPMT_PUBLIC;

typedef struct {
    uint16_t size;
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

typedef struct {
    uint16_t size;
    uint8_t buffer[sizeof(TPMU_HA)];
} TPM2B_DATA;

typedef struct {
    TPMI_ALG_HASH hash;
    uint8_t sizeofSelect;
    uint8_t pcrSelect[TPM2_PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

typedef struct {
    uint32_t count;
    TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS];
} TPML_PCR_SELECTION;

typedef union {
    TPMT_HA digest;
    TPM2_HANDLE handle;
} TPMU_NAME;

typedef	struct {
	TPM2B_DIGEST integrityOuter;
	TPM2B_DIGEST integrityInner;
	TPM2B_SENSITIVE sensitive;
} _PRIVATE;

typedef struct {
    uint16_t size;
    uint8_t buffer[sizeof(_PRIVATE)];
} TPM2B_PRIVATE;

typedef struct {
    uint16_t size;
    uint8_t name[sizeof(TPMU_NAME)];
} TPM2B_NAME;

typedef struct {
    TPML_PCR_SELECTION pcrSelect;
    TPM2B_DIGEST pcrDigest;
    TPMA_LOCALITY locality;
    TPM2_ALG_ID parentNameAlg;
    TPM2B_NAME parentName;
    TPM2B_NAME parentQualifiedName;
    TPM2B_DATA outsideInfo;
} TPMS_CREATION_DATA;

typedef struct {
    uint16_t size;
    TPMS_CREATION_DATA creationData;
} TPM2B_CREATION_DATA;

typedef struct {
    TPM2_ST tag; // MUST be TPM2_ST_CREATION
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_CREATION;

typedef struct {
    TPM2_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
} TPMT_TK_HASHCHECK;

typedef struct {
    TPMI_ALG_HASH hash;
    TPM2B_ECC_PARAMETER signatureR;
    TPM2B_ECC_PARAMETER signatureS;
} TPMS_SIGNATURE_ECC;

typedef union {
    TPMS_SIGNATURE_ECC ecdaa;
    TPMS_SIGNATURE_ECC ecdsa;
} TPMU_SIGNATURE;

typedef struct {
    TPMI_ALG_SIG_SCHEME sigAlg;
    TPMU_SIGNATURE signature;
} TPMT_SIGNATURE;

typedef uint32_t TPMA_NV;

#define TPMA_NV_PPWRITE        0x00000001
#define TPMA_NV_OWNERWRITE     0x00000002
#define TPMA_NV_AUTHWRITE      0x00000004
#define TPMA_NV_POLICYWRITE    0x00000008

#define TPMA_NV_POLICY_DELETE  0x00000400
#define TPMA_NV_WRITELOCKED    0x00000800
#define TPMA_NV_WRITEALL       0x00001000
#define TPMA_NV_WRITEDEFINE    0x00002000
#define TPMA_NV_WRITE_STCLEAR  0x00004000
#define TPMA_NV_GLOBALLOCK     0x00008000
#define TPMA_NV_PPREAD         0x00010000
#define TPMA_NV_OWNERREAD      0x00020000
#define TPMA_NV_AUTHREAD       0x00040000
#define TPMA_NV_POLICYREAD     0x00080000
#define TPMA_NV_RESERVED2_MASK 0x01F00000
#define TPMA_NV_NO_DA          0x02000000
#define TPMA_NV_ORDERLY        0x04000000
#define TPMA_NV_CLEAR_STCLEAR  0x08000000
#define TPMA_NV_READLOCKED     0x10000000
#define TPMA_NV_WRITTEN        0x20000000
#define TPMA_NV_PLATFORMCREATE 0x40000000
#define TPMA_NV_READ_STCLEAR   0x80000000

typedef struct {
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    TPMA_NV attributes;
    TPM2B_DIGEST authPolicy;
    uint16_t dataSize;
} TPMS_NV_PUBLIC;

typedef struct {
    uint16_t size;
    TPMS_NV_PUBLIC nvPublic;
} TPM2B_NV_PUBLIC;

typedef struct {
    uint16_t size;
    uint8_t buffer[TPM2_MAX_NV_BUFFER_SIZE];
} TPM2B_MAX_NV_BUFFER;

#ifdef __cplusplus
}
#endif

#endif

