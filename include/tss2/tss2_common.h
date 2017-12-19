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

// Cf. TSS-system-API Family 2.0, Level 00, Revision 01.00, Section 6

#ifndef XAPTUM_TPM_TSS2_COMMON_H
#define XAPTUM_TPM_TSS2_COMMON_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct {
    uint32_t tssCreator;  
    uint32_t tssFamily;   
    uint32_t tssLevel;    
    uint32_t tssVersion;      
} TSS2_ABI_VERSION;

extern const TSS2_ABI_VERSION TSS2_ABI_CURRENT_VERSION;

typedef uint32_t TSS2_RC;

#define TSS2_RC_SUCCESS 0
#define TSS2_RC_LEVEL_SHIFT 16

// Base Error Codes
#define TSS2_BASE_RC_GENERAL_FAILURE 1 /* Catch all for all errors
                                          not otherwise specifed */
#define TSS2_BASE_RC_NOT_IMPLEMENTED 2 /* If called functionality isn't implemented */
#define TSS2_BASE_RC_BAD_CONTEXT 3 /* A context structure is bad */
#define TSS2_BASE_RC_ABI_MISMATCH 4 /* Passed in ABI version doesn't match
                                       called module's ABI version */
#define TSS2_BASE_RC_BAD_REFERENCE 5 /* A pointer is NULL that isn't allowed to
                                        be NULL. */
#define TSS2_BASE_RC_INSUFFICIENT_BUFFER 6 /* A buffer isn't large enough */
#define TSS2_BASE_RC_BAD_SEQUENCE 7 /* Function called in the wrong order */
#define TSS2_BASE_RC_NO_CONNECTION 8 /* Fails to connect to next lower layer */
#define TSS2_BASE_RC_TRY_AGAIN 9 /* Operation timed out; function must be
                                    called again to be completed */
#define TSS2_BASE_RC_IO_ERROR 10 /* IO failure */
#define TSS2_BASE_RC_BAD_VALUE 11 /* A parameter has a bad value */
#define TSS2_BASE_RC_NOT_PERMITTED 12 /* Operation not permitted. */
#define TSS2_BASE_RC_INVALID_SESSIONS 13 /* Session structures were sent, but */
/* command doesn't use them or doesn't use
 * the specifed number of them */
#define TSS2_BASE_RC_NO_DECRYPT_PARAM 14 /* If function called that uses decrypt
                                            parameter, but command doesn't support
                                            decrypt parameter. */
#define TSS2_BASE_RC_NO_ENCRYPT_PARAM 15 /* If function called that uses encrypt
                                            parameter, but command doesn't support
                                            decrypt parameter. */
#define TSS2_BASE_RC_BAD_SIZE 16 /* If size of a paremeter is incorrect */
#define TSS2_BASE_RC_MALFORMED_RESPONSE 17 /* Response is malformed */
#define TSS2_BASE_RC_INSUFFICIENT_CONTEXT 18 /* Context not large enough */
#define TSS2_BASE_RC_INSUFFICIENT_RESPONSE 19 /* Response is not long enough */
#define TSS2_BASE_RC_INCOMPATIBLE_TCTI 20 /* Unknown or unusable TCTI version */
#define TSS2_BASE_RC_NOT_SUPPORTED 21 /* Functionality not supported. */
#define TSS2_BASE_RC_BAD_TCTI_STRUCTURE 21 /* TCTI context is bad. */

// TCTI Error Codes
#define TSS2_TCTI_ERROR_LEVEL ( 10 << TSS2_RC_LEVEL_SHIFT)

#define TSS2_TCTI_RC_GENERAL_FAILURE ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_TCTI_RC_NOT_IMPLEMENTED ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_NOT_IMPLEMENTED))
#define TSS2_TCTI_RC_BAD_CONTEXT ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_CONTEXT))
#define TSS2_TCTI_RC_ABI_MISMATCH ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_TCTI_RC_BAD_REFERENCE ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_TCTI_RC_INSUFFICIENT_BUFFER ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_TCTI_RC_BAD_SEQUENCE ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_TCTI_RC_NO_CONNECTION ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_NO_CONNECTION))
#define TSS2_TCTI_RC_TRY_AGAIN ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_TRY_AGAIN))
#define TSS2_TCTI_RC_IO_ERROR ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_IO_ERROR))
#define TSS2_TCTI_RC_BAD_VALUE ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_VALUE))
#define TSS2_TCTI_RC_NOT_PERMITTED ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_NOT_PERMITTED))
#define TSS2_TCTI_RC_MALFORMED_RESPONSE ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_TCTI_RC_NOT_SUPPORTED ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_NOT_SUPPORTED))

// SAPI Error Codes
#define TSS2_SYS_ERROR_LEVEL 8 << TSS2_RC_LEVEL_SHIFT

#define TSS2_SYS_RC_GENERAL_FAILURE ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL | \
            TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_SYS_RC_ABI_MISMATCH ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_SYS_RC_BAD_REFERENCE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_SYS_RC_INSUFFICIENT_BUFFER ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_SYS_RC_BAD_SEQUENCE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_SYS_RC_BAD_VALUE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_VALUE))
#define TSS2_SYS_RC_INVALID_SESSIONS ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_INVALID_SESSIONS))
#define TSS2_SYS_RC_NO_DECRYPT_PARAM ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_NO_DECRYPT_PARAM))
#define TSS2_SYS_RC_NO_ENCRYPT_PARAM ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_NO_ENCRYPT_PARAM))
#define TSS2_SYS_RC_BAD_SIZE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_SIZE))
#define TSS2_SYS_RC_MALFORMED_RESPONSE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_SYS_RC_INSUFFICIENT_CONTEXT ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
#define TSS2_SYS_RC_INSUFFICIENT_RESPONSE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
#define TSS2_SYS_RC_INCOMPATIBLE_TCTI ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_INCOMPATIBLE_TCTI))
#define TSS2_SYS_RC_BAD_TCTI_STRUCTURE ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL | \
            TSS2_BASE_RC_BAD_TCTI_STRUCTURE))

#define TSS2_SYS_PART2_RC_LEVEL 9 << TSS2_RC_LEVEL_SHIFT

// TPM errors
#define TSS2_TPM_RC_LEVEL 0

#ifdef __cplusplus
}
#endif

#endif

