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

#ifndef XAPTUM_TPM_INTERNAL_ASN1_H
#define XAPTUM_TPM_INTERNAL_ASN1_H
#pragma once

#include <xaptum-tpm/keys.h>

/*
 * A buffer of this size is sufficient to hold a Tpm_Loadable_Key ASN.1 structure.
 */
#define ASN1_LOADABLE_KEY_MIN_BUF 2240

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a TPM_Loadable_Key ASN.1 structure for `key`.
 *
 * The structure is written to `buf`,
 *  and the total size of the structure is returned in `length`.
 */
void
build_asn1_from_key(const struct xtpm_key *key,
                    uint8_t *buf,
                    size_t *length);

#ifdef __cplusplus
}
#endif

#endif

