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

#include "asn1.h"

#include "marshal.h"

#include <tss2/tss2_tpm2_types.h>

#include <assert.h>
#include <stdint.h>
#include <string.h>

/**
    TPM_Loadable_Key ::= SEQUENCE {
    type            OBJECT IDENTIFIER,
    emptyAuth       [0] EXPLICIT BOOLEAN OPTIONAL,
    parent          INTEGER,
    pubkey          OCTET STRING,
    privkey         OCTET STRING
    }
 */

const uint8_t ASN1_PREAMBLE[] = {
    0x30, 0x81,                                         // type = sequence, first octet of length indicating "long form" of total length
    00,                                                 // total length, TO BE FILLED IN
    0x06, 0x06, 0x67, 0x81, 0x05, 0x0A, 0x01, 0x03,     // - object id - type = 06, length = 06, value = 2.23.133.10.1.3
    0xA0, 0x03, 0x01, 0x01, 0x01,                       // - empth auth - type = constructed, length = 3, type = boolean, length = 1, value = true
};

const unsigned char ASN1_INTEGER_TYPE = 0x02;
const unsigned char ASN1_OCTET_STRING_TYPE = 0x04;

const size_t LENGTH_LOC = 2;

const unsigned char ASN1_LONG_FORM_LENGTH_PREFIX = 0x81;

typedef void (*marshal_func_type)(const void*, uint8_t**);

static
void
build_asn1_octet_string(uint8_t **ptr, const void* val, marshal_func_type marshal);

static
void
build_asn1_integer(uint8_t **ptr, uint32_t val);

void
build_asn1_from_key(const struct xtpm_key *key,
                    uint8_t *buf,
                    size_t *length)
{
    uint8_t *ptr = buf;

    // Preamble
    memcpy(buf, ASN1_PREAMBLE, sizeof(ASN1_PREAMBLE));
    ptr += sizeof(ASN1_PREAMBLE);

    // Parent handle
    build_asn1_integer(&ptr, key->parent_handle);

    // Public key
    build_asn1_octet_string(&ptr,
                            &key->public_key,
                            (marshal_func_type)&marshal_tpm2b_public);

    // Private key
    build_asn1_octet_string(&ptr,
                            &key->private_key_blob,
                            (marshal_func_type)&marshal_tpm2b_private);

    // Save total size to length field of SEQUENCE at beginning of structure.
    //  (subtract 3 bytes for the type/length fields of the SEQUENCE header itself).
    *length = ptr - buf;
    buf[LENGTH_LOC] = *length - 3;

    // Just to make sure this constant is still defined correctly.
    assert(ASN1_LOADABLE_KEY_MIN_BUF >= *length);
}

void
build_asn1_octet_string(uint8_t **ptr, const void* val, marshal_func_type marshal)
{
    **ptr = ASN1_OCTET_STRING_TYPE;
    ++(*ptr);

    uint8_t *size_ptr = *ptr;
    ++(*ptr);  // Assuming size is < 127B

    marshal(val, ptr);

    size_t marshalled_size = *ptr - (size_ptr + 1);
    if (marshalled_size < 127) {
        *size_ptr = marshalled_size;
    } else {
        // Marshalled value was larger than expected
        // so have to use "long-format" length.
        // (NOTE: we're still assuming the length is <256,
        //  which TPM2B_[Public, Private] always are).
        *ptr = size_ptr;

        **ptr = ASN1_LONG_FORM_LENGTH_PREFIX;
        ++(*ptr);

        **ptr = marshalled_size;
        ++(*ptr);

        marshal(val, ptr);
    }
}

void
build_asn1_integer(uint8_t **ptr, uint32_t val)
{
    **ptr = ASN1_INTEGER_TYPE;
    ++(*ptr);

    size_t size = sizeof(uint32_t);

    // If msb is set, pad with a zero
    if (val & 0x80000000) {
        **ptr = size + 1;
        ++(*ptr);
        **ptr = 0;
        ++(*ptr);
    } else {
        **ptr = size;
        ++(*ptr);
    }

    marshal_uint32(val, ptr);
}
