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

void unmarshal_uint32(uint8_t *in, uint32_t *out)
{
    *out = (uint64_t)(in[3]);
    *out |= (uint64_t)(in[2]) << 8;
    *out |= (uint64_t)(in[1]) << 16;
    *out |= (uint64_t)(in[0]) << 24;
}

void marshal_uint32(uint32_t in, uint8_t *out)
{
    out[0] = (unsigned char)(in >> 24);  /* 3*8 */
    out[1] = (unsigned char)(in >> 16);  /* 2*8 */
    out[2] = (unsigned char)(in >> 8);   /* 1*8 */
    out[3] = (unsigned char)(in);        /* 0*8 */
}
