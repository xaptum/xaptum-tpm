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

#include "pem.h"

#include <stdio.h>

const char *PEM_HEADER = "-----BEGIN TSS2 PRIVATE KEY-----";
const char *PEM_FOOTER = "-----END TSS2 PRIVATE KEY-----";
const int PEM_LINE_LIMIT = 64;

const char base64_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                           'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                           'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                           'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                           '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

#define CHUNK0(byte_0) ( byte_0 >> 2 )
#define CHUNK1(byte_0, byte_1) ( ((0x3 & byte_0) << 4) + (byte_1 >> 4) )
#define CHUNK2(byte_1, byte_2) ( ((0xF & byte_1) << 2) + (byte_2 >> 6) )
#define CHUNK3(byte_2) ( 0x3F & byte_2 )

#define checked_print(file_ptr, ...) \
    do \
    { \
        if (fprintf(file_ptr, __VA_ARGS__) < 0) { \
            ret = -1; \
            goto finish; \
        } \
    } while(0)

int
write_pem(const char *filename,
          const uint8_t *buffer,
          size_t buffer_length)
{
    FILE *file_ptr = fopen(filename, "w");
    if (NULL == file_ptr)
        return -1;

    int ret = 0;

    checked_print(file_ptr, "%s\n", PEM_HEADER);

    size_t pos = 0;
    int line_size = 0;
    for (; pos <= buffer_length - 3; pos += 3) {
        unsigned char byte_0=buffer[pos];
        unsigned char byte_1=buffer[pos+1];
        unsigned char byte_2=buffer[pos+2];

        char out[] = {base64_map[ CHUNK0(byte_0) ],
                      base64_map[ CHUNK1(byte_0, byte_1) ],
                      base64_map[ CHUNK2(byte_1, byte_2) ],
                      base64_map[ CHUNK3(byte_2) ]};

        for (size_t i=0; i<sizeof(out); ++i) {
            if (PEM_LINE_LIMIT == line_size) {
                checked_print(file_ptr, "\n%c", out[i]);
                line_size = 1;
            } else {
                checked_print(file_ptr, "%c", out[i]);
                ++line_size;
            }
        }
    }

    int leftover_bytes = buffer_length % 3 ;
    if (2 == leftover_bytes) {
        unsigned char byte_0=buffer[pos];
        unsigned char byte_1=buffer[pos+1];

        checked_print(file_ptr, "%c", base64_map[ CHUNK0(byte_0) ]);
        checked_print(file_ptr, "%c", base64_map[ CHUNK1(byte_0, byte_1) ]);
        checked_print(file_ptr, "%c", base64_map[ CHUNK2(byte_1, 0) ]);

        checked_print(file_ptr, "%c", '=');
    } else if (1 == leftover_bytes) {
        unsigned char byte_0=buffer[pos];

        checked_print(file_ptr, "%c", base64_map[ CHUNK0(byte_0) ]);
        checked_print(file_ptr, "%c", base64_map[ CHUNK1(byte_0, 0) ]);

        checked_print(file_ptr, "%c", '=');
        checked_print(file_ptr, "%c", '=');
    }

    checked_print(file_ptr, "\n%s\n", PEM_FOOTER);

finish:
    fclose(file_ptr);

    return ret;
}
