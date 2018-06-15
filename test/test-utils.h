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

#include <stdio.h>

char *hostname_g = "localhost";
const char *port_g = "2321";
const char* dev_file_path_g = NULL;   // indicates to use default
const size_t dev_file_path_length_g = 0;
char *pub_key_filename_g = "pub_key.txt";
char *handle_filename_g = "handle.txt";

#define TEST_ASSERT(cond) \
    do \
    { \
        if (!(cond)) { \
            printf("Condition \'%s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #cond,__FILE__,  __func__, __LINE__); \
            printf("exiting\n"); \
            exit(1); \
        } \
    } while(0)

#define TEST_EXPECT(cond) \
    do \
    { \
        if (!(cond)) { \
            printf("Condition \'%s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #cond,__FILE__,  __func__, __LINE__); \
            printf("continuing\n"); \
        } \
    } while(0)

#define parse_cmd_args(argc, argv) \
    do \
    { \
        if (argc >= 2) { \
            hostname_g = argv[1]; \
        } \
        if (argc == 4) { \
            pub_key_filename_g = argv[2]; \
            handle_filename_g = argv[3]; \
        } \
        printf("Saving public key to %s and handle to %s\n", pub_key_filename_g, handle_filename_g);\
    } while(0)
