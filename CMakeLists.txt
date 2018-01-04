# Copyright 2017 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(xaptum-tpm
        LANGUAGES C
        VERSION "0.3.0")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -Wno-missing-field-initializers -std=c99 -D_POSIX_C_SOURCE=200112L")

set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")

set(XAPTUM_TPM_SRCS
    src/tss2_tcti_socket.c
    src/tss2_sys_context_allocation.c
    src/tss2_sys_createprimary.c
    src/tss2_sys_commit.c
    src/tss2_sys_hierarchychangeauth.c
    src/tss2_sys_nv.c
    src/tss2_sys_sign.c
    src/internal/cmdauths.c
    src/internal/constants.c
    src/internal/execute.c
    src/internal/marshal.c
    src/internal/sys_context_common.c
    src/internal/command_utils.c
)

add_library(xaptum_tpm-obj OBJECT ${XAPTUM_TPM_SRCS})
set_target_properties(xaptum_tpm-obj PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_include_directories(xaptum_tpm-obj PUBLIC include)

add_library(xaptum_tpm-shared SHARED $<TARGET_OBJECTS:xaptum_tpm-obj>)
add_library(xaptum_tpm-static STATIC $<TARGET_OBJECTS:xaptum_tpm-obj>)

enable_testing()
add_subdirectory(test)
