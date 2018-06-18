# Copyright 2017-2018 Xaptum, Inc.
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
        VERSION "0.5.5"
)

include(GNUInstallDirs)
include(CTest)

add_compile_options(-std=c99 -Werror -Wall -Wextra -Wno-missing-field-initializers)
add_definitions(-D_POSIX_C_SOURCE=200112L)
set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")

option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)
option(BUILD_UTILS "Build utility programs" ON)

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if(NOT DEFINED BUILD_SHARED_LIBS OR NOT  "${BUILD_SHARED_LIBS}")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif()

set(XAPTUM_TPM_VERSION ${PROJECT_VERSION})
set(XAPTUM_TPM_SOVERSION ${PROJECT_VERSION_MAJOR})

set(XAPTUM_TPM_SRCS
    src/xaptum/nvram.c

    src/tss2_tcti_device.c
    src/tss2_tcti_socket.c
    src/tss2_sys_context_allocation.c
    src/tss2_sys_clear.c
    src/tss2_sys_create.c
    src/tss2_sys_createprimary.c
    src/tss2_sys_commit.c
    src/tss2_sys_hierarchychangeauth.c
    src/tss2_sys_load.c
    src/tss2_sys_evictcontrol.c
    src/tss2_sys_nv.c
    src/tss2_sys_sign.c

    src/internal/cmdauths.c
    src/internal/constants.c
    src/internal/execute.c
    src/internal/marshal.c
    src/internal/sys_context_common.c
    src/internal/command_utils.c
)

################################################################################
# Shared Libary
################################################################################
if(BUILD_SHARED_LIBS)
  add_library(xaptum-tpm SHARED ${XAPTUM_TPM_SRCS})

  set_target_properties(xaptum-tpm PROPERTIES
    VERSION "${XAPTUM_TPM_VERSION}"
    SOVERSION "${XAPTUM_TPM_SOVERSION}"
  )

  target_include_directories(xaptum-tpm PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  install(TARGETS xaptum-tpm
          EXPORT xaptum-tpm-targets
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )
endif()

################################################################################
# Static Libary
################################################################################
if(BUILD_STATIC_LIBS)
  add_library(xaptum-tpm_static STATIC ${XAPTUM_TPM_SRCS})

  set_target_properties(xaptum-tpm_static PROPERTIES
    OUTPUT_NAME "xaptum-tpm${STATIC_SUFFIX}"
    VERSION "${XAPTUM_TPM_VERSION}"
    SOVERSION "${XAPTUM_TPM_SOVERSION}"
  )

  target_include_directories(xaptum-tpm_static PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )

  install(TARGETS xaptum-tpm_static
          EXPORT xaptum-tpm-targets
          RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
          LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
          ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  )
endif()

################################################################################
# Headers
################################################################################
install(DIRECTORY include/tss2 DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

################################################################################
# pkgconfig
################################################################################
configure_file(xaptum-tpm.pc.in xaptum-tpm.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xaptum-tpm.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

################################################################################
# CMake export
################################################################################
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/xaptum-tpm)

install(EXPORT xaptum-tpm-targets
        FILE xaptum-tpm-targets.cmake
        NAMESPACE xaptum-tpm::
        DESTINATION ${INSTALL_CONFIGDIR}
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/xaptum-tpm-config-version.cmake
  VERSION ${XAPTUM_TPM_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/xaptum-tpm-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/xaptum-tpm-config.cmake
  INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/xaptum-tpm-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/xaptum-tpm-config-version.cmake
  DESTINATION ${INSTALL_CONFIGDIR}
)

if(BUILD_TESTING)
  add_subdirectory(test)
endif()

################################################################################
# Util
################################################################################
if(BUILD_UTILS)
  add_subdirectory(util)
endif()
