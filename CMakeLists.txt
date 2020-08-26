# Copyright 2017-2020 Xaptum, Inc.
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
        VERSION "0.5.8"
)

include(GNUInstallDirs)
include(CTest)

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

add_compile_options(-std=c99 -Wall -Wextra -Wno-missing-field-initializers)
add_definitions(-D_POSIX_C_SOURCE=200112L)
set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")
set(CMAKE_C_FLAGS_DEV "${CMAKE_C_FLAGS_RELEASE} -Werror")
set(CMAKE_C_FLAGS_DEVDEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")

option(BUILD_SHARED_LIBS "Build as a shared library" ON)
option(BUILD_STATIC_LIBS "Build as a static library" OFF)

option(XTPM_VERBOSE_LOGGING "Turn on debug-level logging OFF")
if(XTPM_VERBOSE_LOGGING)
  add_definitions(-DVERBOSE_LOGGING)
endif()

option(BUILD_TSS2 "Build restricted subset of the TPM2.0 SAPI library" OFF)

# If not building as a shared library, force build as a static.  This
# is to match the CMake default semantics of using
# BUILD_SHARED_LIBS = OFF to indicate a static build.
if(NOT DEFINED BUILD_SHARED_LIBS OR NOT  "${BUILD_SHARED_LIBS}")
  set(BUILD_STATIC_LIBS ON CACHE BOOL "Build as a static library" FORCE)
endif()

set(XAPTUM_TPM_VERSION ${PROJECT_VERSION})
set(XAPTUM_TPM_SOVERSION ${PROJECT_VERSION_MAJOR})

set(XAPTUM_TPM_SRCS
  src/nvram.c
) 

################################################################################
# TSS2
################################################################################
if(BUILD_TSS2)
  add_subdirectory(tss2)
else()
  find_package(TSS2 REQUIRED QUIET)
endif()

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

  target_link_libraries(xaptum-tpm PUBLIC
    tss2::sys
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

  if(BUILD_TSS2)
    target_link_libraries(xaptum-tpm_static PUBLIC
      tss2::sys_static
    )
  else()
    target_link_libraries(xaptum-tpm_static PUBLIC
      tss2::sys
    )
  endif()

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
install(DIRECTORY include/xaptum-tpm DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(FILES include/xaptum-tpm.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

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

################################################################################
# Tests
################################################################################
if(BUILD_TESTING)
  add_subdirectory(test)
endif()
