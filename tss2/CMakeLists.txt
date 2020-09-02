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

set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/tss2)

set(XAPTUM_TSS2_TCTI_DEVICE_SRCS
    src/tss2_tcti_device.c

    src/internal/marshal.c
)

set(XAPTUM_TSS2_TCTI_MSSIM_SRCS
    src/tss2_tcti_mssim.c

    src/internal/marshal.c
)

set(XAPTUM_TSS2_SYS_SRCS
    src/tss2_sys_context_allocation.c
    src/tss2_sys_clear.c
    src/tss2_sys_create.c
    src/tss2_sys_createprimary.c
    src/tss2_sys_commit.c
    src/tss2_sys_hierarchychangeauth.c
    src/tss2_sys_load.c
    src/tss2_sys_evictcontrol.c
    src/tss2_sys_readpublic.c
    src/tss2_sys_nv.c
    src/tss2_sys_sign.c

    src/internal/cmdauths.c
    src/internal/execute.c
    src/internal/marshal.c
    src/internal/sys_context_common.c
    src/internal/command_utils.c
)

macro(xtpm_build lib_name)
  # Shared Libary
  if(BUILD_SHARED_LIBS)
    add_library(${lib_name} SHARED ${ARGN})

    set_target_properties(${lib_name} PROPERTIES
      VERSION "${XAPTUM_TPM_VERSION}"
      SOVERSION "${XAPTUM_TPM_SOVERSION}"
    )

    target_include_directories(${lib_name} PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    install(TARGETS ${lib_name}
            EXPORT ${lib_name}-targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

    # Alias, to use this internally via a namespaced-name
    string(REPLACE "tss2-" "" namespaced_name ${lib_name})
    add_library(tss2::${namespaced_name} ALIAS ${lib_name})
  endif()

  # Static Libary
  if(BUILD_STATIC_LIBS)
    add_library(${lib_name}_static STATIC ${ARGN})

    set_target_properties(${lib_name}_static PROPERTIES
      OUTPUT_NAME "${lib_name}${STATIC_SUFFIX}"
      VERSION "${XAPTUM_TPM_VERSION}"
      SOVERSION "${XAPTUM_TPM_SOVERSION}"
    )

    target_include_directories(${lib_name}_static PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    install(TARGETS ${lib_name}_static
            EXPORT ${lib_name}-targets
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    )

    # Alias, to use this internally via a namespaced-name
    string(REPLACE "tss2-" "" namespaced_name ${lib_name})
    add_library(tss2::${namespaced_name}_static ALIAS ${lib_name}_static)
  endif()

  # Headers
  install(DIRECTORY include/tss2 DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

  # pkgconfig
  configure_file(${lib_name}.pc.in ${lib_name}.pc @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${lib_name}.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  # CMake export
  install(EXPORT ${lib_name}-targets
          FILE ${lib_name}-targets.cmake
          NAMESPACE xaptum-tpm::
          DESTINATION ${INSTALL_CONFIGDIR}
  )
endmacro()

################################################################################
# Build SAPI library
################################################################################
xtpm_build(tss2-sys ${XAPTUM_TSS2_SYS_SRCS})

################################################################################
# Build TCTI-device library
################################################################################
xtpm_build(tss2-tcti-device ${XAPTUM_TSS2_TCTI_DEVICE_SRCS})

################################################################################
# Build TCTI-mssim library
################################################################################
xtpm_build(tss2-tcti-mssim ${XAPTUM_TSS2_TCTI_MSSIM_SRCS})

################################################################################
# Expand CMake config template
################################################################################
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/tss2-config-version.cmake
  VERSION ${XAPTUM_TPM_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/tss2-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/tss2-config.cmake
  INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/tss2-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/tss2-config-version.cmake
  DESTINATION ${INSTALL_CONFIGDIR}
)

################################################################################
# Build tests
################################################################################
if(BUILD_TESTING)
  add_subdirectory(test)
endif()
