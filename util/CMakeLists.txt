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

################################################################################
# xtpm_read_nvram
################################################################################
add_executable(xtpm_read_nvram xtpm_read_nvram.c)
if(BUILD_SHARED_LIBS)
      target_link_libraries(xtpm_read_nvram PRIVATE xaptum-tpm)
else()
      target_link_libraries(xtpm_read_nvram PRIVATE xaptum-tpm_static)
endif()
install(TARGETS xtpm_read_nvram DESTINATION ${CMAKE_INSTALL_BINDIR})
