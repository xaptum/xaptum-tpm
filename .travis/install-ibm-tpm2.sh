#!/bin/bash
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

if [[ $# -ne 1 ]]; then
        echo "usage: $0 <absolute-path-to-tpm-simulator-installation-directory>"
        exit 1
fi

tpm_version=532
tss_version=593

install_dir="$1"

mkdir -p ${install_dir}
cd ${install_dir}

mkdir -p ./tpm
cd ./tpm
wget https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm${tpm_version}.tar
tar xvf ibmtpm${tpm_version}.tar
cd ./src/
make
cd ../../

mkdir -p ./tss
cd ./tss
wget https://sourceforge.net/projects/ibmtpm20tss/files/ibmtss${tss_version}.tar
tar xvf ibmtss${tss_version}.tar
cd ./utils/
make
