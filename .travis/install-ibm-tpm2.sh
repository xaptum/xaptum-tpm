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

set -e

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <git-tag> <absolute-path-to-tpm-simulator-installation-directory>"
        exit 1
fi

source_tag="$1"
installation_dir="$2"

if [[ ! -d "$installation_dir" ]]; then
        git clone --branch "${source_tag}" --depth 1 https://github.com/xaptum-eng/ibm-tpm2-simulator-mirror "$installation_dir"
fi

pushd $installation_dir 

make

popd
