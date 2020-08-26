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

# "error-exitcode" makes bugs cause non-zero return code
cppcheck -v --std=c99 --error-exitcode=6 --enable=all --suppress=missingIncludeSystem -I $(pwd)/include/ -I $(pwd)/tss2/include/ $(pwd)/src/ $(pwd)/tss2/src/ $(pwd)/test/ $(pwd)/tss2/test/
