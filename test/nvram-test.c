/******************************************************************************
 *
 * Copyright 2017-2020 Xaptum, Inc.
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

#include <xaptum-tpm/nvram.h>

#include "test-utils.h"

void constants_test(void);

int main()
{
    constants_test();

    // TODO: Actually test this (this is jsut to satisfy cppcheck for now)
    (void)xtpm_read_object;
}

void constants_test(void)
{
    printf("In nvram-test::constants_test...\n");

    TEST_ASSERT(XTPM_GPK_HANDLE == xtpm_gpk_handle());

    TEST_ASSERT(XTPM_CRED_HANDLE == xtpm_cred_handle());

    TEST_ASSERT(XTPM_CRED_SIG_HANDLE == xtpm_cred_sig_handle());

    TEST_ASSERT(XTPM_ROOT_ASN1CERT_HANDLE == xtpm_root_asn1cert_handle());

    TEST_ASSERT(XTPM_BASENAME_HANDLE == xtpm_basename_handle());

    TEST_ASSERT(XTPM_SERVER_ID_HANDLE == xtpm_serverid_handle());

    TEST_ASSERT(XTPM_ROOT_XTTCERT_HANDLE == xtpm_root_xttcert_handle());

    printf("ok\n");
}
