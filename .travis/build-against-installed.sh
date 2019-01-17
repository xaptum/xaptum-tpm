#!/bin/bash
#
# Attempt to build a project that depends on xaptum-tpm,
# to test that an installation of xaptum-tpm works correctly.

set -e

if [[ $# -ne 2 ]]; then
        echo "usage: $0 <xaptum-tpm installation directory> <tmp directory>"
        exit 1
fi

install_dir="$1"
tmp_dir="$2"
output_file=${tmp_dir}/installation-test.out

function cleanup()
{
        rm -f $output_file
}
trap cleanup INT KILL EXIT

LIB_DIR="${install_dir}/lib"

INCLUDE_FLAGS="-I${install_dir}/include"
LINKER_FLAGS="-L${LIB_DIR} -lxaptum-tpm"

echo "Attempting to build downstream program..."
cc $INCLUDE_FLAGS -x c - -o $output_file -std=c99 $LINKER_FLAGS <<'EOF'
#include <stdio.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tcti_socket.h>
#include <tss2/tss2_tpm2_types.h>
int main() {
printf("It worked!\n");
}
EOF
echo "ok"

echo "Attempting to run downstream executable..."
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${LIB_DIR}
${output_file}
echo "ok"
