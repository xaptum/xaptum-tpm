#!/bin/bash
#
# Attempt to build a project that depends on xaptum-tpm,
# to test that an installation of xaptum-tpm works correctly.

set -e

if [[ $# -ne 3 ]]; then
        echo "usage: $0 <xaptum-tpm installation directory> <tss2 install directory> <tmp directory>"
        exit 1
fi

install_dir="$1"
tss2_install_dir="$2"
tmp_dir="$3"
output_file=${tmp_dir}/installation-test.out

function cleanup()
{
        rm -f $output_file
}
trap cleanup INT KILL EXIT

LIB_DIR="${install_dir}/lib"
TSS2_LIB_DIR="${tss2_install_dir}/lib"

INCLUDE_FLAGS="-I${install_dir}/include -I${tss2_install_dir}/include"

echo "Attempting to build downstream program..."
cc $INCLUDE_FLAGS -x c - -o $output_file -std=c99 <<'EOF'
#include <stdio.h>
#include <xaptum-tpm.h>
int main() {
printf("It worked!\n");
}
EOF
echo "ok"

echo "Attempting to run downstream executable..."
${output_file}
echo "ok"
