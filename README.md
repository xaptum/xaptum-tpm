# Xaptum TPM

Utilities for interacting with a TPM2.0 used for access to the Xaptum Edge Network Fabric.

## Project Status

[![Build Status](https://travis-ci.org/xaptum/xaptum-tpm.svg?branch=master)](https://travis-ci.org/xaptum/xaptum-tpm)

## Requirements
- cmake version >= 3.0
- A C99-compliant compiler
- Currently, only supports POSIX platforms

## Building

```bash
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build . -- -j4
```

## Running the tests
The tests assume that a TPM2.0 simulator (for instance, [IBM's simulator](https://sourceforge.net/projects/ibmswtpm2/))
is listening locally on TCP port 2321.
This can be achieved by running the following in the background, before starting the tests:
```
.travis/install-ibm-tpm2.sh
.travis/run-ibm-tpm2.sh
```

Then, to run the test suite:
```bash
cd build
ctest -V
```
