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

```bash
cd build
ctest -V
```
