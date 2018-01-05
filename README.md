# Xaptum TPM

Utilities for interacting with a TPM2.0 used for access to the Xaptum Edge Network Fabric.

## Project Status

[![Build Status](https://travis-ci.org/xaptum/xaptum-tpm.svg?branch=master)](https://travis-ci.org/xaptum/xaptum-tpm)

## Requirements
- cmake version >= 3.0
- A C99-compliant compiler
- Currently, only supports POSIX platforms

## Building

`xaptum-tpm` uses CMake as its build system:

```bash
# Create a subdirectory to hold the build
mkdir -p build
cd build

# Configure the build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON

# Build the library
cmake --build .
```

In addition to the standard CMake options the following configuration
options and variables are supported.

### Static vs Shared Libary
If `BUILD_SHARED_LIBS` is set, the shared library is built. If
`BUILD_STATIC_LIBS` is set, the static library is built. If both are
set, both libraries will be built.  If neither is set, the static
library will be built.

### Static Library Name
`STATIC_SUFFIX`, if defined, will be appended to the static library
name.  For example,

```bash
cmake .. -DBUILD_STATIC_LIBS=ON -DSTATIC_SUFFIX=_static
cmake --build .
```

will create a static library named `libxaptum_tpm_static.a`.

### Force Position Independent Code (-fPIC)
Set the standard CMake variable `CMAKE_POSITION_INDEPENDENT_CODE` to
`ON` to force compilation with `-fPIC` for static libraries.  The
default is `OFF` for static libraries and `ON` for shared libraries.

### Disable Building of Tests
Set the standard CMake variable `BUILD_TESTING` to `OFF` to disable
the building of tests.  The default value is `ON`.

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
