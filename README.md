# Xaptum TPM

Utilities for interacting with a TPM2.0 used for access to the Xaptum Edge Network Fabric.

## Project Status

[![Build Status](https://travis-ci.org/xaptum/xaptum-tpm.svg?branch=master)](https://travis-ci.org/xaptum/xaptum-tpm)

## Installation

`xaptum-tpm` is available for the following distributions. It may also
be built from source.

### Debian (Jessie or Stretch)

Install the repository GPG key.

``` bash
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca
```

Add the repository to APT sources, replacing `<dist>` with either `jessie`
or `stretch`.

``` bash
echo "deb http://dl.bintray.com/xaptum/deb <dist> main" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
```

Install the library.

``` bash
sudo apt-get install libxaptum-tpm-dev
```

### Homebrew (MacOS)

Tap the Xaptum repository.

``` bash
brew tap xaptum/xaptum
```

Install the library.
``` bash
brew install xaptum-tpm
```

## Installation from Source

### Build Dependencies

* CMake (version 3.0 or higher)
* A C99-compliant compiler
* A POSIX-compliant platform

### Building

```bash
# Create a subdirectory to hold the build
mkdir -p build
cd build

# Configure the build
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build the library
cmake --build .
```

### CMake Options

The following CMake configuration options are supported.

| Option                          | Values          | Default    | Description                                     |
|---------------------------------|-----------------|------------|-------------------------------------------------|
| CMAKE_BUILD_TYPE                | Release         |            | With full optimizations.                        |
|                                 | Debug           |            | With debug symbols.                             |
|                                 | RelWithDebInfo  |            | With full optimizations and debug symbols.      |
|                                 | RelWithSanitize |            | With address and undefined-behavior sanitizers. |
| CMAKE_INSTALL_PREFIX            | <string>        | /usr/local | The directory to install the library in.        |
| BUILD_SHARED_LIBS               | ON, OFF         | ON         | Build shared libraries.                         |
| BUILD_STATIC_LIBS               | ON, OFF         | OFF        | Build static libraries.                         |
| BUILD_TESTING                   | ON, OFF         | ON         | Build the test suite.                           |
| STATIC_SUFFIX                   | <string>        | <none>     | Appends a suffix to the static lib name.        |
| CMAKE_POSITION_INDEPENDENT_CODE | ON, OFF         | ON         | Compile static libs with `-fPIC`.               |

### Testing

The tests assume that a TPM2.0 simulator (for instance, [IBM's simulator](https://sourceforge.net/projects/ibmswtpm2/))
is listening locally on TCP port 2321.
This can be achieved by running the following in the background, before starting the tests:
```
.travis/install-ibm-tpm2.sh <installation dir>
.travis/run-ibm-tpm2.sh
```

Then, to run the test suite:
```bash
cd build
ctest -V
```

### Installing

```bash
cd build
cmake --build . --target install
```
