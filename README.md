# Xaptum TPM

[![Release](https://img.shields.io/github/release/xaptum/xaptum-tpm.svg)](https://github.com/xaptum/xaptum-tpm/releases)
[![Build Status](https://travis-ci.org/xaptum/xaptum-tpm.svg?branch=master)](https://travis-ci.org/xaptum/xaptum-tpm)

Utilities for interacting with a TPM2.0 used for access to the Xaptum Edge Network Fabric.

## Installation

`xaptum-tpm` is available for the following distributions. It may also
be built from source.

### Debian (Stretch, Buster) and Ubuntu (Bionic)

``` bash
DIST=$(lsb_release -cs)

# Install the Xaptum API repo GPG signing key.
sudo apt-get install dirmngr
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca

# Add the repository to your APT sources
echo "deb https://xaptum.jfrog.io/artifactory/debian ${DIST} main" | sudo tee /etc/apt/sources.list.d/xaptum.list
sudo apt-get update

# Install the library
sudo apt-get install libxaptum-tpm-dev
```

### Homebrew (MacOS)

``` bash
# Tap the Xaptum repository.
brew tap xaptum/xaptum

# Install the library.
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

By default, the tests use a device-file-based TCTI.
For this reason, `sudo` privileges may be required to run them.

The tests can instead be build to use a TCP-socket-based TCTI,
by using the CMake option `TEST_USE_TCP_TPM=ON`.

If using the TCP-socket-based TCTI, the tests require a [TPM 2.0
simulator](https://sourceforge.net/projects/ibmswtpm2/) running
locally on TCP port 2321.

Use the following commands to start the simulator before running the tests.
```
.travis/install-ibm-tpm2.sh <installation dir>
.travis/run-ibm-tpm2.sh
```

To run the tests:

```bash
cd build
ctest -V
```

### Installing

```bash
cd build
cmake --build . --target install
```

# License
Copyright 2017-2018 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
