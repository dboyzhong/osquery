osquery supports many flavors of Linux, FreeBSD, macOS, and Windows.

While osquery runs on a large number of operating systems, we only provide instructions for building on a select few.

The supported compilers are: clang/libc++ 6.0 on Linux, MSVC v141 on Windows, AppleClang from Xcode Command Line Tools 10.2.1.

# Building with CMake

Git, CMake (>= 3.13.3), Python 2, and Python 3 are required to build. The rest of the dependencies are downloaded by CMake.

The default build type is `RelWithDebInfo` (optimizations active + debug symbols) and can be changed in the CMake configure phase by setting the `CMAKE_BUILD_TYPE` flag to `Release` or `Debug`.

The build type is chosen when building on Windows, not during the configure phase, through the `--config` option.

## Linux

The root folder is assumed to be `/home/<user>`

**Ubuntu 18.04**

```
# Install the prerequisites
sudo apt install git llvm clang libc++-dev libc++abi-dev liblzma-dev python python3

# Download and install a newer CMake
wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.14.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
# Verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`

# Download and build osquery
git clone https://github.com/osquery/osquery
mkdir build; cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

**Ubuntu 18.10**

```
# Install the prerequisites
sudo apt install git llvm-6.0 clang-6.0 libc++-dev libc++abi-dev liblzma-dev python python3

# Download and install a newer CMake
wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.14.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
# Verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`

# Download and build osquery
git clone https://github.com/osquery/osquery
mkdir build; cd build
cmake -DCMAKE_C_COMPILER=clang-6.0 -DCMAKE_CXX_COMPILER=clang++-6.0 ..
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

## macOS

Please ensure [homebrew](https://brew.sh/) has been installed. The root folder is assumed to be `/Users/<user>`

```
# Install prerequisites
xcode-select --install
brew install git cmake python@2 python

# Download and build
git clone https://github.com/osquery/osquery

# Configure
mkdir build; cd build
cmake ..

# Build
cmake --build .
```

## Windows 10

The root folder is assumed to be `C:\Users\<user>`

**Step 1: Install the prerequisites**

- [CMake](https://cmake.org/) (>= 3.14.4): be sure to put it into the `PATH`
- [Build Tools for Visual Studio 2019](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16): from the installer choose the C++ build tools workload, then on the right, under Installation details, also check MSVC v141
- [Git for Windows](https://github.com/git-for-windows/git/releases/latest) (or equivalent)
- [Python 2](https://www.python.org/downloads/windows/)
- [Python 3](https://www.python.org/downloads/windows/)

**Step 2: Download and build**

```
# Download using a PowerShell console
git clone https://github.com/osquery/osquery

# Configure
mkdir build; cd build
cmake -G "Visual Studio 16 2019" -A x64 -T v141 ..

# Build
cmake --build . --config RelWithDebInfo -j10 # Number of projects to build in parallel
```

## Testing

To build with tests active, add `-DOSQUERY_BUILD_TESTS=ON` to the osquery configure phase, then build the project. CTest will be used to run the tests and give a report.

**Run tests on Windows**

To run the tests and get just a summary report:

```
cmake --build . --config <RelWithDebInfo|Release|Debug> --target run_tests
```

To get more information when a test fails using powershell:

```
$Env:CTEST_OUTPUT_ON_FAILURE=1
cmake --build . --config <RelWithDebInfo|Release|Debug> --target run_tests
```

To run a single test, in verbose mode:

```
ctest -R <test name> -C <RelWithDebInfo|Release|Debug> -V
```

**Run tests on Linux and MacOS**

To run the tests and get just a summary report:

```
cmake --build . --target test
```

To get more information when a test fails:
```
CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test
```

To run a single test, in verbose mode:

```
ctest -R <test name> -V
```

# Building with Buck

Building and testing is the same on all platforms. Each platform section below describes how to install the required tools and dependencies.

## Linux

Install required tools on Ubuntu 18.04 or Ubuntu 18.10

```
sudo apt install openjdk-8-jre clang libc++1 libc++-dev libc++abi1 libc++abi-dev python python3 python3-distutils
```

Install library dependencies

```
sudo apt install liblzma-dev
```

Install `buck`

```
wget 'https://github.com/facebook/buck/releases/download/v2018.10.29.01/buck.2018.10.29.01_all.deb'
sudo apt install ./buck.2018.10.29.01_all.deb
```

## macOS

Install required tools using Homebrew

```
xcode-select --install

brew tap caskroom/cask
brew tap caskroom/versions
brew cask install java8
```

Install `buck` and `watchman`. Watchman isn't mandatory but will make builds faster.

```
brew tap facebook/fb
brew install buck watchman
```

## FreeBSD

Install required tools on FreeBSD 11.2

```
sudo pkg install openjdk8 python3 python2 clang35
```

Install `buck`

```
sudo curl --output /usr/local/bin/buck 'https://jitpack.io/com/github/facebook/buck/v2018.10.29.01/buck-v2018.10.29.01.pex'
sudo chmod +x /usr/local/bin/buck
```

Install library dependencies

```
sudo pkg install glog thrift thrift-cpp boost-libs magic rocksdb-lite rapidjson zstd linenoise-ng augeas ssdeep sleuthkit yara aws-sdk-cpp lldpd libxml++-2 smartmontools lldpd
```

## Windows 10

You'll need to have the following software installed before you can build osquery on Windows:

* Buck, this also requires the JRE 8 version
* Visual Studio 2017 or greater
* The Windows 10 SDK
* Python3

Once you've installed the above requirements, run `.\tools\generate_buck_config.ps1 -VsInstall '' -VcToolsVersion '' -SdkInstall '' -SdkVersion '' -Python3Path '' -BuckConfigRoot .\tools\buckconfigs\` to generate the buckconfig for building.

## Building and Testing

To build simply run the following command replacing `<platform>` and `<mode>`
appropriately:

```
buck build @mode/<platform>/<mode> //osquery:osqueryd
```

When buck finishes find the binary at `buck-out/<mode>/gen/osquery/osqueryd`.

Similarly to run tests just run:

```
buck test @mode/<platform>/<mode> //...
```

This will run all tests, you can replace `//...` with a specific target to run specific tests only.

Supported platforms:

* `linux-x86_64`
* `macos-x86_64`
* `windows-x86_64`
* `freebsd-x86_64`

Supported modes:

* `release`
* `debug`

# Using Vagrant

If you are familiar with Vagrant there is a helpful configuration in the root directory for testing osquery.

## AWS EC2 Backed Vagrant Targets

The osquery vagrant infrastructure supports leveraging AWS EC2 to run virtual machines.
This capability is provided by the [vagrant-aws](https://github.com/mitchellh/vagrant-aws) plugin, which is installed as follows:

```sh
$ vagrant plugin install vagrant-aws
```

Next, add a vagrant dummy box for AWS:

```sh
$ vagrant box add andytson/aws-dummy
```

Before launching an AWS-backed virtual machine, a few environment variables must be set:

```sh
# Required. Credentials for AWS API. vagrant-aws will error if these are unset.
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# Name of AWS keypair for launching and accessing the EC2 instance.
export AWS_KEYPAIR_NAME=my-osquery-vagrant-security-group
export AWS_SSH_PRIVATE_KEY_PATH=/path/to/keypair.pem
# Name of AWS security group that allows TCP/22 from vagrant host.
# If using a non-default VPC use the security group ID instead.
export AWS_SECURITY_GROUP=my-osquery-vagrant-security-group
# Set this to the AWS region, "us-east-1" (default) or "us-west-1".
export AWS_DEFAULT_REGION=...
# Set this to the AWS instance type. If unset, m3.medium is used.
export AWS_INSTANCE_TYPE=m3.large
# (Optional) Set this to the VPC subnet ID.
# (Optional) Make sure your subnet assigns public IPs and there is a route.
export AWS_SUBNET_ID=...
```

Spin up a VM in EC2 and SSH in (remember to suspect/destroy when finished):

```sh
$ vagrant up aws-amazon2015.03 --provider=aws
$ vagrant ssh aws-amazon2015.03
```

# Custom Packages

Package creation is facilitated by CPack.

# Build Performance

Generating a virtual table should NOT impact system performance. This is easier said than done as some tables may _seem_ inherently latent such as `SELECT * from suid_bin;` if your expectation is a complete filesystem traversal looking for binaries with suid permissions. Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

* Performance regression and leak detection CI guards.
* Blacklisting performance-impacting virtual tables.
* Scheduled query optimization and profiling.
* Query implementation isolation options.
