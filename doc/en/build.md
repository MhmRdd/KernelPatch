# How to Build

## Build kpimg

Require a bare-metal cross compiler
[Download here](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # Android version, including support for the 'su' command
make
```

## Build kptools

kptools is written in C++17 and uses CMake for building.

```shell
cd tools
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
# Output: bin/kptools
```

### Cross-compile for Android

```shell
export ANDROID_NDK=/path/to/ndk
cd tools
mkdir -p build/android && cd build/android
cmake \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DANDROID_PLATFORM=android-26 \
    -DANDROID_ABI=arm64-v8a \
    -DKPTOOLS_ANDROID=ON \
    ../..
cmake --build .
```

## Build KernelPatch Module

Example:

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpms/demo-hello
make
```
