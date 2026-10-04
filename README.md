# MagiskbootAlone

Standalone, CMake-only build of **magiskboot** — no Rust, no Magisk `Android.mk`.  
Builds on **host** (Linux/macOS/Windows) and on **Android** (via NDK).  
Boot image unpack/repack/split-dtb logic is derived from [Magisk](https://github.com/topjohnwu/Magisk) and reimplemented in pure C++ with external libraries.

## Features

- **Unpack** boot/vendor boot images (kernel, ramdisk, dtb, etc.)
- **Repack** from extracted files with optional recompression
- **Split DTB** from kernel images that embed device tree
- **Compression**: GZIP/ZOPFLI (via zlib); optional LZ4/XZ when enabled
- **Hashing & AVB**: SHA-1 / SHA-256 and AVB verify/sign via **mbedTLS** (no OpenSSL, no picosha2)
- **CPIO document API**: stable node IDs, complete newc metadata, streamed content,
  recursive moves, Unix metadata editing, symbolic links, and hard links
- **No-shards boot ramdisk API**: open a standard v3/v4 boot or init_boot image,
  edit its in-memory CPIO, and rebuild it without an unpack directory

## Embedded CPIO document API

`src/cpio.hpp` exposes a C++17 API for hosts that need to edit a ramdisk
without extracting every entry into a real directory:

```cpp
CpioDocument document;
document.load(ramdisk_bytes, ramdisk_size);

auto init = document.find("init");
document.read_content(*init, [](const std::uint8_t* data, std::size_t size) {
    return consume(data, size);
});

document.replace_content(*init, [](std::uint8_t* output, std::size_t capacity) {
    return produce(output, capacity);  // 0 = EOF, negative = failure
});

document.dump_fd(output_fd);
```

The document keeps node IDs stable across rename and move operations. It also
preserves inode/link information, timestamps, device metadata, and archive
order during a load/edit/dump cycle. Path-based CLI commands remain available
for compatibility, but new embedders should use the node API.

`src/boot_ramdisk.hpp` connects that document directly to modern standard AOSP
boot images:

```cpp
BootRamdiskDocument image;
image.load("init_boot.img");

CpioDocument& ramdisk = image.ramdisk();
// Use the same stable-node and streamed-content operations shown above.

image.dump("new-init_boot.img");
```

The no-shards path currently accepts standard AOSP boot/init_boot header v3-v4
images with a single CPIO ramdisk. It retains the source compression and
supported AVB footer layout. The source can also be rebuilt into a byte vector
or callback sink.

## Requirements

- CMake ≥ 3.20
- C++17 compiler (GCC, Clang, or MSVC)
- **zlib** (required)
- **mbedTLS** (fetched via CMake FetchContent; provides SHA1/SHA256 and X.509/RSA/ECDSA for AVB)

## Build

### Host (Linux / macOS / Windows)

```bash
cmake -S . -B build
cmake --build build
```

Binary: `build/magiskboot` (or `build/magiskboot.exe` on Windows).

### Android (NDK，设备上运行)

在安卓设备上跑的版本需要用 **Android NDK** 交叉编译：

```bash
# 设置 ANDROID_NDK 或 ANDROID_HOME（已安装 NDK）
export ANDROID_NDK=/path/to/ndk
./build_android.sh              # 默认 arm64-v8a
./build_android.sh armeabi-v7a
./build_android.sh x86_64
./build_android.sh x86
```

或用 CMake 直接指定 NDK toolchain：

```bash
cmake -S . -B build_android \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-21 \
cmake --build build_android
```

产物：`build_android/magiskboot`，推送到设备后可直接运行（例如 `adb push build_android/magiskboot /data/local/tmp && adb shell /data/local/tmp/magiskboot unpack boot.img`）。  
Android 构建使用 mbedTLS（FetchContent），无需预装 OpenSSL。

## Usage

```bash
./magiskboot unpack  <boot.img> [--skip-decomp] [--hdr]
./magiskboot repack  <in-boot.img> <out-boot.img> [--skip-comp]
./magiskboot split-dtb <kernel-or-boot.img> [--skip-decomp]
```

- **unpack**: extracts kernel, ramdisk, dtb, etc. into the current directory; optionally skip decompression or dump header to `header`.
- **repack**: builds a new boot image from the files produced by `unpack` (and optionally edited).
- **split-dtb**: splits a single file into kernel + `kernel_dtb` when the image embeds a DTB.

## Project layout

```
.
├── CMakeLists.txt
├── LICENSE
├── README.md
├── .github/workflows/build.yml
└── src/
    ├── base_host.hpp / base_host.cpp   # Minimal host utils (log, xopen, mmap, byte_view)
    ├── boot_crypto.hpp / boot_crypto.cpp  # SHA + compress/decompress (zlib, optional OpenSSL)
    ├── bootimg.hpp / bootimg.cpp       # Boot image structures and unpack/repack logic
    ├── magiskboot.hpp                  # Constants and API declarations
    └── magiskboot_main.cpp             # CLI entry (unpack / repack / split-dtb)
```

## Origin and license

- Boot image format handling and unpack/repack logic are adapted from **Magisk**’s `native/src/boot` (C++ and formerly Rust).  
- This repository is a standalone, Rust-free reimplementation intended for use in projects that only need the magiskboot binary (e.g. [ZySU](https://github.com/wuluoy-creator/ZySU)) and prefer a single CMake build.
- **License**: [GPL-3.0](LICENSE). Same as Magisk. See [LICENSE](LICENSE) for full text.

## CI

GitHub Actions builds the project on every push/PR (see [.github/workflows/build.yml](.github/workflows/build.yml)):

- **Ubuntu** → `magiskboot-linux`
- **macOS** → `magiskboot-macos`
- **Android (NDK)** → `magiskboot-android-arm64-v8a`、`magiskboot-android-armeabi-v7a`、`magiskboot-android-x86_64`、`magiskboot-android-x86`
