# Broadcom-Mailbox C++ Interface

A modern C++17 wrapper around the Raspberry Pi’s GPU mailbox property interface, enabling:

- Opening and closing `/dev/vcio`
- Querying the GPU firmware version
- Allocating, locking, unlocking, and freeing GPU-accessible memory
- Mapping and unmapping physical memory via `/dev/mem`
- Optional “fake‐hook” mode for unit testing without hardware

This library exposes a convenient, RAII-friendly API (`Mailbox` and `MappedRegion`) that abstracts low-level `ioctl()` calls and `mmap()` operations behind exception-safe C++ methods.

---

## Table of Contents

1. [Features](#features)
2. [Dependencies](#dependencies)
3. [Building](#building)
4. [Installation](#installation)
5. [Usage](#usage)
   - [Opening & Closing the Mailbox](#opening--closing-the-mailbox)
   - [Querying Firmware Version](#querying-firmware-version)
   - [Allocating & Freeing GPU Memory](#allocating--freeing-gpu-memory)
   - [Locking & Unlocking GPU Memory](#locking--unlocking-gpu-memory)
   - [Mapping Physical Memory](#mapping-physical-memory)
   - [Cleaning Up](#cleaning-up)
   - [Test-Hook Mode](#test-hook-mode)
6. [Error Handling](#error-handling)
7. [Contributing](#contributing)
8. [License](#license)

---

## Features

- **Singleton Mailbox Interface** (`Mailbox::instance()`):
  Thread-safe, lazy initialization of `/dev/vcio` file descriptor.
- **RAII-style MappedRegion**:
  Wraps `mmap()`/`munmap()` into a move-only class that unmaps on destruction.
- **GPU Memory Management**:
  – `mem_alloc()`, `mem_lock()`, `mem_unlock()`, `mem_free()` for contiguous, DMA-capable memory.
- **Physical Memory Mapping**:
  – `mapmem()` returns a `MappedRegion` pointing to a byte-aligned view of `/dev/mem`.
- **Debug Output**:
  Enable verbose mailbox messages with `Mailbox::set_debug()`.
- **Fake-Hook Mode**:
  Install in-library stubs for unit testing on a non-Pi host.

---

## Dependencies

- C++17-compatible compiler (GCC 8+, Clang 10+, MSVC 2017+)
- Linux kernel headers (for `ioctl`, `/dev/mem`, `/dev/vcio`)
- Standard C/C++ libraries (no external dependencies)

---

## Building

1. Clone this repository:

	```bash
	git clone https://github.com/YourUser/Broadcom-Mailbox.git
	cd Broadcom-Mailbox
	```

2. Create a build directory and invoke CMake:

	```cpp
	mkdir build && cd build
	cmake -DCMAKE_BUILD_TYPE=Debug ..
	make
	```

By default, a broadcom-mailbox library and a small `test_mailbox` binary are compiled.

## Installation

To install the library and headers system-wide (⇧ should run as root or via sudo):

```bash
cd build
make install
```

By default, headers go to `/usr/local/include/broadcom-mailbox` and the shared library to `/usr/local/lib`.

---

## Usage

Include the public header and link against `libbroadcom-mailbox`. Below are common usage patterns.

### Opening & Closing the Mailbox

```cpp
#include <broadcom-mailbox/mailbox.hpp>
using namespace std;

int main() {
    // Acquire singleton instance
    Mailbox &mbox = Mailbox::instance();

    // Open /dev/vcio (throws on failure)
    int fd = mbox.mbox_open();

    // ... use other methods ...

    // Close (only if it matches the cached FD; otherwise no-op)
    mbox.mbox_close(fd);
    return 0;
}
```

### Querying Firmware Version

```cpp
#include <iostream>
#include <broadcom-mailbox/mailbox.hpp>

int main() {
    Mailbox &mbox = Mailbox::instance();
    int fd = mbox.mbox_open();

    try {
        uint32_t version = mbox.get_version(fd);
        std::cout << "GPU firmware version: 0x"
                  << std::hex << version << std::dec << std::endl;
    }
    catch (const std::system_error &e) {
        std::cerr << "Error fetching version: " << e.what() << "\n";
    }

    mbox.mbox_close(fd);
    return 0;
}
```

### Allocating & Freeing GPU Memory

```cpp
#include <iostream>
#include <broadcom-mailbox/mailbox.hpp>

int main() {
    Mailbox &mbox = Mailbox::instance();
    int fd = mbox.mbox_open();

    // Allocate 4 KB with 4 KB alignment and appropriate flags (e.g. 0x0C)
    uint32_t handle = mbox.mem_alloc(fd, 4096, 4096, /*flags=*/0x0C);
    std::cout << "Allocated handle: 0x" << std::hex << handle << std::dec << "\n";

    // Free the block when done
    mbox.mem_free(fd, handle);

    mbox.mbox_close(fd);
    return 0;
}
```

### Locking & Unlocking GPU Memory

Locking returns a bus address suitable for DMA. Always unlock after use.

```cpp
#include <iostream>
#include <broadcom-mailbox/mailbox.hpp>

int main() {
    Mailbox &mbox = Mailbox::instance();
    int fd = mbox.mbox_open();

    uint32_t handle = mbox.mem_alloc(fd, 8192, 4096, /*flags=*/0x0C);
    if (handle == 0) {
        std::cerr << "Allocation failed\n";
        return 1;
    }

    // Lock to obtain bus address
    uint32_t bus_addr = mbox.mem_lock(fd, handle);
    std::cout << "Bus address: 0x" << std::hex << bus_addr << std::dec << "\n";

    // Unlock and free when no longer needed
    mbox.mem_unlock(fd, handle);
    mbox.mem_free(fd, handle);

    mbox.mbox_close(fd);
    return 0;
}
```

### Mapping Physical Memory

Map a GPU-accessible region or any physical address (e.g. peripherals):

```cpp
#include <iostream>
#include <broadcom-mailbox/mailbox.hpp>

int main() {
    Mailbox &mbox = Mailbox::instance();

    // Example: map peripheral base 0x3F000000, length 0x1000
    constexpr uint32_t phys_base = 0x3F000000;
    constexpr size_t   length    = 0x1000;

    try {
        MappedRegion region = mbox.mapmem(phys_base, length);
        auto *ptr = region.get();  // std::byte* or cast to desired type
        if (!ptr) {
            throw std::runtime_error("mapmem returned nullptr");
        }

        // Access mapped memory:
        volatile uint32_t *reg = reinterpret_cast<volatile uint32_t *>(ptr);
        std::cout << "First 32-bit word: 0x"
                  << std::hex << reg[0] << std::dec << "\n";

        // Unmapping is automatic when ‘region’ goes out of scope.
    }
    catch (const std::system_error &e) {
        std::cerr << "mapmem error: " << e.what() << "\n";
    }

    return 0;
}
```

### Cleaning Up

To release the cached `/dev/mem` descriptor (optional; also registered with the destructor):

```cpp
mbox.mem_cleanup();
```

If you close your program normally, the destructor and registered cleanup routines will handle any remaining FDs.

---

## Test-Hook Mode

For unit tests on a non-Pi host (or to simulate failures), call:

```cpp
Mailbox &mbox = Mailbox::instance();
mbox.set_test_hooks();   // Installs fake_open, fake_version, etc.
mbox.set_debug();        // Print fake mailbox messages

int fd = mbox.mbox_open();   // Always returns 100 (fake)
uint32_t version = mbox.get_version(fd);  // Returns 0x00020000
// mem_alloc → always returns 123
// mem_lock  → always returns 0xABC
// mem_free  → no-op
// mapmem    → always fails with EPERM
// …
```

This allows exercising error paths without actual GPU hardware.

---

## Error Handling

All methods that perform I/O or system calls throw std::system_error on failure:

- mbox_open(): Throws if `/dev/vcio` cannot be opened.
- mbox_close(): Throws if `::close()` on the cached FD fails.
- get_version(): Throws if `ioctl()` fails or the tag response is invalid.
- `mem_alloc()`, `mem_lock()`, `mem_free()`, `mem_unlock()`: Throw if the mailbox property call fails or returns an invalid handle/address.
- `mapmem()`: Throws if opening /dev/mem fails or mmap() fails.
- `mem_cleanup()`: Throws if the fake hook fails (in test mode).

Always wrap calls in `try/catch` if you need to recover or print diagnostic messages.

---

## Contributing

1. Fork the repository and create a feature branch:

	```bash
	git checkout -b feature/your-feature
	```

2.	Make your changes and add tests as needed.
3.	Ensure all unit tests pass in both real-hook and fake-hook modes.
4.	Submit a Pull Request describing your changes and rationale.

Please follow the existing code style (K&R braces, 4-space indentation, Doxygen comments).

---

## License

This project is released under the [MIT License](LICENSE.md), © 2025 Lee C. Bussy. All rights reserved.
