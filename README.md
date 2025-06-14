# Raspberry Pi Broadcom Mailbox Communication Library

A minimal C++17 wrapper for the Raspberry Pi GPU mailbox interface—designed to be used as a **git submodule** in your project rather than a system-wide library install.

## 📌 Features

* Thin, one‑for‑one C++ shim over the legacy C API (`mbox_open`, `mem_alloc`, etc.)
* Correct big‑endian parsing of `/proc/device-tree/soc/ranges` for peripheral base
* Explicit control over mailbox open/close, memory allocation, lock/unlock, and physical memory mapping
* Lightweight: no external dependencies beyond the C++ standard library and the Linux kernel headers

## 📦 Integration as a Submodule

1. **Add as submodule**

   ```bash
   cd your-project
   git submodule add https://github.com/lbussy/Broadcom-Mailbox.git extern/Broadcom-Mailbox

   # Initialize and fetch
   git submodule update --init --recursive
   ```

2. **Include in your build**

   * Add `extern/Broadcom-Mailbox/src` (or wherever you placed it) to your include path.
   * Compile and link `mailbox.cpp` and `old_mailbox.c` alongside your own sources.

   ```makefile
   INCLUDES += -I$(PROJECT_ROOT)/extern/Broadcom-Mailbox/src
   SRCS     += \
       $(PROJECT_ROOT)/extern/Broadcom-Mailbox/src/mailbox.cpp \
       $(PROJECT_ROOT)/extern/Broadcom-Mailbox/src/old_mailbox.c
   ```

3. **Include the header**

   ```cpp
   #include "mailbox.hpp"
   extern Mailbox mailbox; // global instance
   ```

4. **Call the API**

   ```cpp
   mailbox.mbox_open();
   uint32_t handle = mailbox.mem_alloc(4096, 4096, flags);
   uint32_t bus    = mailbox.mem_lock(handle);
   void*   ptr     = mailbox.mapmem(
       Mailbox::discover_peripheral_base(), 4096
   );
   mailbox.unmapmem(ptr, 4096);
   mailbox.mem_unlock(handle);
   mailbox.mem_free(handle);
   mailbox.mbox_close();
   ```

## 🔧 Build Requirements

* **Raspberry Pi OS (Raspbian)** on board (Pi 1 through Pi 4)
* **Linux kernel ≥ 4.1** (provides `/dev/vcio`)
* **GCC** or **Clang** with C++17 support

## ⚠️ Usage Notes

* **Run as root** (e.g., via `sudo`) to map `/dev/mem` for peripheral access.
* Endianness is handled internally—no manual byte-swapping needed.
* This is a **header + source** inclusion; no `make install` step.

## 📜 License

Distributed under the **BSD 3-Clause License**. See [LICENSE](LICENSE.md).

## 🤝 Contributing

PRs welcome. Please fork, branch, commit, and open a pull request.
