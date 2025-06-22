# Raspberry Pi (1 through 4) Broadcom Mailbox Communication Library

A **modern C++17** implementation of the Raspberry Pi GPU mailbox interface—packaged as a **git submodule** (header + source) you can embed directly into your project.

## 📌 Features

- New C++17 rewrite of the legacy Broadcom C API (`open`, `mem_alloc`, etc.).
- `[[nodiscard]]` annotations on critical APIs to prevent dropped error codes.
- Compile‑time constants: `PAGE_SIZE`, `BLOCK_SIZE`, `BUS_FLAG_MASK`, `PERIPH_BUS_BASE`.
- Correct big‑endian parsing of `/proc/device-tree/soc/ranges` for accurate peripheral base discovery (`discover_peripheral_base()`).
- Throws `std::runtime_error` or `std::system_error` instead of exiting on failure.
- Lightweight: No external dependencies beyond the C++17 standard library and Linux kernel headers.

## 📦 Integration as a Submodule

1. **Add as submodule**

   ```bash
   cd your-project
   git submodule add https://github.com/lbussy/Broadcom-Mailbox.git extern/Broadcom-Mailbox
   git submodule update --init --recursive
   ```

2. **Include in your build**

   - Add the mailbox source directory to your include path.
   - Compile & link `mailbox.cpp` and the legacy shim `old_mailbox.c` alongside your sources.

   ```makefile
   INCLUDES += -I$(PROJECT_ROOT)/extern/Broadcom-Mailbox/src
   SRCS     += \
       $(PROJECT_ROOT)/extern/Broadcom-Mailbox/src/mailbox.cpp
   ```

3. **Include the header**

   ```cpp
   #include "mailbox.hpp"
   extern Mailbox mailbox;  // global instance
   ```

4. **Call the API**

   ```cpp
   mailbox.open();  // open the device

   uint32_t handle = mailbox.mem_alloc(
       Mailbox::PAGE_SIZE,   // size
       Mailbox::BLOCK_SIZE,  // alignment
       flags                 // mailbox flags
   );

   std::uintptr_t bus = mailbox.mem_lock(handle);

   volatile uint8_t* ptr = mailbox.mapmem(
       Mailbox::discover_peripheral_base(),
       Mailbox::PAGE_SIZE
   );

   // … use ptr …

   mailbox.unmapmem(ptr, Mailbox::PAGE_SIZE);
   mailbox.mem_unlock(handle);
   mailbox.mem_free(handle);
   mailbox.mbox_close();
   ```

## 🔧 Build Requirements

- **Raspberry Pi OS** (Pi 1 through Pi 4)
- **Linux kernel ≥ 4.1** (provides `/dev/vcio`)
- **GCC** or **Clang** with **-std=c++17** support

## ⚠️ Usage Notes

- Must run with **root privileges** (e.g. via `sudo`) to map `/dev/mem` and open `/dev/vcio`.
- Endianness conversion is handled internally—no manual byte‑swapping required.

## 📜 License

Legacy mailbox code was distributed by Broadcom under the **BSD 3-Clause License**. As a new product, the C++ code in this repository is released under the  [MIT License](LICENSE.md).

## 🤝 Contributing

Contributions are welcome. Please fork, branch, commit, and open a PR.
