# Raspberry Pi Broadcom Mailbox Communication Library

This library provides an interface for communicating with the **Raspberry Pi GPU** via the **mailbox interface**. It enables users to interact with the GPU, allocate memory, execute GPU code, and control QPUs.

This is NOT my code, it is code I found in some older projects and [Wsprry Pi](https://github.com/lbussy/wsprrypi) depends upon this to work with low-level device control.  This is also modified for my needs, and unused code (`qemu`) has been removed.

## 📌 Features

- Open and close the mailbox device.
- Query the mailbox interface version.
- Allocate, free, lock, and unlock GPU memory.
- Map physical memory into the process's address space.

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/lbussy/Broadcom-Mailbox.git
cd mailbox-library
```

### 2. Build the Library

```bash
make
```

### 3. Install System-Wide (Optional)

```bash
sudo make install
```

## 🚀 Usage

### 1. Include the Header in Your Code

```c
#include "mailbox.h"
```

### 2. Open the Mailbox Device\

```c
int file_desc = mbox_open();
```

### 3. Allocate Memory

```c
uint32_t handle = mem_alloc(file_desc, 1024, 4096, 0);
```

### 4. Lock and Map the Memory

```c
uint32_t mem_addr = mem_lock(file_desc, handle);
void *mapped_mem = mapmem(mem_addr, 1024);
```

### 5. Unlock and Free Memory

```c
mem_unlock(file_desc, handle);
mem_free(file_desc, handle);
```

### 6. Close the Mailbox

```c
mbox_close(file_desc);
```

## 📖 API Reference

### Mailbox Functions

| Function | Description |
|----------|------------|
| `int mbox_open()` | Opens the mailbox device (`/dev/vcio`). |
| `void mbox_close(int file_desc)` | Closes the mailbox device. |
| `uint32_t get_version(int file_desc)` | Gets the mailbox interface version. |

### Memory Management

| Function | Description |
|----------|------------|
| `uint32_t mem_alloc(int fd, uint32_t size, uint32_t align, uint32_t flags)` | Allocates memory. |
| `uint32_t mem_free(int fd, uint32_t handle)` | Frees allocated memory. |
| `uint32_t mem_lock(int fd, uint32_t handle)` | Locks allocated memory. |
| `uint32_t mem_unlock(int fd, uint32_t handle)` | Unlocks locked memory. |
| `void *mapmem(uint32_t base, uint32_t size)` | Maps physical memory into the process's address space. |
| `void unmapmem(void *addr, uint32_t size)` | Unmaps previously mapped memory. |

## 🔧 Requirements

- Raspberry Pi running **Raspberry Pi OS (Raspbian)**
- Kernel **>= 4.1** (uses `/dev/vcio`)
- **C Compiler** (GCC recommended)

## ⚠️ Notes

- You **must** run programs using this library as **root (sudo)** to access `/dev/mem` for memory mapping.
- Some functions depend on **specific Raspberry Pi GPU firmware versions**.

## 📜 License

This project is released under the **BSD 3-Clause License**, as required by Broadcom’s mailbox implementation. See [LICENSE](LICENSE.md) for details.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a **Pull Request**.

## 📞 Support

If you encounter any issues, open an [Issue](https://github.com/lbussy/Broadcom-Mailbox/issues) or start a discussion.
