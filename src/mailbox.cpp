#include "mailbox.hpp"      // project header

// C++ Standard Library
#include <cstdio>
#include <fstream>
#include <optional>

// POSIX/system headers
#include <endian.h>         // for be32toh()
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "old_mailbox.h"    // legacy C API
#ifdef __cplusplus
}
#endif

Mailbox mailbox;

// Constructor: open on creation
Mailbox::Mailbox()
{
}

// Destructor: close on destruction
Mailbox::~Mailbox()
{
    mbox_close(fd_);
}

// Wrapper around C mbox_open()
int Mailbox::mbox_open()
{
    if (fd_ >= 0)
        throw std::runtime_error("Mailbox already open");
    fd_ = ::mbox_open();
    if (fd_ < 0)
        throw std::runtime_error("mbox_open() failed");
    return fd_;
}

// Wrapper around C mbox_close()
void Mailbox::mbox_close(int fd)
{
    if (fd_ >= 0)
    {
        ::mbox_close(fd_);
        fd_ = -1;
    }
}

// Wrapper around C mem_alloc()
uint32_t Mailbox::mem_alloc(int fd, uint32_t size, uint32_t align, uint32_t flags)
{
    return ::mem_alloc(fd_, size, align, flags);
}

// Wrapper around C mem_free()
uint32_t Mailbox::mem_free(int fd, uint32_t handle)
{
    return ::mem_free(fd_, handle);
}

// Wrapper around C mem_lock()
uint32_t Mailbox::mem_lock(int fd, uint32_t handle)
{
    return ::mem_lock(fd_, handle);
}

// Wrapper around C mem_unlock()
uint32_t Mailbox::mem_unlock(int fd, uint32_t handle)
{
    return ::mem_unlock(fd_, handle);
}

// Wrapper around C mapmem()
volatile uint8_t *Mailbox::mapmem(uint32_t base, uint32_t size)
{
    return ::mapmem(base, size);
}

// Wrapper around C unmapmem()
void Mailbox::unmapmem(volatile uint8_t *addr, uint32_t size)
{
    ::unmapmem(addr, size);
}

static std::optional<uint32_t> read_dt_range_helper(const char* path, std::size_t offset)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;

    f.seekg(offset);
    uint32_t be_val = 0;
    f.read(reinterpret_cast<char*>(&be_val), sizeof(be_val));
    if (!f) return std::nullopt;

    // convert from big-endian on-disk to CPU-endian
    uint32_t val = be32toh(be_val);
    return val;
}

// Implementation of discover_peripheral_base()
uint32_t Mailbox::discover_peripheral_base()
{
    uint32_t base = 0x20000000;
    if (auto v = read_dt_range_helper("/proc/device-tree/soc/ranges", 4); v && *v)
        base = *v;
    else if (auto v = read_dt_range_helper("/proc/device-tree/soc/ranges", 8); v)
        base = *v;
    return base;
}
