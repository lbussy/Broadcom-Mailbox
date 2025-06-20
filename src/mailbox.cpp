#include "mailbox.hpp" // project header
#include "bcm_model.hpp"

// C++ Standard Library
#include <cstdio>
#include <fstream>
#include <optional>

// POSIX/system headers
#include <endian.h> // for be32toh()
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif
#include "old_mailbox.h" // legacy C API
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
    mbox_close();
}

// Wrapper around C mbox_open()
void Mailbox::mbox_open()
{
    if (fd_ >= 0)
        throw std::runtime_error("Mailbox already open");
    fd_ = ::mbox_open();
    if (fd_ < 0)
        throw std::runtime_error("mbox_open() failed");
    return;
}

// Wrapper around C mbox_close()
void Mailbox::mbox_close()
{
    if (fd_ >= 0)
    {
        ::mbox_close(fd_);
        fd_ = -1;
    }
}

// Wrapper around C mem_alloc()
uint32_t Mailbox::mem_alloc(uint32_t size, uint32_t align)
{
    return ::mem_alloc(fd_, size, align, get_mem_flag());
}

// Wrapper around C mem_free()
uint32_t Mailbox::mem_free(uint32_t handle)
{
    return ::mem_free(fd_, handle);
}

// Wrapper around C mem_lock()
std::uintptr_t Mailbox::mem_lock(uint32_t handle)
{
    // Cast the 32-bit bus address from the C API up to a uintptr_t
    return static_cast<std::uintptr_t>(::mem_lock(fd_, handle));
}

// Wrapper around C mem_unlock()
uint32_t Mailbox::mem_unlock(uint32_t handle)
{
    return ::mem_unlock(fd_, handle);
}

// Wrapper around C mapmem()
volatile uint8_t *Mailbox::mapmem(uint32_t base, size_t size)
{
    // Legacy mapmem takes a 32-bit size
    return ::mapmem(base, static_cast<uint32_t>(size));
}

// Wrapper around C unmapmem()
void Mailbox::unmapmem(volatile uint8_t *addr, uint32_t size)
{
    // Legacy unmapmem takes a 32-bit size
    ::unmapmem(addr, static_cast<uint32_t>(size));
}

static std::optional<uint32_t> read_dt_range_helper(const char *path, std::size_t offset)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;

    f.seekg(offset);
    uint32_t be_val = 0;
    f.read(reinterpret_cast<char *>(&be_val), sizeof(be_val));
    if (!f)
        return std::nullopt;

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

uint32_t Mailbox::get_mem_flag()
{
    static std::optional<unsigned> cached_rev;
    if (!cached_rev)
    {
        std::ifstream f("/proc/cpuinfo");
        unsigned rev = 0;
        if (f)
        {
            std::string line;
            while (std::getline(f, line))
            {
                if (sscanf(line.c_str(), "Revision\t: %x", &rev) == 1)
                {
                    cached_rev = rev;
                    break;
                }
            }
        }
        if (!cached_rev)
            cached_rev = 0;
    }

    unsigned rev = *cached_rev;
    BCMChip proc = (rev & 0x800000)
                       ? static_cast<BCMChip>((rev & 0xF000) >> 12)
                       : BCMChip::BCM_HOST_PROCESSOR_BCM2835;

    switch (proc)
    {
    case BCMChip::BCM_HOST_PROCESSOR_BCM2835:
        return 0x0C;
    case BCMChip::BCM_HOST_PROCESSOR_BCM2836:
    case BCMChip::BCM_HOST_PROCESSOR_BCM2837:
    case BCMChip::BCM_HOST_PROCESSOR_BCM2711:
        return 0x04;
    }
    throw std::runtime_error(
        std::string("Mailbox::get_mem_flag(): unknown chipset ") +
        std::string(to_string(proc)));
}
