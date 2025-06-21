#include "mailbox.hpp" // project header
#include "bcm_model.hpp"

// C++ Standard Library
#include <array>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <optional>
#include <system_error>

// POSIX/system headers
#include <endian.h> // for be32toh()
#include <fcntl.h>
#include <linux/ioctl.h> // for IOCTL_MBOX_PROPERTY
#include <sys/ioctl.h>
#include <sys/mman.h> // for mmap, munmap
#include <unistd.h>

/** New kernel version (>= 4.1) major device number. */
#define MAJOR_NUM_A 249
/** Older kernel version major device number. */
#define MAJOR_NUM_B 100
/** IOCTL command for mailbox property interface. */
#define IOCTL_MBOX_PROPERTY _IOWR(MAJOR_NUM_B, 0, char *)
/** Name of the mailbox device file. */
#define DEVICE_FILE_NAME "/dev/vcio"
/** Name of the memory device file. */
#define MEM_FILE_NAME "/dev/mem"

// TODO: Doxygen
Mailbox mailbox;

// TODO: Doxygen
Mailbox::Mailbox()
{
}

// TODO: Doxygen
Mailbox::~Mailbox()
{
    mbox_close();
}

// TODO: Doxygen
void Mailbox::mbox_open()
{
    if (fd_ >= 0)
        throw std::logic_error("Mailbox is already open");

    int file_desc = ::open(DEVICE_FILE_NAME, O_RDWR);
    if (file_desc < 0)
    {
        int err = errno;
        throw std::system_error(
            err,
            std::generic_category(),
            std::string("Mailbox::mbox_open(): failed to open ") + DEVICE_FILE_NAME);
    }

    fd_ = file_desc;
}

// TODO: Doxygen
void Mailbox::mbox_close()
{
    if (fd_ < 0)
        return;

    if (::close(fd_) < 0)
    {
        int err = errno;
        throw std::system_error(
            err,
            std::generic_category(),
            std::string("Mailbox::mbox_close(): failed to close ") + DEVICE_FILE_NAME);
    }

    fd_ = -1;
}

// TODO: Doxygen
uint32_t Mailbox::mem_alloc(uint32_t size, uint32_t align)
{
    constexpr uint32_t TAG_ALLOC = 0x3000C;  // allocation tag
    constexpr uint32_t END_TAG = 0x00000000; // end-of-tags marker
    uint32_t flags = get_mem_flag();         // determine mem_flag internally

    // Build the property message buffer (9 words total)
    std::array<uint32_t, 9> buf = {
        0,         // [0] total message size (bytes) - to be filled below
        0,         // [1] request code (0 = request)
        TAG_ALLOC, // [2] tag identifier for mem_alloc
        12,        // [3] value buffer size (bytes)
        12,        // [4] value length (bytes)
        size,      // [5] allocation size in bytes
        align,     // [6] memory alignment in bytes
        flags,     // [7] allocation flags
        END_TAG    // [8] end tag
    };
    // Fill in the total message size
    buf[0] = static_cast<uint32_t>(buf.size() * sizeof(uint32_t));

    // Issue the ioctl to /dev/vcio
    if (::ioctl(fd_, IOCTL_MBOX_PROPERTY, buf.data()) < 0)
    {
        int err = errno;
        throw std::system_error(
            err,
            std::generic_category(),
            "Mailbox::mem_alloc(): ioctl failed");
    }

    // On success, the handle is returned in buf[5]
    return buf[5];
}

// TODO: Doxygen
uint32_t Mailbox::mem_free(uint32_t handle)
{
    constexpr uint32_t TAG_FREE = 0x3000F;   // Free tag
    constexpr uint32_t END_TAG = 0x00000000; // End-of-tags marker

    // Build the property message buffer (7 words total)
    std::array<uint32_t, 7> buf = {
        0,        // [0] Total message size (bytes)
        0,        // [1] Request code (0 = request)
        TAG_FREE, // [2] Tag identifier for mem_free
        4,        // [3] Value buffer size (bytes)
        4,        // [4] Value length (bytes)
        handle,   // [5] Handle to free
        END_TAG   // [6] End tag
    };
    // Fill in the total message size
    buf[0] = static_cast<uint32_t>(buf.size() * sizeof(uint32_t));

    // Issue the ioctl to /dev/vcio
    if (::ioctl(fd_, IOCTL_MBOX_PROPERTY, buf.data()) < 0)
    {
        int err = errno;
        throw std::system_error(
            err,
            std::generic_category(),
            "Mailbox::mem_free(): ioctl failed");
    }

    // On success, the result code is returned in buf[5]
    return buf[5];
}

// TODO: Doxygen
std::uintptr_t Mailbox::mem_lock(uint32_t handle)
{
    constexpr uint32_t TAG_LOCK = 0x3000D;   // lock tag
    constexpr uint32_t END_TAG = 0x00000000; // end-of-tags marker

    std::array<uint32_t, 7> buf = {
        0,        // [0] Total message size
        0,        // [1] Request code
        TAG_LOCK, // [2] Tag for mem_lock
        4,        // [3] Buffer size
        4,        // [4] Data size
        handle,   // [5] Handle
        END_TAG   // [6] End tag
    };
    buf[0] = static_cast<uint32_t>(buf.size() * sizeof(uint32_t));

    if (::ioctl(fd_, IOCTL_MBOX_PROPERTY, buf.data()) < 0)
    {
        int err = errno;
        throw std::system_error(
            err,
            std::generic_category(),
            "Mailbox::mem_lock(): ioctl failed");
    }

    return static_cast<std::uintptr_t>(buf[5]);
}

// TODO: Doxygen
uint32_t Mailbox::mem_unlock(uint32_t handle)
{
    // Tag definitions
    constexpr uint32_t TAG_UNLOCK = 0x3000E; // mailbox “unlock” tag
    constexpr uint32_t END_TAG = 0x00000000; // end marker

    // Build the property buffer
    std::array<uint32_t, 7> buf = {
        0,          // [0] Total message size (bytes), will fill in
        0,          // [1] Request (0)
        TAG_UNLOCK, // [2] Tag id
        4,          // [3] Value buffer size
        4,          // [4] Value length
        handle,     // [5] The handle to unlock
        END_TAG     // [6] End tag
    };
    buf[0] = static_cast<uint32_t>(buf.size() * sizeof(uint32_t));

    // Issue the ioctl
    if (::ioctl(fd_, IOCTL_MBOX_PROPERTY, buf.data()) < 0)
    {
        int e = errno;
        throw std::system_error(
            e,
            std::generic_category(),
            "Mailbox::mem_unlock(): ioctl failed");
    }

    // Response value is in buf[5]
    return buf[5];
}

// TODO: Doxygen
volatile uint8_t *Mailbox::mapmem(uint32_t base, size_t size)
{
    // Compute page‐aligned base and offset within page
    const unsigned offset = base % PAGE_SIZE;
    const off_t aligned_base = static_cast<off_t>(base - offset);

    // Open /dev/mem
    int mem_fd = ::open(MEM_FILE_NAME, O_RDWR | O_SYNC);
    if (mem_fd < 0)
    {
        int e = errno;
        throw std::system_error(
            e, std::generic_category(),
            std::string("Mailbox::mapmem(): cannot open ") + MEM_FILE_NAME);
    }

    // mmap the physical region
    void *mapped = ::mmap(
        nullptr,
        size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        mem_fd,
        aligned_base);
    ::close(mem_fd);

    if (mapped == MAP_FAILED)
    {
        int e = errno;
        throw std::system_error(
            e, std::generic_category(),
            "Mailbox::mapmem(): mmap failed");
    }

    // Return pointer adjusted by the page‐offset
    return static_cast<uint8_t *>(mapped) + offset;
}

// TODO: Doxygen
void Mailbox::unmapmem(volatile uint8_t *addr, size_t size)
{
    // Compute the original mapping base by stripping the page‐offset
    auto addr_val = reinterpret_cast<std::uintptr_t>(addr);
    const std::size_t offset = addr_val % PAGE_SIZE;
    void *base = reinterpret_cast<void *>(addr_val - offset);

    // Unmap and throw on failure
    if (::munmap(base, size) != 0)
    {
        int e = errno;
        throw std::system_error(
            e,
            std::generic_category(),
            "Mailbox::unmapmem(): munmap failed");
    }
}

// TODO: Doxygen
uint32_t Mailbox::discover_peripheral_base()
{
    uint32_t base = 0x20000000;
    if (auto v = read_dt_range_helper("/proc/device-tree/soc/ranges", 4); v && *v)
        base = *v;
    else if (auto v = read_dt_range_helper("/proc/device-tree/soc/ranges", 8); v)
        base = *v;
    return base;
}

// TODO: Doxygen
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

// TODO: Doxygen
std::optional<uint32_t> Mailbox::read_dt_range_helper(const char *path, std::size_t offset)
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
