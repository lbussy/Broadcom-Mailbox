/**
 * @file mailbox.cpp
 * @brief C++17 `Mailbox` class to interface with the Broadcom GPU mailbox.
 *
 * This project is is licensed under the MIT License. See LICENSE.md
 * for more information.
 *
 * Copyright (C) 2025 Lee C. Bussy (@LBussy). All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mailbox.hpp"
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
#include <sys/ioctl.h>
#include <sys/mman.h> // for mmap, munmap
#include <unistd.h>

/**
 * @brief Global instance of the Broadcom Mailbox interface shim.
 *
 * Provides a single, shared `Mailbox` object for opening/closing the mailbox,
 * allocating/freeing GPU memory, and mapping/unmapping physical address ranges.
 */
Mailbox mailbox;

/**
 * @brief Default-constructs a Mailbox instance.
 *
 * The mailbox device is not opened by the constructor;
 * call open() to open the underlying `/dev/vcio` interface.
 */
Mailbox::Mailbox()
{
}

/**
 * @brief Destructs the Mailbox instance.
 *
 * Closes the mailbox device if it is currently open, ensuring
 * that resources are released properly.
 */
Mailbox::~Mailbox()
{
    mbox_close();
}

/**
 * @brief Opens the mailbox device.
 *
 * Attempts to open the mailbox device file specified by DEVICE_FILE_NAME.
 * If the mailbox is already open, throws a logic_error.
 * On failure to open the file, throws a system_error with the errno
 * and a descriptive message.
 *
 * @throws std::logic_error   If the mailbox is already open.
 * @throws std::system_error  If the underlying open() call fails.
 */
void Mailbox::open()
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
            std::string("Mailbox::open(): failed to open ") + DEVICE_FILE_NAME);
    }

    fd_ = file_desc;
}

/**
 * @brief Closes the mailbox device.
 *
 * If the mailbox file descriptor is valid, attempts to close it.
 * If the underlying close() call fails, throws a system_error with the errno
 * and a descriptive message. After successful close, the internal file
 * descriptor is reset to -1.
 *
 * @throws std::system_error  If the underlying close() call fails.
 */
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

/**
 * @brief Allocate GPU-accessible memory via the mailbox property interface.
 *
 * Constructs and sends a mailbox property message to request a memory allocation
 * of the specified size and alignment, using flags determined by the current
 * Raspberry Pi hardware revision.
 *
 * @param size  Number of bytes to allocate.
 * @param align Alignment constraint in bytes (power-of-two).
 * @return A handle (uint32_t) identifying the allocated memory block.
 * @throws std::system_error if the ioctl to the mailbox device fails.
 */
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

/**
 * @brief Free previously allocated GPU memory via the mailbox property interface.
 *
 * Constructs and sends a mailbox property message to release a memory block
 * identified by the given handle.
 *
 * @param handle Handle returned by a prior call to mem_alloc().
 * @return Result code from the mailbox property response (non-zero indicates success).
 * @throws std::system_error if the ioctl to the mailbox device fails.
 */
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

/**
 * @brief Lock a previously allocated GPU memory block to obtain its bus address.
 *
 * Constructs and sends a mailbox property message to lock a memory block
 * identified by the given handle, returning its bus address for DMA use.
 *
 * @param handle Handle returned by a prior call to mem_alloc().
 * @return Physical (bus) address of the locked memory block.
 * @throws std::system_error if the ioctl to the mailbox device fails.
 */
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

/**
 * @brief Unlock a previously locked GPU memory block.
 *
 * Constructs and sends a mailbox property message to unlock a memory block
 * identified by the given handle, allowing it to be freed or reallocated.
 *
 * @param handle Handle returned by mem_alloc() and previously passed to mem_lock().
 * @return Result code: non-zero indicates success.
 * @throws std::system_error if the ioctl to the mailbox device fails.
 */
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

/**
 * @brief Map a physical bus address range into user-space memory.
 *
 * Opens `/dev/mem`, aligns the requested `base` address to the system page size,
 * and mmaps a region of length `size` bytes. The returned pointer is offset
 * by the original `base % PAGE_SIZE` so that it points directly at the requested
 * bus address.
 *
 * @param base The bus address to map; will be aligned down to a PAGE_SIZE boundary.
 * @param size The number of bytes to map.
 * @return A pointer to the mapped memory region, adjusted by the page offset.
 * @throws std::system_error if opening `/dev/mem` or the mmap operation fails.
 */
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

/**
 * @brief Unmap a previously mapped bus address region.
 *
 * Calculates the original mapping base by removing the page offset
 * from the pointer returned by mapmem(), then calls munmap() to
 * release the mapping.
 *
 * @param addr Pointer returned by mapmem(), adjusted into the mapped region.
 * @param size The number of bytes that were mapped (same size passed to mapmem()).
 * @throws std::system_error if munmap() fails.
 */
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

/**
 * @brief Determine the SoC peripheral base address from the device tree.
 *
 * Reads the 4-byte big-endian values at offsets 4 and 8 in
 * `/proc/device-tree/soc/ranges` to discover the GPU peripheral bus base.
 * If neither entry is present or nonzero, falls back to the legacy
 * address 0x2000'0000.
 *
 * @return The bus-addressable peripheral base to use for mmap offsets.
 */
uint32_t Mailbox::discover_peripheral_base()
{
    uint32_t base = 0x20000000;
    if (auto v = read_dt_range_helper("/proc/device-tree/soc/ranges", 4); v && *v)
        base = *v;
    else if (auto v = read_dt_range_helper("/proc/device-tree/soc/ranges", 8); v)
        base = *v;
    return base;
}

/**
 * @brief Determine the appropriate mailbox memory‐allocation flag for this Pi.
 *
 * Parses `/proc/cpuinfo` (cached on first call) to extract the hardware revision,
 * maps that to a BCM processor ID, and then returns the correct
 * `MEM_FLAG_*` for `mem_alloc()`:
 *   - BCM2835 (RPi1): non‐allocating L1 flag (0x0C)
 *   - BCM2836/37 (RPi2/3) and BCM2711 (RPi4): normal L2 alloc flag (0x04)
 *
 * @return The 32-bit flags value to pass to `mem_alloc()`.
 * @throws std::runtime_error if the parsed processor ID is unrecognized.
 */
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

/**
 * @brief Read a 32-bit big-endian value from a device-tree file at a given offset.
 *
 * Opens the binary file at `path`, seeks to `offset`, and reads four bytes.
 * Converts from big-endian on-disk format to host endianness.
 *
 * @param path   Filesystem path to the device-tree binary file.
 * @param offset Byte offset within the file to read from.
 * @return A `std::optional<uint32_t>` containing the converted value on success,
 *         or `std::nullopt` if the file cannot be opened or the read fails.
 */
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

    // Convert from big-endian on-disk to CPU-endian
    uint32_t val = be32toh(be_val);
    return val;
}
