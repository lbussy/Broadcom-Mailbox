/**
 * @file mailbox.hpp
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

#ifndef _MAILBOX_HPP
#define _MAILBOX_HPP
#pragma once

// C++ Standard Library
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

// POSIX/system headers
#include <linux/ioctl.h> // for IOCTL_MBOX_PROPERTY

class Mailbox
{
public:
    /**
     * @brief Default-constructs a Mailbox instance.
     *
     * The mailbox device is not opened by the constructor;
     * call open() to open the underlying `/dev/vcio` interface.
     */
    Mailbox();

    /**
     * @brief Destructs the Mailbox instance.
     *
     * Closes the mailbox device if it is currently open, ensuring
     * that resources are released properly.
     */
    ~Mailbox();

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
    void open();

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
    void mbox_close();

    /**
     * @brief Get the underlying mailbox file descriptor.
     *
     * @return The file descriptor obtained via `open()`, or -1 if the mailbox is closed.
     */
    [[nodiscard]] int get_fd() const noexcept { return fd_; }

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
    [[nodiscard]] uint32_t mem_alloc(uint32_t size, uint32_t align);

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
    uint32_t mem_free(uint32_t handle);

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
    [[nodiscard]] std::uintptr_t mem_lock(uint32_t handle);

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
    uint32_t mem_unlock(uint32_t handle);

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
    [[nodiscard]] volatile uint8_t *mapmem(uint32_t base, size_t size);

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
    void unmapmem(volatile uint8_t *addr, size_t size);

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
    [[nodiscard]] static uint32_t discover_peripheral_base();

    /**
     * @brief Convert a bus address into its underlying physical address.
     *
     * This function clears the high-order flag bits (as defined by BUS_FLAG_MASK)
     * from a bus address, yielding the raw physical memory address.
     *
     * @param x The bus address, potentially containing caching/alias flags.
     * @return The physical address with flag bits masked off.
     */
    [[nodiscard]] static constexpr std::uintptr_t
    bus_to_physical(std::uintptr_t x) noexcept
    {
        return x & ~BUS_FLAG_MASK;
    }

    /**
     * @brief Compute the offset of a bus address from the peripheral base.
     *
     * This function subtracts the constant PERIPH_BUS_BASE from the given bus
     * address to obtain the byte offset within the mapped peripheral region.
     *
     * @param x The bus address to offset.
     * @return The offset (in bytes) from the peripheral base address.
     */
    [[nodiscard]] static constexpr std::uintptr_t
    offset_from_base(std::uintptr_t x) noexcept
    {
        return x - PERIPH_BUS_BASE;
    }

    /**
     * @brief Mask of the high bits in a 32-bit bus address that indicate
     *       caching flags.
     */
    static constexpr std::uintptr_t BUS_FLAG_MASK = 0xC0000000ULL;

    /**
     * @brief Base bus address for peripheral registers (to compute offsets
     *       into the mapped window).
     */
    static constexpr std::uintptr_t PERIPH_BUS_BASE = 0x7E000000ULL;

    /**
     * @brief Standard page size (4 KiB) for mailbox allocations.
     */
    static constexpr size_t PAGE_SIZE = 4 * 1024;

    /**
     * @brief Standard block size (4 KiB) for mailbox allocations (same as
     *        PAGE_SIZE).
     */
    static constexpr size_t BLOCK_SIZE = 4 * 1024;

private:
    /**
     * @brief Major device number for the mailbox property interface on newer kernels (>= 4.1).
     */
    static inline constexpr int MAJOR_NUM_A = 249;

    /**
     * @brief Major device number for the mailbox property interface on older kernels.
     */
    static inline constexpr int MAJOR_NUM_B = 100;

    /**
     * @brief IOCTL command code for the mailbox property interface.
     *
     * Builds a read-write IOCTL with major number MAJOR_NUM_B and command 0.
     */
    static inline constexpr int IOCTL_MBOX_PROPERTY = _IOWR(MAJOR_NUM_B, 0, char *);

    /**
     * @brief Path to the mailbox character device.
     *
     * Used by mbox_open() to open `/dev/vcio`.
     */
    static inline constexpr char DEVICE_FILE_NAME[] = "/dev/vcio";

    /**
     * @brief Path to the raw memory device.
     *
     * Used by mapmem() to open `/dev/mem` for physical memory mapping.
     */
    static inline constexpr char MEM_FILE_NAME[] = "/dev/mem";

    /**
     * @brief File descriptor for the opened mailbox device.
     *
     * Initialized to -1 to indicate that the mailbox is not currently open.
     */
    int fd_ = -1;

    /**
     * @brief Determine the mailbox mem_flag based on Pi hardware revision.
     *
     * Reads `/proc/cpuinfo` (cached on first call), extracts the processor ID,
     * and returns 0x0C for BCM2835 (Pi 1) or 0x04 for later models (Pi 2/3/4).
     *
     * @return The mem_flag to pass into mem_alloc().
     * @throws std::runtime_error on an unrecognized chipset.
     */
    [[nodiscard]] uint32_t get_mem_flag();

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
    static std::optional<uint32_t> read_dt_range_helper(const char *path, std::size_t offset);
};

/**
 * @brief Global instance of the Broadcom Mailbox interface shim.
 *
 * Provides a single, shared `Mailbox` object for opening/closing the mailbox,
 * allocating/freeing GPU memory, and mapping/unmapping physical address ranges.
 */
extern Mailbox mailbox;

#endif // _MAILBOX_HPP
