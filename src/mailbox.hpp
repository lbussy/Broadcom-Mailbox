#ifndef _MAILBOX_HPP
#define _MAILBOX_HPP
#pragma once

// C++ Standard Library
#include <cstdint>
#include <stdexcept>
#include <vector>

/**
 * @brief C++ wrapper around the legacy mailbox C interface.
 *
 * Encapsulates open/close and memory operations behind RAII,
 * and provides utility to discover peripheral base address.
 */
class Mailbox
{
public:
    /**
     * @brief Default-construct and open the mailbox device.
     * @throws std::runtime_error on failure.
     */
    Mailbox();

    /**
     * @brief Close the mailbox device on destruction.
     */
    ~Mailbox();

    /**
     * @brief Open the mailbox device (maps to mbox_open()).
     * @throws std::runtime_error on failure.
     */
    void mbox_open();

    /**
     * @brief Close the mailbox device (maps to mbox_close()).
     */
    void mbox_close();

    /**
     * @brief Returns the underlying mailbox file descriptor.
     * @return File descriptor, or -1 if closed.
     */
    int get_fd() const noexcept { return fd_; }

    /**
     * @brief Allocate memory via mailbox (maps to mem_alloc()).
     * @param size  Number of bytes to allocate.
     * @param align Alignment in bytes.
     * @return Handle to allocated memory.
     */
    uint32_t mem_alloc(uint32_t size, uint32_t align);

    /**
     * @brief Free memory via mailbox (maps to mem_free()).
     * @param handle Handle returned by mem_alloc().
     * @return Result code (non-zero on success).
     */
    uint32_t mem_free(uint32_t handle);

    /**
     * @brief Lock memory via mailbox (maps to mem_lock()).
     * @param handle Handle returned by mem_alloc().
     * @return Bus address of locked memory.
     */
    uint32_t mem_lock(uint32_t handle);

    /**
     * @brief Unlock memory via mailbox (maps to mem_unlock()).
     * @param handle Handle returned by mem_alloc().
     * @return Result code (non-zero on success).
     */
    uint32_t mem_unlock(uint32_t handle);

    /**
     * @brief Map physical memory (maps to mapmem()).
     * @param base Physical base address.
     * @param size Size of region in bytes.
     * @return Pointer to mapped region.
     */
    volatile uint8_t *mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmap physical memory (maps to unmapmem()).
     * @param addr Pointer returned by mapmem().
     * @param size Size of the mapped region.
     */
    void unmapmem(volatile uint8_t *addr, uint32_t size);

    /**
     * @brief Determine the SoC peripheral base address from the device tree.
     * Reads `/proc/device-tree/soc/ranges` at offsets 4 and 8. Falls back to 0x20000000.
     * @return Bus address for mmap offset.
     */
    static uint32_t discover_peripheral_base();

    /// Mask of the high bits in a 32-bit bus address that indicate caching flags.
    static constexpr std::uintptr_t BUS_FLAG_MASK = 0xC0000000ULL;
    /// Base bus address for peripheral registers (to compute offsets into the mapped window).
    static constexpr std::uintptr_t PERIPH_BUS_BASE = 0x7E000000ULL;

    /// Standard page size (4 KiB) for mailbox allocations.
    static constexpr size_t PAGE_SIZE  = 4 * 1024;
    /// Standard block size (4 KiB) for mailbox allocations (same as PAGE_SIZE).
    static constexpr size_t BLOCK_SIZE = 4 * 1024;

private:
    int fd_ = -1; ///< mailbox file descriptor, -1 if closed

    /**
     * @brief Determine the mailbox mem_flag based on Pi hardware revision.
     *
     * Reads `/proc/cpuinfo` (cached on first call), extracts the processor ID,
     * and returns 0x0C for BCM2835 (Pi 1) or 0x04 for later models (Pi 2/3/4).
     *
     * @return The mem_flag to pass into mem_alloc().
     * @throws std::runtime_error on an unrecognized chipset.
     */
    uint32_t get_mem_flag();
};

extern Mailbox mailbox;

#endif // _MAILBOX_HPP
