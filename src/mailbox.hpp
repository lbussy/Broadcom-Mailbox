#ifndef _MAILBOX_HPP
#define _MAILBOX_HPP
#pragma once

// C++ Standard Library
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

class Mailbox
{
public:
    // TODO: Doxygen
    Mailbox();

    // TODO: Doxygen
    ~Mailbox();

    // TODO: Doxygen
    void mbox_open();

    // TODO: Doxygen
    void mbox_close();

    // TODO: Doxygen
    [[nodiscard]] int get_fd() const noexcept { return fd_; }

    /**
     * @brief Allocate memory via mailbox (maps to mem_alloc()).
     * @param size  Number of bytes to allocate.
     * @param align Alignment in bytes.
     * @return Handle to allocated memory.
     */
    [[nodiscard]] uint32_t mem_alloc(uint32_t size, uint32_t align);

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
    [[nodiscard]] std::uintptr_t mem_lock(uint32_t handle);

    /**
     * @brief Unlock memory via mailbox (maps to mem_unlock()).
     * @param handle Handle returned by mem_alloc().
     * @return Result code (non-zero on success).
     */
    uint32_t mem_unlock(uint32_t handle);

    /**
     * @brief Map physical memory (maps to mapmem()).
     * @param base Physical base address.
     * @param size Length of region to map, in bytes.
     * @return Pointer to mapped region.
     */
    [[nodiscard]] volatile uint8_t *mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmap physical memory (maps to unmapmem()).
     * @param addr Pointer returned by mapmem().
     * @param size Length of the region to unmap, in bytes.
     */
    void unmapmem(volatile uint8_t *addr, size_t size);

    /**
     * @brief Determine the SoC peripheral base address from the device tree.
     * Reads `/proc/device-tree/soc/ranges` at offsets 4 and 8. Falls back to 0x20000000.
     * @return Bus address for mmap offset.
     */
    [[nodiscard]] static uint32_t discover_peripheral_base();

    /**
     * @brief Clear the bus caching flags from a bus address.
     * @param x Raw bus address with flags.
     * @return Physical address.
     */
    [[nodiscard]] static constexpr std::uintptr_t
    bus_to_physical(std::uintptr_t x) noexcept
    {
        return x & ~BUS_FLAG_MASK;
    }

    /**
     * @brief Compute the offset into the peripheral mapping.
     * @param x Raw bus address.
     * @return Offset from the mapped base.
     */
    [[nodiscard]] static constexpr std::uintptr_t
    offset_from_base(std::uintptr_t x) noexcept
    {
        return x - PERIPH_BUS_BASE;
    }

    /**
     * @brief Mask of the high bits in a 32-bit bus address that indicate caching flags.
     */
    static constexpr std::uintptr_t BUS_FLAG_MASK = 0xC0000000ULL;

    /**
     * @brief Base bus address for peripheral registers (to compute offsets into the mapped window).
     */
    static constexpr std::uintptr_t PERIPH_BUS_BASE = 0x7E000000ULL;

    /**
     * @brief Standard page size (4 KiB) for mailbox allocations.
     */
    static constexpr size_t PAGE_SIZE = 4 * 1024;

    /**
     * @brief Standard block size (4 KiB) for mailbox allocations (same as PAGE_SIZE).
     */
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
    [[nodiscard]] uint32_t get_mem_flag();

    // TODO: Doxygen
    static std::optional<uint32_t> read_dt_range_helper(const char *path, std::size_t offset);
};

extern Mailbox mailbox;

#endif // _MAILBOX_HPP
