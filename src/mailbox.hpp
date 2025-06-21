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

    // TODO: Doxygen
    [[nodiscard]] uint32_t mem_alloc(uint32_t size, uint32_t align);

    // TODO: Doxygen
    uint32_t mem_free(uint32_t handle);

    // TODO: Doxygen
    [[nodiscard]] std::uintptr_t mem_lock(uint32_t handle);

    // TODO: Doxygen
    uint32_t mem_unlock(uint32_t handle);

    // TODO: Doxygen
    [[nodiscard]] volatile uint8_t *mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmap physical memory (maps to unmapmem()).
     * @param addr Pointer returned by mapmem().
     * @param size Length of the region to unmap, in bytes.
     */
    void unmapmem(volatile uint8_t *addr, size_t size);

    // TODO: Doxygen
    [[nodiscard]] static uint32_t discover_peripheral_base();

    // TODO: Doxygen
    [[nodiscard]] static constexpr std::uintptr_t
    bus_to_physical(std::uintptr_t x) noexcept
    {
        return x & ~BUS_FLAG_MASK;
    }

    // TODO: Doxygen
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
