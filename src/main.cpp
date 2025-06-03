/**
 * @file main.cpp
 * @brief Entry point for either real-hardware mailbox tests or unit-tests with fake hooks.
 *
 * @details
 * When compiled without `ENABLE_MBOX_TEST_HOOKS`, this program exercises the real
 * mailbox interface on a Raspberry Pi:
 *   - Opens `/dev/vcio`
 *   - Queries firmware version
 *   - Allocates, locks, unlocks, and frees GPU memory
 *   - Optionally maps and reads a physical address via `/dev/mem`
 *
 * When compiled with `-DENABLE_MBOX_TEST_HOOKS`, it runs a suite of unit-tests that:
 *   - Install fake hooks for `open()`, `/dev/mem` access, and mailbox IOCTL calls
 *   - Verify that `mbox_open()` returns a dummy FD
 *   - Verify that `get_version()` returns a fake version
 *   - Verify that `mapmem()` fails when the fake `/dev/mem` hook returns an error
 *
 * Use -DENABLE_MBOX_TEST_HOOKS at compile time to enable the fake-hook tests.
 */

#include "mailbox.hpp"

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdint>
#include <system_error>

/**
 * @brief Runs unit-tests under fake-hook mode.
 *
 * @details
 * Installs fake hooks into the Mailbox singleton, then verifies:
 *   - `mbox_open()` returns a dummy file descriptor (100)
 *   - `get_version()` returns the fake GPU firmware version
 *   - `mapmem()` throws a `std::system_error` with `EPERM` when the fake `/dev/mem` hook fails
 *
 * @return 0 on success; non-zero if any assertion fails or an unexpected exception occurs.
 */
int test_main()
{
    // Install fake hooks for all mailbox operations
    mailbox.set_test_hooks();

    // mbox_open() → fake_open() → should return 100
    int fd = mailbox.mbox_open();
    assert(fd == 100 && "fake_open() did not return 100");

    // get_version() → fake_version() → should return 0x00020000
    {
        uint32_t ver = mailbox.get_version(fd);
        std::printf("Fake version: 0x%08x\n", ver);
        assert(ver == 0x00020000 && "fake_version() did not return 0x00020000");
    }

    // Test mapmem() failure: fake_mapmem() should force an EPERM error
    try
    {
        (void)mailbox.mapmem(0x1000, 4096);
        assert(false && "Expected mapmem() to throw under EPERM");
    }
    catch (const std::system_error &e)
    {
        int ec = e.code().value();
        assert(ec == EPERM && "mapmem() threw an unexpected error code");
    }

    // Clean up
    mailbox.mbox_close(fd);
    std::printf("All unit-test hooks passed.\n");
    return 0;
}

/**
 * @brief Exercises the real mailbox interface on actual Raspberry Pi hardware.
 *
 * @details
 *   - Opens `/dev/vcio` via `mbox_open()`
 *   - Queries firmware version via `get_version()`
 *   - Allocates GPU memory (`mem_alloc()`), locks it (`mem_lock()`), unlocks it (`mem_unlock()`),
 *     and frees it (`mem_free()`)
 *   - Maps a known physical address (`mapmem()`), reads a 32-bit value, and then unmaps it
 *
 * @return 0 on success; non-zero if any assertion fails or an unexpected exception occurs.
 */
int real_main()
{
    // Enable debug printing of all words
    mailbox.set_debug();

    // Open the mailbox device
    int fd = mailbox.mbox_open();
    assert(fd >= 0 && "Failed to open mailbox (/dev/vcio)");

    // Query firmware version
    uint32_t ver = mailbox.get_version(fd);
    std::printf("Mailbox version: 0x%08x\n", ver);
    assert(ver != 0 && "get_version() returned zero");

    // Allocate GPU memory: size=4096, alignment=4096, flags=(1<<0)|(1<<4)
    uint32_t handle = mailbox.mem_alloc(
        fd,
        4096,
        4096,
        (1u << 0) | (1u << 4));
    std::printf("Allocated handle: 0x%08x\n", handle);
    assert(handle != 0 && "mem_alloc() failed");

    // Lock the allocated memory to obtain a bus address
    uint32_t bus_addr = mailbox.mem_lock(fd, handle);
    std::printf("Locked, bus address: 0x%08x\n", bus_addr);
    assert(bus_addr != 0 && "mem_lock() failed");

    // Unlock and free the GPU memory
    mailbox.mem_unlock(fd, handle);
    std::printf("Unlocked\n");
    mailbox.mem_free(fd, handle);
    std::printf("Freed\n");

    // Map a well-known physical address (e.g., peripheral base) and read a 32-bit register
    uint32_t test_phys = 0x3F000000; ///< Base of BCM peripheral registers
    size_t map_size = 4096;          ///< Map one page (4KB)
    auto region = mailbox.mapmem(test_phys, map_size);
    void *ptr_real = region ? region.get() : nullptr;
    std::printf("Mapped 0x%08x → %p\n", test_phys, ptr_real);
    if (ptr_real)
    {
        // Read a 32-bit value from the mapped memory
        volatile uint32_t val = *static_cast<volatile uint32_t *>(ptr_real);
        std::printf("Read 0x%08x\n", val);

        // Unmap the region when done
        mailbox.unmapmem(ptr_real, map_size);
    }
    else
    {
        std::printf("mapmem() failed (errno=%d)\n", errno);
    }

    // Close the mailbox device
    mailbox.mbox_close(fd);
    std::printf("All mailbox tests passed.\n");
    return 0;
}

/**
 * @brief Program entry point.
 *
 * @details
 * Depending on whether `ENABLE_MBOX_TEST_HOOKS` is defined at compile time:
 *   - If defined, runs `test_main()`
 *   - Otherwise, runs `real_main()`
 *
 * The return value from the selected function is propagated as the process exit code.
 *
 * @return Exit code from either `test_main()` or `real_main()`.
 */
int main()
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return test_main();
#else
    return real_main();
#endif // ENABLE_MBOX_TEST_HOOKS
}
