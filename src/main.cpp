/**
 * @file main.cpp
 * @brief Entry point for either real‐hardware mailbox tests or unit‐tests with fake hooks.
 *
 * @details
 * When compiled without `ENABLE_MBOX_TEST_HOOKS`, this program exercises the real
 * mailbox interface on a Raspberry Pi:
 *   - Opens `/dev/vcio`
 *   - Queries firmware version
 *   - Allocates, locks, unlocks, and frees GPU memory
 *   - Optionally maps and reads a physical address via `/dev/mem`
 *
 * When compiled with `-DENABLE_MBOX_TEST_HOOKS`, it runs a suite of unit‐tests that:
 *   - Install fake hooks for `open()`, `/dev/mem` access, and mailbox ioctl calls
 *   - Verify that `mbox_open()` returns a dummy FD
 *   - Verify that `get_version()` returns a fake version and properly handles errors
 *   - Verify that `mapmem()` fails when the fake `/dev/mem` hook returns an error
 *
 * Use -DENABLE_MBOX_TEST_HOOKS at compile time to enable the fake‐hook tests.
 */

#include "mailbox.hpp"

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdint>
#include <system_error>

#ifdef ENABLE_MBOX_TEST_HOOKS

static int fake_open(const char * /*path*/, int /*flags*/)
{
    return 100;
}

static int fake_close(int /*fd*/)
{
    return 0;
}

static int fake_get_mem_fd_succeed(void)
{
    return 200;
}

static int fake_get_mem_fd_fail(void)
{
    errno = EPERM;
    return -1;
}

static int fake_property_version(int /*fd*/, void *buf)
{
    auto msg = static_cast<uint32_t *>(buf);
    if (msg[2] == static_cast<uint32_t>(MailboxTags::Tag::GetFirmwareVersion))
    {
        msg[5] = 0x00020000;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

int main()
{
    // 2) Install fakes
    mailbox_set_open_hook(fake_open);
    mailbox_set_close_hook(fake_close);
    mailbox_set_mem_fd_hook(fake_get_mem_fd_succeed);
    mailbox_set_property_hook(fake_property_version);

    // 3) mbox_open() → fake_open() → returns 100
    int fd = mbox_open();
    assert(fd == 100);

    // 4) get_version() → fake_property_version() → returns 0x00020000
    {
        uint32_t ver = get_version(fd);
        std::printf("Fake version: 0x%08x\n", ver);
        assert(ver == 0x00020000);
    }

    // 5) Simulate get_version() error path: restore “real” ioctl hook → should now throw
    mailbox_set_property_hook(nullptr);
    try
    {
        (void)get_version(fd);
        assert(false && "Expected get_version(...) to throw");
    }
    catch (const std::system_error &e)
    {
        int ec = e.code().value();
        // Real ioctl on FD=100 will fail with EBADF (or EIO); either is acceptable:
        assert(ec == EBADF || ec == EIO);
    }

    // 6) Test mapmem() failure by forcing get_mem_fd() to fail
    mailbox_set_mem_fd_hook(fake_get_mem_fd_fail);
    try
    {
        (void)mapmem(0x1000, 4096);
        assert(false && "Expected mapmem() to throw under EPERM");
    }
    catch (const std::system_error &e)
    {
        assert(e.code().value() == EPERM);
    }

    // 7) Clean up
    mbox_close(fd);
    std::printf("All unit‐test hooks passed.\n");
    return 0;
}

#else // ENABLE_MBOX_TEST_HOOKS

int main()
{
    int fd = mbox_open();
    assert(fd >= 0 && "Failed to open mailbox");

    uint32_t ver = get_version(fd);
    std::printf("Mailbox version: 0x%08x\n", ver);
    assert(ver != 0 && "get_version() returned zero");

    uint32_t handle = mem_alloc(fd,
                                4096,
                                4096,
                                (1u << 0) | (1u << 4));
    std::printf("Allocated handle: 0x%08x\n", handle);
    assert(handle != 0 && "mem_alloc() failed");

    uint32_t bus_addr = mem_lock(fd, handle);
    std::printf("Locked, bus address: 0x%08x\n", bus_addr);
    assert(bus_addr != 0 && "mem_lock() failed");

    mem_unlock(fd, handle);
    std::printf("Unlocked\n");

    mem_free(fd, handle);
    std::printf("Freed\n");

    uint32_t test_phys = 0x3F000000;
    size_t map_size = 4096;
    void *ptr_real = mapmem(test_phys, map_size);
    std::printf("Mapped 0x%08x → %p\n", test_phys, ptr_real);
    if (ptr_real)
    {
        volatile uint32_t val = *static_cast<volatile uint32_t *>(ptr_real);
        std::printf("Read 0x%08x\n", val);
        unmapmem(ptr_real, map_size);
    }
    else
    {
        std::printf("mapmem() failed (errno=%d)\n", errno);
    }

    mbox_close(fd);
    std::printf("All mailbox tests passed.\n");
    return 0;
}

#endif // ENABLE_MBOX_TEST_HOOKS
