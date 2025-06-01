/**
 * @file main.c
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

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include "mailbox.h"

#ifdef ENABLE_MBOX_TEST_HOOKS

/*-----------------------------------------
 * 1) Fake implementations for unit tests
 *-----------------------------------------*/

/**
 * @brief Fake open(): always return a dummy FD (100).
 */
static int fake_open(const char *path, int flags)
{
    (void)path;
    (void)flags;
    return 100;
}

/**
 * @brief Fake get_mem_fd(): succeed path (return 200).
 */
static int fake_get_mem_fd_succeed(void)
{
    return 200;
}

/**
 * @brief Fake get_mem_fd(): fail path (errno=EPERM).
 */
static int fake_get_mem_fd_fail(void)
{
    errno = EPERM;
    return -1;
}

/**
 * @brief Fake property that only handles GET_FIRMWARE_VERSION.
 *
 * If `msg[2] == TAG_GET_FIRMWARE_VERSION`, writes 0x00020000 to msg[5].
 * Otherwise returns EINVAL.
 */
static int fake_property_version(int fd, void *buf)
{
    (void)fd;
    uint32_t *msg = buf;
    if (msg[2] == TAG_GET_FIRMWARE_VERSION)
    {
        msg[5] = 0x00020000; /* fake version */
        return 0;
    }
    errno = EINVAL;
    return -1;
}

#endif // ENABLE_MBOX_TEST_HOOKS

int main(void)
{
#ifdef ENABLE_MBOX_TEST_HOOKS

    /*-----------------------------------------
     * 2) Install fakes
     *-----------------------------------------*/
    mailbox_set_open_hook(fake_open);
    mailbox_set_mem_fd_hook(fake_get_mem_fd_succeed);
    mailbox_set_property_hook(fake_property_version);

    /*-----------------------------------------
     * 3) mbox_open() calls fake_open(), returns 100
     *-----------------------------------------*/
    int fd = mbox_open();
    assert(fd == 100);

    /*-----------------------------------------
     * 4) get_version() calls fake_property_version()
     *-----------------------------------------*/
    uint32_t ver = get_version(fd);
    printf("Fake version: 0x%08x\n", ver);
    assert(ver == 0x00020000);

    /*-----------------------------------------
     * 5) Simulate get_version() error path:
     *    Revert to real property_impl → error
     *-----------------------------------------*/
    mailbox_set_property_hook(NULL); /* restore real_mbox_property */
    errno = 0;
    ver = get_version(fd);
    assert(ver == 0 && errno == EIO);

    /*-----------------------------------------
     * 6) Test mapmem() failure by forcing get_mem_fd() to fail
     *-----------------------------------------*/
    mailbox_set_mem_fd_hook(fake_get_mem_fd_fail);
    void *ptr = mapmem(0x1000, 4096);
    assert(ptr == NULL && errno == EPERM);

    /*-----------------------------------------
     * 7) Clean up
     *-----------------------------------------*/
    mbox_close(fd);
    printf("All unit‐test hooks passed.\n");
    return 0;

#else

    /* “Real‐hardware” test path (identical to your existing main.c) */
    int fd = mbox_open();
    assert(fd >= 0 && "Failed to open mailbox");

    uint32_t ver = get_version(fd);
    printf("Mailbox version: 0x%08x\n", ver);
    assert(ver != 0 && "get_version() returned zero");

    /* Test mem_alloc / mem_lock / mem_unlock / mem_free */
    uint32_t handle = mem_alloc(fd, 4096, 4096,
                                (1 << 0) | (1 << 4)); /* MEM_FLAG_DISCARDABLE|MEM_FLAG_L1_NONALLOCATING */
    printf("Allocated handle: 0x%08x\n", handle);
    assert(handle != 0 && "mem_alloc() failed");

    uint32_t bus_addr = mem_lock(fd, handle);
    printf("Locked, bus address: 0x%08x\n", bus_addr);
    assert(bus_addr != 0 && "mem_lock() failed");

    int unlock_result = mem_unlock(fd, handle);
    printf("Unlocked result: %d\n", unlock_result);
    assert(unlock_result == 0 && "mem_unlock() failed");

    uint32_t free_result = mem_free(fd, handle);
    printf("Freed result: %u\n", free_result);
    assert(free_result == 0 && "mem_free() failed");

    /* Optionally test mapmem() / unmapmem() by mapping a region of /dev/mem */
    uint32_t test_phys = 0x3F000000; /* e.g. peripheral base on Pi 4 */
    uint32_t map_size = 4096;
    void *ptr_real = mapmem(test_phys, map_size);
    printf("Mapped 0x%08x (%u bytes) → %p\n", test_phys, map_size, ptr_real);
    volatile uint32_t val = ptr_real ? *((volatile uint32_t *)ptr_real) : 0;
    printf("Read 0x%08x from mapped region\n", val);
    if (ptr_real)
    {
        unmapmem(ptr_real, map_size);
    }

    mbox_close(fd);
    printf("All mailbox tests passed.\n");
    return 0;

#endif // ENABLE_MBOX_TEST_HOOKS
}
