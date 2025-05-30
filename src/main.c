#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "mailbox.h"

/*
 * Flags for mem_alloc; these come from the property‐interface docs
 * (you may already have these defined somewhere in your codebase).
 */
#define MEM_FLAG_DISCARDABLE (1 << 0)
#define MEM_FLAG_NORMAL (0 << 2)
#define MEM_FLAG_DIRECT (1 << 2)
#define MEM_FLAG_COHERENT (2 << 2)
#define MEM_FLAG_L1_NONALLOCATING (1 << 4)

int main(void)
{
    int fd = mbox_open();
    assert(fd >= 0 && "Failed to open mailbox");

    /* Test get_version() */
    uint32_t ver = get_version(fd);
    printf("Mailbox version: 0x%08x\n", ver);
    assert(ver != 0 && "get_version() returned zero");

    /* Test mem_alloc / mem_lock / mem_unlock / mem_free */
    uint32_t handle = mem_alloc(fd, 4096, 4096,
                                MEM_FLAG_DISCARDABLE | MEM_FLAG_L1_NONALLOCATING);
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

    /* Optionally test mapmem() / unmapmem() by mapping a small region
       of /dev/mem. Be sure you have permission (run as root). */
    uint32_t test_phys = 0x3F000000; // e.g. peripheral base on Pi 4
    uint32_t map_size = 4096;
    void *ptr = mapmem(test_phys, map_size);
    printf("Mapped 0x%08x (%u bytes) → %p\n", test_phys, map_size, ptr);
    // Touch the memory lightly (read a word)
    volatile uint32_t val = *((volatile uint32_t *)ptr);
    printf("Read 0x%08x from mapped region\n", val);
    unmapmem(ptr, map_size);

    mbox_close(fd);
    printf("All mailbox tests passed.\n");
    return 0;
}
