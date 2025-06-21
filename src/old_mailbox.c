/*
 * References:
 * - https://github.com/raspberrypi/firmware/wiki/Mailboxes
 * - https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
 * - https://bitbanged.com/posts/understanding-rpi/the-mailbox/
 * - http://www.freenos.org/doxygen/classBroadcomMailbox.html
 */

#include "old_mailbox.h" // project header

// C Standard Library
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// POSIX/system headers
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE (4 * 1024)

/**
 * @brief Maps physical memory into the process's address space.
 *
 * @param base Physical base address to map.
 * @param size Size of the memory region to map.
 * @return Pointer to the mapped memory, or exits on failure.
 */
volatile uint8_t *mapmem(uint32_t base, uint32_t size)
{
    int mem_fd;
    unsigned offset = base % PAGE_SIZE;
    base -= offset;

    if ((mem_fd = open(MEM_FILE_NAME, O_RDWR | O_SYNC)) < 0)
    {
        fprintf(stderr,
                "Error: Cannot open %s. Run as root or use sudo.\n",
                MEM_FILE_NAME);
        exit(EXIT_FAILURE);
    }

    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, base);
    close(mem_fd);

    if (mem == MAP_FAILED)
    {
        perror("Error: mmap failed");
        exit(EXIT_FAILURE);
    }

    return (uint8_t *)mem + offset;
}

/**
 * @brief Unmaps previously mapped memory.
 *
 * @param addr Pointer to the mapped memory.
 * @param size Size of the memory region to unmap.
 */
void unmapmem(volatile uint8_t *addr, uint32_t size)
{
    // Recover the numeric pointer and compute the offset
    uintptr_t addr_val = (uintptr_t)addr;
    unsigned offset = addr_val % PAGE_SIZE;

    // Subtract offset to get the original mapping address
    void *raw = (void *)(addr_val - offset);

    // Cast away volatile *only* here and unmap
    if (munmap(raw, size) != 0)
    {
        perror("Error: munmap failed");
        exit(EXIT_FAILURE);
    }
}
