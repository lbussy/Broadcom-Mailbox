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

/*
 * use ioctl to send mbox property message
 */

static int mbox_property(int file_desc, void *buf)
{
    int ret_val = ioctl(file_desc, IOCTL_MBOX_PROPERTY, buf);

    if (ret_val < 0)
    {
        // something wrong somewhere, send some details to stderr
        perror("ioctl_set_msg failed");
    }

#ifdef DEBUG
    unsigned *p = buf;
    int i;
    unsigned size = *(unsigned *)buf;
    for (i = 0; i < size / 4; i++)
        printf("%04zx: 0x%08x\n", i * sizeof *p, p[i]); // Use %zx for size_t
#endif
    return ret_val;
}

unsigned mem_alloc(int file_desc, unsigned size, unsigned align, unsigned flags)
{
    int i = 0;
    unsigned p[32];
    p[i++] = 0;          // size
    p[i++] = 0x00000000; // process request

    p[i++] = 0x3000c; // (the tag id)
    p[i++] = 12;      // (size of the buffer)
    p[i++] = 12;      // (size of the data)
    p[i++] = size;    // (num bytes? or pages?)
    p[i++] = align;   // (alignment)
    p[i++] = flags;   // (MEM_FLAG_L1_NONALLOCATING)

    p[i++] = 0x00000000;  // end tag
    p[0] = i * sizeof *p; // actual size

    if (mbox_property(file_desc, p) < 0)
    {
        printf("mem_alloc: mbox_property() error, abort!\n");
        exit(-1);
    }
    return p[5];
}

unsigned mem_free(int file_desc, unsigned handle)
{
    int i = 0;
    unsigned p[32];
    p[i++] = 0;          // size
    p[i++] = 0x00000000; // process request

    p[i++] = 0x3000f; // (the tag id)
    p[i++] = 4;       // (size of the buffer)
    p[i++] = 4;       // (size of the data)
    p[i++] = handle;

    p[i++] = 0x00000000;  // end tag
    p[0] = i * sizeof *p; // actual size

    if (mbox_property(file_desc, p) < 0)
    {
        printf("mem_free: mbox_property() error, ignoring\n");
        return 0;
    }
    return p[5];
}

/**
 * @brief Locks memory using the mailbox interface.
 *
 * @param file_desc File descriptor for the mailbox.
 * @param handle Handle to the memory to lock.
 * @return Memory lock handle, or exits on error.
 */
unsigned mem_lock(int file_desc, unsigned handle)
{
    unsigned p[32];
    unsigned i = 0;

    p[i++] = 0;          // Size
    p[i++] = 0x00000000; // Process request
    p[i++] = 0x3000d;    // Tag ID
    p[i++] = 4;          // Size of the buffer
    p[i++] = 4;          // Size of the data
    p[i++] = handle;
    p[i++] = 0x00000000; // End tag
    p[0] = i * sizeof(*p);

    if (mbox_property(file_desc, p) < 0)
    {
        fprintf(stderr, "Error: mem_lock failed, aborting.\n");
        exit(EXIT_FAILURE);
    }

    return p[5];
}

/**
 * @brief Unlocks memory using the mailbox interface.
 *
 * @param file_desc File descriptor for the mailbox.
 * @param handle Handle to the memory to unlock.
 * @return 0 on success, or exits on error.
 */
unsigned mem_unlock(int file_desc, unsigned handle)
{
    unsigned p[32];
    unsigned i = 0;

    p[i++] = 0;          // Size
    p[i++] = 0x00000000; // Process request
    p[i++] = 0x3000e;    // Tag ID
    p[i++] = 4;          // Size of the buffer
    p[i++] = 4;          // Size of the data
    p[i++] = handle;
    p[i++] = 0x00000000; // End tag
    p[0] = i * sizeof(*p);

    if (mbox_property(file_desc, p) < 0)
    {
        fprintf(stderr, "Error: mem_unlock failed.\n");
        return 0;
    }

    return p[5];
}

/**
 * @brief Opens the mailbox device for communication.
 *
 * @return File descriptor for the opened mailbox device, or exits on failure.
 */
// int mbox_open()
// {
//     int file_desc = open(DEVICE_FILE_NAME, O_RDWR);
//     if (file_desc < 0)
//     {
//         perror("Error: Unable to open mailbox device");
//         exit(EXIT_FAILURE);
//     }
//     return file_desc;
// }

/**
 * @brief Closes the mailbox device.
 *
 * @param file_desc File descriptor for the mailbox to close.
 */
// void mbox_close(int file_desc)
// {
//     close(file_desc);
// }
