/**
 * @file mailbox.c
 * @brief Implementation of mailbox-based communication for the Raspberry Pi.
 *
 * Copyright (c) 2012, Broadcom Europe Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  - Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * References:
 * - https://github.com/raspberrypi/firmware/wiki/Mailboxes
 * - https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
 * - https://bitbanged.com/posts/understanding-rpi/the-mailbox/
 * - http://www.freenos.org/doxygen/classBroadcomMailbox.html
 */

#include "mailbox.h" /* our prototypes + stdint.h */

#include <errno.h>
#include <fcntl.h>  /* open, O_RDWR, O_SYNC */
#include <stdint.h> /* for uintptr_t */
#include <stdlib.h>
#include <sys/ioctl.h> /* ioctl */
#include <sys/mman.h>  /* mmap, munmap, MAP_SHARED, PROT_* */
#include <unistd.h>    /* close, sysconf */

#ifdef ENABLE_TIMEOUTS
#include <signal.h>
#include <setjmp.h>
#endif

#ifdef DEBUG_MAILBOX
#include <stdio.h>
#endif

/* Mailbox property‐interface tag IDs */
enum
{
    TAG_GET_FIRMWARE_VERSION = 0x00000001,
    TAG_ALLOCATE_MEMORY = 0x3000c,
    TAG_LOCK_MEMORY = 0x3000d,
    TAG_UNLOCK_MEMORY = 0x3000e,
    TAG_RELEASE_MEMORY = 0x3000f,
};

/**
 * @brief IOCTL command code for the mailbox property interface.
 *
 * Uses magic number 100 and command number 0 to send property-interface
 * messages to the VideoCore GPU via the `/dev/vcio` driver.
 */
#define IOCTL_MBOX_PROPERTY _IOWR(100, 0, char *)

/**
 * @brief Returns a cached file descriptor for /dev/mem, opening it on first call.
 *
 * On the first successful open, registers mem_cleanup() with atexit().
 *
 * @return Non-negative fd on success; -1 on error (errno set by open()).
 */
static int get_mem_fd(void)
{
    static int mem_fd = -1;
    if (mem_fd < 0)
    {
        mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (mem_fd >= 0)
        {
            atexit(mem_cleanup);
        }
    }
    return mem_fd;
}

/**
 * @brief Explicitly cleans up the /dev/mem file descriptor.
 *
 * Registered via atexit(), so it will be called automatically
 * on program exit.
 */
void mem_cleanup(void)
{
    int fd = get_mem_fd();
    if (fd >= 0)
    {
        close(fd);
    }
}

/**
 * @brief Sends a mailbox property interface message.
 *
 * Forwards the property buffer `buf` to the GPU via the mailbox ioctl command.
 * On failure, returns -1 and leaves errno set by the ioctl call.
 * In debug builds (`DEBUG_MAILBOX`), dumps the raw 32-bit words of the
 * response buffer to stdout.
 *
 * @param file_desc  File descriptor returned by `mbox_open()`. Must be >= 0.
 * @param buf        Pointer to the mailbox property message buffer. Must be non-NULL.
 * @return The return value from the ioctl call (>=0), or -1 on error (errno set).
 */
static int mbox_property(int file_desc, void *buf)
{
    if (buf == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    int ret_val = ioctl(file_desc, IOCTL_MBOX_PROPERTY, buf);

#ifdef DEBUG_MAILBOX
    uint32_t *p = buf;
    size_t words = *(uint32_t *)buf / sizeof(uint32_t);
    for (size_t i = 0; i < words; i++)
        printf("%04zx: 0x%08x\n", i * sizeof *p, p[i]);
#endif

    return (ret_val < 0) ? -1 : ret_val;
}

#ifdef ENABLE_TIMEOUTS

/**
 * @brief Jump buffer for mailbox ioctl timeout handling.
 *
 * Used by sigsetjmp()/siglongjmp() to escape a hanging ioctl after the alarm fires.
 */
static sigjmp_buf jmpbuf;

/**
 * @brief Signal handler for the SIGALRM timeout.
 *
 * Invoked when the alarm set in mbox_property_with_timeout() expires.
 * Jumps back to the checkpoint in mbox_property_with_timeout() via siglongjmp().
 *
 * @param sig The signal number (should be SIGALRM).
 */
static void timeout_handler(int sig)
{
    (void)sig; // unused, but required signature
    siglongjmp(jmpbuf, 1);
}

/**
 * @brief Performs a mailbox-property ioctl with a one-second timeout.
 *
 * Installs an alarm handler for SIGALRM, sets a one-second timer, and then
 * performs the ioctl.  If the ioctl hangs past the timeout, the SIGALRM handler
 * will longjmp back, causing this function to return -1 with errno set to ETIMEDOUT.
 * On success or any non-timeout error, the alarm is canceled.
 *
 * @param fd  File descriptor for /dev/vcio (from mbox_open()).
 * @param buf Pointer to the mailbox message buffer.
 * @return The ioctl return value (>=0) on success;
 *         -1 on error or timeout (errno=ETIMEDOUT if timed out, or set by ioctl()).
 */
static int __attribute__((unused)) mbox_property_with_timeout(int fd, void *buf)
{
    struct sigaction sa = {
        .sa_handler = timeout_handler,
        .sa_flags = 0};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);

    /* Set a checkpoint; siglongjmp to here on timeout */
    if (sigsetjmp(jmpbuf, 1) != 0)
    {
        errno = ETIMEDOUT;
        return -1;
    }

    /* Arm the one-second timer */
    alarm(1);

    /* Perform the actual ioctl */
    int ret = ioctl(fd, IOCTL_MBOX_PROPERTY, buf);

    /* Cancel the timer */
    alarm(0);

    return ret;
}

#endif // ENABLE_TIMEOUTS

/**
 * @brief Returns the system page size, cached after first lookup.
 *
 * Queries sysconf(_SC_PAGESIZE) on the first call, falls back to 4096 if it fails,
 * and reuses that value on all subsequent calls to avoid extra syscalls.
 *
 * @return The page size in bytes.
 */
static size_t get_page_size(void)
{
    static size_t page = 0;
    if (page == 0)
    {
        long tmp = sysconf(_SC_PAGESIZE);
        if (tmp < 0)
        {
            /* sysconf failed—fall back and set errno for caller */
            page = 4096;
            errno = (errno == 0 ? EINVAL : errno);
        }
        else
        {
            page = (size_t)tmp;
        }
    }
    return page;
}

/**
 * @brief Opens the mailbox device for communication.
 *
 * Attempts to open the `/dev/vcio` character device.
 * On success, returns a non-negative file descriptor.
 * On failure, returns -1 and leaves errno set by open().
 *
 * @return File descriptor (>=0) on success; -1 on error.
 */
int mbox_open(void)
{
    int file_desc = open("/dev/vcio", O_RDWR);
    if (file_desc < 0)
    {
        /* errno is already set by open() */
        return -1;
    }
    return file_desc;
}

/**
 * @brief Closes the mailbox device.
 *
 * @param file_desc File descriptor for the mailbox to close.
 */
void mbox_close(int file_desc)
{
    close(file_desc);
}

/**
 * @brief Queries the GPU firmware version via the mailbox interface.
 *
 * Sends the GET_FIRMWARE_VERSION property tag and returns the 32-bit version
 * word from the VideoCore GPU.
 *
 * @param file_desc  File descriptor returned by `mbox_open()`.
 * @return On success, the firmware version.
 *         On failure, returns 0 and sets `errno` (e.g. to `EIO`).
 */
uint32_t get_version(int file_desc)
{
    uint32_t msg[7];

    msg[0] = sizeof(msg);              // total size
    msg[1] = 0;                        // request code
    msg[2] = TAG_GET_FIRMWARE_VERSION; // GET_FIRMWARE_VERSION tag
    msg[3] = 4;                        // value buffer size
    msg[4] = 0;                        // request size
    msg[5] = 0;                        // space for returned version
    msg[6] = 0;                        // end tag

    if (mbox_property(file_desc, msg) < 0)
    {
        errno = EIO;
        return 0;
    }

    return msg[5];
}

/**
 * @brief Allocates memory via the mailbox interface.
 *
 * Sends the ALLOCATE_MEMORY property tag to request a contiguous block of
 * GPU-accessible memory.
 *
 * @param file_desc File descriptor returned by `mbox_open()`.
 * @param size      Number of bytes to allocate.
 * @param align     Alignment (in bytes) for the allocation.
 * @param flags     Allocation flags (e.g., caching, permissions).
 * @return On success, returns a nonzero handle to the allocated memory.
 *         On failure, returns 0 and sets errno (e.g., to EIO).
 */
uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags)
{
    size_t i = 0;
    uint32_t p[32];
    p[i++] = 0;          // size
    p[i++] = 0x00000000; // process request

    p[i++] = TAG_ALLOCATE_MEMORY; // (the tag id)
    p[i++] = 12;                  // (size of the buffer)
    p[i++] = 12;                  // (size of the data)
    p[i++] = size;                // (num bytes? or pages?)
    p[i++] = align;               // (alignment)
    p[i++] = flags;               // (MEM_FLAG_L1_NONALLOCATING)

    p[i++] = 0x00000000;  // end tag
    p[0] = i * sizeof *p; // actual size

    if (mbox_property(file_desc, p) < 0)
    {
        errno = EIO;
        return 0;
    }
    return p[5];
}

/**
 * @brief Frees previously allocated GPU memory.
 *
 * Sends the RELEASE_MEMORY (0x3000f) property tag to the VideoCore GPU,
 * asking it to free the allocation identified by `handle`.
 *
 * @param file_desc  Mailbox file descriptor from mbox_open().
 * @param handle     Handle returned by a prior mem_alloc() call.
 * @return On success, returns 0.
 *         On firmware‐level error, returns a non-zero error code in the return value.
 *         If the underlying ioctl() fails, returns 0 and sets errno to EIO.
 */
uint32_t mem_free(int file_desc, uint32_t handle)
{
    size_t i = 0;
    uint32_t p[32];
    p[i++] = 0;          // size
    p[i++] = 0x00000000; // process request

    p[i++] = TAG_RELEASE_MEMORY; // (the tag id)
    p[i++] = 4;                  // (size of the buffer)
    p[i++] = 4;                  // (size of the data)
    p[i++] = handle;

    p[i++] = 0x00000000;  // end tag
    p[0] = i * sizeof *p; // actual size

    if (mbox_property(file_desc, p) < 0)
    {
        errno = EIO;
        return 0;
    }
    return p[5];
}

/**
 * @brief Locks allocated memory via the mailbox interface.
 *
 * @param file_desc File descriptor returned by mbox_open().
 * @param handle    Handle to the memory to lock.
 * @return On success, the bus address handle (>0). On failure, returns 0 and sets errno.
 */
uint32_t mem_lock(int file_desc, uint32_t handle)
{
    uint32_t p[32];
    size_t i = 0;

    p[i++] = 0;               // total size placeholder
    p[i++] = 0x00000000;      // process request
    p[i++] = TAG_LOCK_MEMORY; // TAG_MEM_LOCK
    p[i++] = 4;               // size of buffer
    p[i++] = 4;               // size of data
    p[i++] = handle;          // request payload
    p[i++] = 0x00000000;      // end tag
    p[0] = i * sizeof *p;

    if (mbox_property(file_desc, p) < 0)
    {
        /* ioctl failed: set errno and return 0 so caller can detect error */
        errno = EIO;
        return 0;
    }

    /* p[5] is the returned bus address handle (or 0 on firmware‐level error) */
    if (p[5] == 0)
    {
        /* firmware returned a failure code, map it to errno if you like */
        errno = EPROTO;
    }

    return p[5];
}

/**
 * @brief Unlocks a previously locked memory allocation.
 *
 * Sends the UNLOCK_MEMORY (0x3000e) property tag, releasing the bus address
 * lock on the allocation identified by `handle`.
 *
 * @param file_desc  Mailbox file descriptor from mbox_open().
 * @param handle     Handle returned by a prior mem_alloc() call.
 * @return On success, returns 0.
 *         On firmware‐level error, returns a non-zero error code in the return value.
 *         If the underlying ioctl() fails, returns 0 and sets errno to EIO.
 */
uint32_t mem_unlock(int file_desc, uint32_t handle)
{
    uint32_t p[32];
    size_t i = 0;

    p[i++] = 0;                 // Size
    p[i++] = 0x00000000;        // Process request
    p[i++] = TAG_UNLOCK_MEMORY; // Tag ID
    p[i++] = 4;                 // Size of the buffer
    p[i++] = 4;                 // Size of the data
    p[i++] = handle;
    p[i++] = 0x00000000; // End tag
    p[0] = i * sizeof(*p);

    if (mbox_property(file_desc, p) < 0)
    {
        errno = EIO;
        return 0;
    }

    return p[5];
}

/**
 * @brief Maps physical memory into the process’s address space.
 *
 * Queries the system page size, aligns the requested `base` down to a page
 * boundary, and mmaps `size + offset` bytes from `/dev/mem`.  Returns a
 * pointer adjusted by the offset so that it covers exactly `[base, base+size)`.
 *
 * @param base  Physical base address to map.
 * @param size  Number of bytes to map.
 * @return On success, a pointer to the mapped region corresponding exactly
 *         to `[base, base+size)`.  On failure, returns NULL and sets errno
 *         (e.g. to EIO or whatever open()/mmap() set).
 */
void *mapmem(uint32_t base, size_t size)
{
    /* Get (and cache) the page size */
    size_t page = get_page_size();

    /* Compute offset and aligned base as before */
    size_t offset = base % page;
    off_t aligned_base = (off_t)(base - offset);

    /* Open /dev/mem */
    int fd = get_mem_fd();
    if (fd < 0)
    {
        /* errno set by open() */
        return NULL;
    }

    /* mmap the full region (including the offset) */
    void *mapping = mmap(
        NULL, size + offset,
        PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, aligned_base);

    if (mapping == MAP_FAILED)
    {
        /* translate to errno and return NULL */
        errno = EIO;
        return NULL;
    }

    /* Return a pointer adjusted by offset */
    return (uint8_t *)mapping + offset;
}

/**
 * @brief Unmaps a region previously mapped by mapmem().
 *
 * Given the pointer returned by mapmem() and the original `size` you
 * requested, this will:
 *  1. Recompute the page‐size and the offset into that page,
 *     by looking at the low bits of `addr`.
 *  2. Subtract the offset to recover the true base pointer.
 *  3. Call munmap() on [base…base+size+offset).
 *
 * @param addr  Pointer returned by mapmem(). May be NULL.
 * @param size  The `size` argument you passed to mapmem().
 */
void unmapmem(void *addr, size_t size)
{
    if (!addr)
        return;

    /* Figure out how far into the page our addr sits */
    size_t page = get_page_size();
    uintptr_t addr_int = (uintptr_t)addr;
    size_t offset = addr_int % page;

    /* Recover the original mapping base and total length */
    void *map_base = (void *)(addr_int - offset);
    size_t map_len = size + offset;

    /* Now unmap the entire region */
    munmap(map_base, map_len);
}
