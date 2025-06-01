/**
 * @file mailbox.c
 * @brief Implementation of the mailbox property‐interface for the Raspberry Pi GPU.
 *
 * @details
 * This source file provides the definitions for all functions declared in `mailbox.h`,
 * enabling communication with the VideoCore GPU via the mailbox property‐interface. It implements:
 *   - Opening and closing the `/dev/vcio` mailbox device (`mbox_open`, `mbox_close`).
 *   - Sending property buffers to the GPU using an IOCTL (`real_mbox_property` and its timeout variant).
 *   - Querying the GPU firmware version (`real_get_version` → `get_version`).
 *   - Allocating (`real_mem_alloc` → `mem_alloc`), locking (`real_mem_lock` → `mem_lock`),
 *     unlocking (`real_mem_unlock` → `mem_unlock`), and freeing (`real_mem_free` → `mem_free`)
 *     contiguous, GPU‐accessible memory.
 *   - Mapping (`real_mapmem` → `mapmem`) and unmapping (`real_unmapmem` → `unmapmem`)
 *     physical memory regions via `/dev/mem`.
 *   - Caching the `/dev/mem` file descriptor with `real_get_mem_fd` and cleaning it up at program exit
 *     (`real_mem_cleanup` → `mem_cleanup`).
 *   - (Optionally) installing test hooks for `open()`, `/dev/mem` access, and mailbox ioctl calls if
 *     compiled with `ENABLE_MBOX_TEST_HOOKS`.
 *
 *   The mailbox property‐interface documentation can be found at:
 *     - https://github.com/raspberrypi/firmware/wiki/Mailboxes
 *     - https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
 *     - https://bitbanged.com/posts/understanding-rpi/the-mailbox/
 *     - http://www.freenos.org/doxygen/classBroadcomMailbox.html
 *
 * @copyright
 * Copyright (c) 2012, Broadcom Europe Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions, and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions, and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   - Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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

#include "mailbox.h"

#include <errno.h>
#include <fcntl.h>     /* open flags */
#include <stdint.h>    /* uintptr_t */
#include <stdlib.h>    /* atexit, NULL */
#include <sys/ioctl.h> /* ioctl */
#include <sys/mman.h>  /* mmap, munmap, MAP_SHARED, PROT_* */
#include <unistd.h>    /* close, sysconf */

#ifdef DEBUG_MAILBOX
#include <stdio.h>
#endif

#ifdef ENABLE_TIMEOUTS
#include <signal.h>
#include <setjmp.h>
#endif

/**
 * @brief IOCTL command code for the mailbox property interface.
 */
#define IOCTL_MBOX_PROPERTY _IOWR(100, 0, char *)

/*---------------------------------------------------------------------------*/
/* 1) Forward‐declarations of “real_…” implementations                       */
/*---------------------------------------------------------------------------*/
static int real_mbox_property(int file_desc, void *buf);
static int real_open_wrapper(const char *path, int flags);
static int real_get_mem_fd(void);
static void real_mbox_close(int file_desc);
static uint32_t real_get_version(int file_desc);
static uint32_t real_mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);
static uint32_t real_mem_free(int file_desc, uint32_t handle);
static uint32_t real_mem_lock(int file_desc, uint32_t handle);
static uint32_t real_mem_unlock(int file_desc, uint32_t handle);
static void *real_mapmem(uint32_t base, size_t size);
static void real_unmapmem(void *addr, size_t size);
static void real_mem_cleanup(void);

#ifdef ENABLE_MBOX_TEST_HOOKS
/*---------------------------------------------------------------------------*/
/* 2) Hook pointers (default to “real_…” funcs) and setters                   */
/*---------------------------------------------------------------------------*/
static int (*property_impl)(int, void *) = real_mbox_property;
static int (*open_impl)(const char *, int) = real_open_wrapper;
static int (*get_mem_fd_impl)(void) = real_get_mem_fd;
static void (*close_impl)(int) = real_mbox_close;
static uint32_t (*get_version_impl)(int) = real_get_version;
static uint32_t (*mem_alloc_impl)(int, uint32_t, uint32_t, uint32_t) = real_mem_alloc;
static uint32_t (*mem_free_impl)(int, uint32_t) = real_mem_free;
static uint32_t (*mem_lock_impl)(int, uint32_t) = real_mem_lock;
static uint32_t (*mem_unlock_impl)(int, uint32_t) = real_mem_unlock;
static void *(*mapmem_impl)(uint32_t, size_t) = real_mapmem;
static void (*unmapmem_impl)(void *, size_t) = real_unmapmem;
static void (*mem_cleanup_impl)(void) = real_mem_cleanup;

/** Install a custom `ioctl()` hook (if non‐NULL); otherwise revert to real. */
void mailbox_set_property_hook(int (*hook)(int, void *))
{
    property_impl = hook ? hook : real_mbox_property;
}

/** Install a custom `open()` hook (if non‐NULL); otherwise revert to real. */
void mailbox_set_open_hook(int (*hook)(const char *, int))
{
    open_impl = hook ? hook : real_open_wrapper;
}

/** Install a custom `/dev/mem`‐fd hook (if non‐NULL); otherwise revert. */
void mailbox_set_mem_fd_hook(int (*hook)(void))
{
    get_mem_fd_impl = hook ? hook : real_get_mem_fd;
}

/** Install a custom `close()` hook for mailbox (if non‐NULL); otherwise revert. */
void mailbox_set_close_hook(void (*hook)(int))
{
    close_impl = hook ? hook : real_mbox_close;
}

/** Install a custom `get_version()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_get_version_hook(uint32_t (*hook)(int))
{
    get_version_impl = hook ? hook : real_get_version;
}

/** Install a custom `mem_alloc()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_mem_alloc_hook(uint32_t (*hook)(int, uint32_t, uint32_t, uint32_t))
{
    mem_alloc_impl = hook ? hook : real_mem_alloc;
}

/** Install a custom `mem_free()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_mem_free_hook(uint32_t (*hook)(int, uint32_t))
{
    mem_free_impl = hook ? hook : real_mem_free;
}

/** Install a custom `mem_lock()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_mem_lock_hook(uint32_t (*hook)(int, uint32_t))
{
    mem_lock_impl = hook ? hook : real_mem_lock;
}

/** Install a custom `mem_unlock()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_mem_unlock_hook(uint32_t (*hook)(int, uint32_t))
{
    mem_unlock_impl = hook ? hook : real_mem_unlock;
}

/** Install a custom `mapmem()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_mapmem_hook(void *(*hook)(uint32_t, size_t))
{
    mapmem_impl = hook ? hook : real_mapmem;
}

/** Install a custom `unmapmem()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_unmapmem_hook(void (*hook)(void *, size_t))
{
    unmapmem_impl = hook ? hook : real_unmapmem;
}

/** Install a custom `mem_cleanup()` hook (if non‐NULL); otherwise revert. */
void mailbox_set_mem_cleanup_hook(void (*hook)(void))
{
    mem_cleanup_impl = hook ? hook : real_mem_cleanup;
}
#endif // ENABLE_MBOX_TEST_HOOKS

/*---------------------------------------------------------------------------*/
/* 3) Public API functions                                                    */
/*---------------------------------------------------------------------------*/

/**
 * @brief Opens the `/dev/vcio` mailbox device.
 * @return File descriptor (>=0) on success; -1 on error.
 */
int mbox_open(void)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return open_impl("/dev/vcio", O_RDWR);
#else
    return real_open_wrapper("/dev/vcio", O_RDWR);
#endif
}

/**
 * @brief Closes the mailbox device.
 * @param file_desc File descriptor returned by mbox_open().
 */
void mbox_close(int file_desc)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    close_impl(file_desc);
#else
    real_mbox_close(file_desc);
#endif
}

/**
 * @brief Queries GPU firmware version.
 * @param file_desc File descriptor from mbox_open().
 * @return Nonzero version on success; 0 on error (errno=EIO).
 */
uint32_t get_version(int file_desc)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return get_version_impl(file_desc);
#else
    return real_get_version(file_desc);
#endif
}

/**
 * @brief Allocates GPU memory (ALLOCATE_MEMORY tag).
 * @param file_desc File descriptor from mbox_open().
 * @param size      Number of bytes to allocate.
 * @param align     Alignment in bytes.
 * @param flags     Allocation flags.
 * @return Nonzero handle on success; 0 on error (errno=EIO).
 */
uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return mem_alloc_impl(file_desc, size, align, flags);
#else
    return real_mem_alloc(file_desc, size, align, flags);
#endif
}

/**
 * @brief Frees GPU memory (RELEASE_MEMORY tag).
 * @param file_desc File descriptor from mbox_open().
 * @param handle    Handle returned by mem_alloc().
 * @return 0 on success; nonzero on firmware error; 0 + errno=EIO on ioctl error.
 */
uint32_t mem_free(int file_desc, uint32_t handle)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return mem_free_impl(file_desc, handle);
#else
    return real_mem_free(file_desc, handle);
#endif
}

/**
 * @brief Locks GPU memory (LOCK_MEMORY tag).
 * @param file_desc File descriptor from mbox_open().
 * @param handle    Handle returned by mem_alloc().
 * @return Bus‐address handle (>0) on success; 0 + errno set on error.
 */
uint32_t mem_lock(int file_desc, uint32_t handle)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return mem_lock_impl(file_desc, handle);
#else
    return real_mem_lock(file_desc, handle);
#endif
}

/**
 * @brief Unlocks GPU memory (UNLOCK_MEMORY tag).
 * @param file_desc File descriptor from mbox_open().
 * @param handle    Handle returned by mem_alloc().
 * @return 0 on success; nonzero on firmware error; 0 + errno=EIO on ioctl error.
 */
uint32_t mem_unlock(int file_desc, uint32_t handle)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return mem_unlock_impl(file_desc, handle);
#else
    return real_mem_unlock(file_desc, handle);
#endif
}

/**
 * @brief Maps physical memory into user space.
 * @param base  Physical base address to map.
 * @param size  Number of bytes to map.
 * @return Pointer to mapped region on success; NULL + errno on error.
 */
void *mapmem(uint32_t base, size_t size)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    return mapmem_impl(base, size);
#else
    return real_mapmem(base, size);
#endif
}

/**
 * @brief Unmaps a region previously mapped by mapmem().
 * @param addr  Pointer returned by mapmem().
 * @param size  Same size passed into mapmem().
 */
void unmapmem(void *addr, size_t size)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    unmapmem_impl(addr, size);
#else
    real_unmapmem(addr, size);
#endif
}

/**
 * @brief Cleans up (closes) the cached `/dev/mem` file descriptor.
 * Registered via atexit(); safe to call multiple times.
 */
void mem_cleanup(void)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    mem_cleanup_impl();
#else
    real_mem_cleanup();
#endif
}

/*---------------------------------------------------------------------------*/
/* 4) “Real” implementations                                                   */
/*---------------------------------------------------------------------------*/

/**
 * @brief Wrapper around open(), so we can override open() via open_impl.
 */
static int real_open_wrapper(const char *path, int flags)
{
    return open(path, flags);
}

/**
 * @brief Closes the mailbox file descriptor.
 */
static void real_mbox_close(int file_desc)
{
    close(file_desc);
}

/**
 * @brief Returns a cached `/dev/mem` fd. Registers real_mem_cleanup via atexit().
 */
static int real_get_mem_fd(void)
{
    static int mem_fd = -1;
    if (mem_fd < 0)
    {
        mem_fd = real_open_wrapper("/dev/mem", O_RDWR | O_SYNC);
        if (mem_fd >= 0)
        {
            atexit(real_mem_cleanup);
        }
    }
    return mem_fd;
}

/**
 * @brief Cleanup callback (registered via atexit) that closes `/dev/mem`.
 */
static void real_mem_cleanup(void)
{
    int fd = real_get_mem_fd();
    if (fd >= 0)
    {
        close(fd);
    }
}

/**
 * @brief Sends a mailbox property buffer via ioctl.
 * @return >=0 on success; -1 on error (errno set).
 */
static int real_mbox_property(int file_desc, void *buf)
{
    if (buf == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    int ret = ioctl(file_desc, IOCTL_MBOX_PROPERTY, buf);

#ifdef DEBUG_MAILBOX
    uint32_t *p = buf;
    size_t words = *(uint32_t *)buf / sizeof(uint32_t);
    for (size_t i = 0; i < words; i++)
    {
        printf("%04zx: 0x%08x\n", i * sizeof(*p), p[i]);
    }
#endif

    return (ret < 0) ? -1 : ret;
}

#ifdef ENABLE_TIMEOUTS
static sigjmp_buf jmpbuf;

/**
 * @brief SIGALRM handler: jumps back on timeout.
 */
static void timeout_handler(int sig)
{
    (void)sig;
    siglongjmp(jmpbuf, 1);
}

/**
 * @brief Perform a mailbox IOCTL with 1-second timeout.
 * @return >=0 on success; -1 on error (errno=ETIMEDOUT if timed out).
 */
static int __attribute__((unused))
mbox_property_with_timeout(int fd, void *buf)
{
    struct sigaction sa = {.sa_handler = timeout_handler, .sa_flags = 0};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);

    if (sigsetjmp(jmpbuf, 1) != 0)
    {
        errno = ETIMEDOUT;
        return -1;
    }

    alarm(1);
    int ret = ioctl(fd, IOCTL_MBOX_PROPERTY, buf);
    alarm(0);
    return ret;
}
#endif // ENABLE_TIMEOUTS

/**
 * @brief Queries GPU firmware version (GET_FIRMWARE_VERSION tag).
 * @return Nonzero version on success; 0 + errno=EIO on error.
 */
static uint32_t real_get_version(int file_desc)
{
    uint32_t msg[7];
    msg[0] = sizeof(msg);
    msg[1] = 0;
    msg[2] = TAG_GET_FIRMWARE_VERSION;
    msg[3] = 4;
    msg[4] = 0;
    msg[5] = 0;
    msg[6] = 0;

#ifdef ENABLE_MBOX_TEST_HOOKS
    if (property_impl(file_desc, msg) < 0)
    {
#else
    if (real_mbox_property(file_desc, msg) < 0)
    {
#endif
        errno = EIO;
        return 0;
    }
    return msg[5];
}

/**
 * @brief Allocates GPU memory (ALLOCATE_MEMORY tag).
 * @return Nonzero handle on success; 0 + errno=EIO on error.
 */
static uint32_t real_mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags)
{
    size_t i = 0;
    uint32_t p[32];
    p[i++] = 0;
    p[i++] = 0x00000000;
    p[i++] = TAG_ALLOCATE_MEMORY;
    p[i++] = 12;
    p[i++] = 12;
    p[i++] = size;
    p[i++] = align;
    p[i++] = flags;
    p[i++] = 0x00000000;
    p[0] = (uint32_t)(i * sizeof *p);

#ifdef ENABLE_MBOX_TEST_HOOKS
    if (property_impl(file_desc, p) < 0)
    {
#else
    if (real_mbox_property(file_desc, p) < 0)
    {
#endif
        errno = EIO;
        return 0;
    }
    return p[5];
}

/**
 * @brief Frees GPU memory (RELEASE_MEMORY tag).
 * @return 0 on success; nonzero on firmware error; 0 + errno=EIO on ioctl error.
 */
static uint32_t real_mem_free(int file_desc, uint32_t handle)
{
    size_t i = 0;
    uint32_t p[32];
    p[i++] = 0;
    p[i++] = 0x00000000;
    p[i++] = TAG_RELEASE_MEMORY;
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0x00000000;
    p[0] = (uint32_t)(i * sizeof *p);

#ifdef ENABLE_MBOX_TEST_HOOKS
    if (property_impl(file_desc, p) < 0)
    {
#else
    if (real_mbox_property(file_desc, p) < 0)
    {
#endif
        errno = EIO;
        return 0;
    }
    return p[5];
}

/**
 * @brief Locks GPU memory (LOCK_MEMORY tag).
 * @return Bus‐address handle (>0) on success; 0 + errno set on error.
 */
static uint32_t real_mem_lock(int file_desc, uint32_t handle)
{
    size_t i = 0;
    uint32_t p[32];
    p[i++] = 0;
    p[i++] = 0x00000000;
    p[i++] = TAG_LOCK_MEMORY;
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0x00000000;
    p[0] = (uint32_t)(i * sizeof *p);

#ifdef ENABLE_MBOX_TEST_HOOKS
    if (property_impl(file_desc, p) < 0)
    {
#else
    if (real_mbox_property(file_desc, p) < 0)
    {
#endif
        errno = EIO;
        return 0;
    }
    if (p[5] == 0)
    {
        errno = EPROTO;
    }
    return p[5];
}

/**
 * @brief Unlocks GPU memory (UNLOCK_MEMORY tag).
 * @return 0 on success; nonzero on firmware error; 0 + errno=EIO on ioctl error.
 */
static uint32_t real_mem_unlock(int file_desc, uint32_t handle)
{
    size_t i = 0;
    uint32_t p[32];
    p[i++] = 0;
    p[i++] = 0x00000000;
    p[i++] = TAG_UNLOCK_MEMORY;
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0x00000000;
    p[0] = (uint32_t)(i * sizeof *p);

#ifdef ENABLE_MBOX_TEST_HOOKS
    if (property_impl(file_desc, p) < 0)
    {
#else
    if (real_mbox_property(file_desc, p) < 0)
    {
#endif
        errno = EIO;
        return 0;
    }
    return p[5];
}

/**
 * @brief Maps physical memory into user space (/dev/mem).
 * @return Pointer to mapped region on success; NULL + errno on error.
 */
static void *real_mapmem(uint32_t base, size_t size)
{
    /* Determine (and cache) system page size */
    size_t page;
    {
        long tmp = sysconf(_SC_PAGESIZE);
        page = (tmp < 0) ? 4096 : (size_t)tmp;
    }
    size_t offset = base % page;
    off_t aligned_base = (off_t)(base - offset);

#ifdef ENABLE_MBOX_TEST_HOOKS
    int fd = get_mem_fd_impl();
#else
    int fd = real_get_mem_fd();
#endif
    if (fd < 0)
    {
        /* Hook likely set errno already (e.g. EPERM) */
        return NULL;
    }

    void *mapping = mmap(
        NULL,
        size + offset,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        aligned_base);
    if (mapping == MAP_FAILED)
    {
        errno = EIO;
        return NULL;
    }
    return (uint8_t *)mapping + offset;
}

/**
 * @brief Unmaps a region previously mapped by real_mapmem().
 */
static void real_unmapmem(void *addr, size_t size)
{
    if (!addr)
        return;

    size_t page;
    {
        long tmp = sysconf(_SC_PAGESIZE);
        page = (tmp < 0) ? 4096 : (size_t)tmp;
    }
    uintptr_t addr_int = (uintptr_t)addr;
    size_t offset = addr_int % page;
    void *map_base = (void *)(addr_int - offset);
    size_t map_len = size + offset;

    munmap(map_base, map_len);
}
