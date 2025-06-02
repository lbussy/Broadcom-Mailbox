/**
 * @file mailbox.cpp
 * @brief Mailbox property‐interface API for communicating with the Raspberry Pi GPU.
 *
 * @details
 *   - Open/close `/dev/vcio`
 *   - Query GPU firmware version
 *   - Allocate/lock/unlock/free GPU memory
 *   - Map/unmap physical memory via `/dev/mem`
 *   - Optionally override each low‐level I/O call via test hooks
 *
 *   See:
 *     https://github.com/raspberrypi/firmware/wiki/Mailboxes
 *     https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
 *
 * @copyright
 *   Copyright (c) 2012, Broadcom Europe Ltd.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions, and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions, and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   - Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *   LIABILITY, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *   POSSIBILITY OF SUCH DAMAGE.
 */

#include "mailbox.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>      // std::atexit
#include <cstring>      // std::memset
#include <fcntl.h>      // O_RDWR, O_SYNC
#include <system_error> // std::system_error, std::generic_category
#include <sys/ioctl.h>  // ioctl()
#include <sys/mman.h>   // mmap(), munmap(), MAP_SHARED, PROT_READ/WRITE
#include <unistd.h>     // close(), open(), sysconf()
#include <mutex>        // std::once_flag, std::call_once

#ifdef DEBUG_MAILBOX
#include <cstdio> // std::printf()
#endif

#ifdef ENABLE_TIMEOUTS
#include <csignal> // sigaction, SIGALRM
#include <csetjmp> // sigjmp_buf, sigsetjmp, siglongjmp
#endif

/*==============================================================================
   FORWARD DECLARATIONS OF “REAL” FUNCTIONS
   (only when hooks are disabled)
==============================================================================*/
#ifndef ENABLE_MBOX_TEST_HOOKS
static uint32_t real_get_version(int file_desc);
#endif

/**
 * @brief IOCTL command code for the mailbox property interface.
 *
 * Uses “magic” number 100 and command 0 to talk to `/dev/vcio`.
 */
static constexpr unsigned long IOCTL_MBOX_PROPERTY = _IOWR(100, 0, char *);

/*==============================================================================
   “REAL”‐MODE SINGLETONS: Always defined, but only used when no hook is set
==============================================================================*/

// ─────────────────────────────────────────────────────────────────────────────
// /dev/vcio (mailbox) – open once, shared FD
// ─────────────────────────────────────────────────────────────────────────────
static std::once_flag s_mbox_init_flag;
static int s_mbox_fd = -1;
static int s_mbox_errno = 0;

static void initialize_mbox_fd()
{
    int fd = ::open("/dev/vcio", O_RDWR);
    if (fd < 0)
    {
        s_mbox_errno = errno;
        s_mbox_fd = -1;
    }
    else
    {
        s_mbox_fd = fd;
        std::atexit([]()
                    {
                        if (s_mbox_fd >= 0) ::close(s_mbox_fd); });
    }
}

// Mark as “unused” so that builds with ENABLE_MBOX_TEST_HOOKS (where it never gets called) do not warn:
static int __attribute__((unused)) get_shared_mbox_fd()
{
    std::call_once(s_mbox_init_flag, initialize_mbox_fd);
    if (s_mbox_fd < 0)
    {
        throw std::system_error(
            s_mbox_errno,
            std::generic_category(),
            "mbox_open(): cannot open /dev/vcio");
    }
    return s_mbox_fd;
}

// ─────────────────────────────────────────────────────────────────────────────
// /dev/mem – open once, shared FD
// ─────────────────────────────────────────────────────────────────────────────
static std::once_flag s_mem_fd_flag;
static int s_mem_fd = -1;
static int s_mem_errno = 0;

static void initialize_mem_fd()
{
    int fd = ::open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0)
    {
        s_mem_errno = errno;
        s_mem_fd = -1;
    }
    else
    {
        s_mem_fd = fd;
        std::atexit([]()
                    {
                        if (s_mem_fd >= 0) ::close(s_mem_fd); });
    }
}

// Mark as “unused” for the same reason:
static int __attribute__((unused)) get_shared_mem_fd()
{
    std::call_once(s_mem_fd_flag, initialize_mem_fd);
    if (s_mem_fd < 0)
    {
        throw std::system_error(
            s_mem_errno,
            std::generic_category(),
            "mapmem(): cannot open /dev/mem");
    }
    return s_mem_fd;
}

/*==============================================================================
   FORWARD DECLARATIONS OF “REAL” FUNCTIONS
==============================================================================*/
static int real_open_wrapper(const char *path, int flags) __attribute__((unused));
static int real_mbox_property(int file_desc, void *buf);
static uint32_t real_mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);
static void real_mem_free(int file_desc, uint32_t handle);
static uint32_t real_mem_lock(int file_desc, uint32_t handle);
static void real_mem_unlock(int file_desc, uint32_t handle);
static void *real_mapmem(uint32_t base, size_t size);
static void real_unmapmem(void *addr, size_t size);
static void real_mem_cleanup(void);

/*==============================================================================
   OPTIONAL TEST‐HOOK FUNCTION POINTERS
==============================================================================*/
#ifdef ENABLE_MBOX_TEST_HOOKS

// Each pointer defaults to nullptr. mailbox_set_*_hook(...) will set them.
static int (*open_impl)(const char *, int) = nullptr;
static int (*close_impl)(int) = nullptr;
static int (*get_mem_fd_impl)(void) = nullptr;
static int (*property_impl)(int, void *) = nullptr;
static int (*mem_alloc_impl)(int, uint32_t, uint32_t, uint32_t) = nullptr;
static int (*mem_free_impl)(int, uint32_t) = nullptr;
static int (*mem_lock_impl)(int, uint32_t) = nullptr;
static int (*mem_unlock_impl)(int, uint32_t) = nullptr;
static int (*mapmem_impl)(uint32_t, size_t) = nullptr;
static int (*unmapmem_impl)(void *, size_t) = nullptr;
static int (*mem_cleanup_impl)(void) = nullptr;

/**
 * @brief Override the internal open() used by mbox_open().
 * @param hook If non‐NULL, mbox_open() calls hook(path, flags) instead of real ::open().
 *             Passing NULL restores real behavior (::open).
 */
void mailbox_set_open_hook(int (*hook)(const char *, int))
{
    open_impl = hook ? hook : real_open_wrapper;
}

/**
 * @brief Override mbox_close().
 * @param hook If non‐NULL, mbox_close(fd) calls hook(fd) instead of ::close(fd).
 *             Passing NULL restores real ::close().
 */
void mailbox_set_close_hook(int (*hook)(int))
{
    close_impl = hook ? hook : [](int fd) -> int
    {
        return ::close(fd);
    };
}

/**
 * @brief Override the function used to open `/dev/mem`.
 * @param hook If non‐NULL, get_mem_fd() calls hook() instead of get_shared_mem_fd().
 *             Passing NULL restores real get_shared_mem_fd().
 */
void mailbox_set_mem_fd_hook(int (*hook)(void))
{
    // Fallback lambda calls get_shared_mem_fd()
    get_mem_fd_impl = hook ? hook : []() -> int
    {
        try
        {
            return get_shared_mem_fd();
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override the internal mailbox‐property IOCTL() function.
 * @param hook If non‐NULL, get_version()/mem_alloc()/etc. invoke hook() instead of real_mbox_property().
 *             Passing NULL restores real_mbox_property().
 */
void mailbox_set_property_hook(int (*hook)(int, void *))
{
    property_impl = hook ? hook : [](int fd, void *buf) -> int
    {
        return real_mbox_property(fd, buf);
    };
}

/**
 * @brief Override mem_alloc().
 * @param hook If non‐NULL, mem_alloc(fd, size, align, flags) calls hook(...) instead of real_mem_alloc().
 *             Passing NULL restores real_mem_alloc().
 */
void mailbox_set_mem_alloc_hook(int (*hook)(int, uint32_t, uint32_t, uint32_t))
{
    mem_alloc_impl = hook ? hook : [](int fd, uint32_t s, uint32_t a, uint32_t f) -> int
    {
        try
        {
            uint32_t h = real_mem_alloc(fd, s, a, f);
            return (h == 0 ? -1 : static_cast<int>(h));
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override mem_free().
 * @param hook If non‐NULL, mem_free(fd, handle) calls hook(...) instead of real_mem_free().
 *             Passing NULL restores real_mem_free().
 */
void mailbox_set_mem_free_hook(int (*hook)(int, uint32_t))
{
    mem_free_impl = hook ? hook : [](int fd, uint32_t h) -> int
    {
        try
        {
            real_mem_free(fd, h);
            return 0;
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override mem_lock().
 * @param hook If non‐NULL, mem_lock(fd, handle) calls hook(...) instead of real_mem_lock().
 *             Passing NULL restores real_mem_lock().
 */
void mailbox_set_mem_lock_hook(int (*hook)(int, uint32_t))
{
    mem_lock_impl = hook ? hook : [](int fd, uint32_t h) -> int
    {
        try
        {
            uint32_t addr = real_mem_lock(fd, h);
            return (addr == 0 ? -1 : static_cast<int>(addr));
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override mem_unlock().
 * @param hook If non‐NULL, mem_unlock(fd, handle) calls hook(...) instead of real_mem_unlock().
 *             Passing NULL restores real_mem_unlock().
 */
void mailbox_set_mem_unlock_hook(int (*hook)(int, uint32_t))
{
    mem_unlock_impl = hook ? hook : [](int fd, uint32_t h) -> int
    {
        try
        {
            real_mem_unlock(fd, h);
            return 0;
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override mapmem().
 * @param hook If non‐NULL, mapmem(base, size) calls hook(...) instead of real_mapmem().
 *             Passing NULL restores real_mapmem().
 */
void mailbox_set_mapmem_hook(int (*hook)(uint32_t, size_t))
{
    mapmem_impl = hook ? hook : [](uint32_t b, size_t s) -> int
    {
        try
        {
            void *p = real_mapmem(b, s);
            return (p ? 0 : -1);
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override unmapmem().
 * @param hook If non‐NULL, unmapmem(addr, size) calls hook(...) instead of real_unmapmem().
 *             Passing NULL restores real_unmapmem().
 */
void mailbox_set_unmapmem_hook(int (*hook)(void *, size_t))
{
    unmapmem_impl = hook ? hook : [](void *a, size_t s) -> int
    {
        try
        {
            real_unmapmem(a, s);
            return 0;
        }
        catch (...)
        {
            return -1;
        }
    };
}

/**
 * @brief Override mem_cleanup().
 * @param hook If non‐NULL, mem_cleanup() calls hook() instead of real_mem_cleanup().
 *             Passing NULL restores real_mem_cleanup().
 */
void mailbox_set_mem_cleanup_hook(int (*hook)(void))
{
    mem_cleanup_impl = hook ? hook : []() -> int
    {
        try
        {
            real_mem_cleanup();
            return 0;
        }
        catch (...)
        {
            return -1;
        }
    };
}

#endif // ENABLE_MBOX_TEST_HOOKS

#ifdef ENABLE_TIMEOUTS
static sigjmp_buf jmpbuf;

/**
 * @brief SIGALRM handler: jumps back on timeout.
 *
 * Invoked if an alarm expires during a mailbox‐property IOCTL.
 */
static void timeout_handler(int sig)
{
    (void)sig;
    siglongjmp(jmpbuf, 1);
}

/**
 * @brief Perform a mailbox IOCTL with a 1‐second timeout.
 * @param fd  File descriptor for /dev/vcio.
 * @param buf Pointer to the mailbox message buffer.
 * @return >=0 on success; -1 on error (errno=ETIMEDOUT if timed out).
 */
static int __attribute__((unused))
mbox_property_with_timeout(int fd, void *buf)
{
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, nullptr);

    if (sigsetjmp(jmpbuf, 1) != 0)
    {
        errno = ETIMEDOUT;
        return -1;
    }

    alarm(1);
    int ret = ::ioctl(fd, IOCTL_MBOX_PROPERTY, buf);
    alarm(0);
    return ret;
}
#endif // ENABLE_TIMEOUTS

/*==============================================================================
   PUBLIC API IMPLEMENTATIONS
==============================================================================*/

/**
 * @brief Opens the `/dev/vcio` mailbox device.
 * @return File descriptor (>=0) on success.
 * @throws std::system_error on failure (real mode only).
 */
int mbox_open()
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    int fd = (open_impl) ? open_impl("/dev/vcio", O_RDWR)
                         : real_open_wrapper("/dev/vcio", O_RDWR);
    if (fd < 0)
    {
        // C‐style: return -1, errno is already set
        return -1;
    }
    return fd;
#else
    // “Real” mode – thread‐safe singleton
    return get_shared_mbox_fd();
#endif
}

/**
 * @brief Closes the mailbox device.
 * @param file_desc File descriptor returned by mbox_open().
 * @throws std::system_error on failure (real mode only).
 */
void mbox_close(int file_desc)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    int rc = (close_impl) ? close_impl(file_desc) : ::close(file_desc);
    if (rc < 0)
    {
        // In test mode, map to exception
        throw std::system_error(errno, std::generic_category(), "mbox_close(): hook failed");
    }
#else
    if (file_desc >= 0)
    {
        if (::close(file_desc) < 0)
        {
            throw std::system_error(
                errno,
                std::generic_category(),
                "mbox_close(): ::close failed");
        }
    }
#endif
}

/**
 * @brief Retrieves GPU firmware version (GET_FIRMWARE_VERSION tag).
 * @param file_desc File descriptor returned by mbox_open().
 * @return Nonzero firmware version on success.
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
uint32_t get_version(int file_desc)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    uint32_t msg[7];
    msg[0] = sizeof(msg);                                                 // total size
    msg[1] = 0;                                                           // request code
    msg[2] = static_cast<uint32_t>(MailboxTags::Tag::GetFirmwareVersion); // tag
    msg[3] = 4;                                                           // value buffer size (in bytes)
    msg[4] = 0;                                                           // req/res flag
    msg[5] = 0;                                                           // placeholder for response
    msg[6] = 0;                                                           // end tag

    int rc = (property_impl)
                 ? property_impl(file_desc, msg)
                 : real_mbox_property(file_desc, msg);
    if (rc < 0)
    {
        throw std::system_error(errno, std::generic_category(), "get_version(): hook/ioctl failed");
    }
    return msg[5];
#else
    return real_get_version(file_desc);
#endif
}

/**
 * @brief Allocates GPU memory (ALLOCATE_MEMORY tag).
 * @param file_desc File descriptor returned by mbox_open().
 * @param size      Number of bytes to allocate.
 * @param align     Alignment in bytes.
 * @param flags     Allocation flags.
 * @return Nonzero handle on success.
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (mem_alloc_impl)
    {
        int rc = mem_alloc_impl(file_desc, size, align, flags);
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "mem_alloc(): hook failed");
        return static_cast<uint32_t>(rc);
    }
    // Fall back to direct C‐style
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::AllocateMemory);
    p[i++] = 12;
    p[i++] = 12;
    p[i++] = size;
    p[i++] = align;
    p[i++] = flags;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));
    int rc = real_mbox_property(file_desc, p);
    if (rc < 0 || p[5] == 0)
    {
        throw std::system_error(errno, std::generic_category(), "mem_alloc(): C‐style failed");
    }
    return p[5];
#else
    return real_mem_alloc(file_desc, size, align, flags);
#endif
}

/**
 * @brief Frees GPU memory (RELEASE_MEMORY tag).
 * @param file_desc File descriptor returned by mbox_open().
 * @param handle    Handle returned by mem_alloc().
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
void mem_free(int file_desc, uint32_t handle)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (mem_free_impl)
    {
        int rc = mem_free_impl(file_desc, handle);
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "mem_free(): hook failed");
        return;
    }
    // Fall back to direct C‐style
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::ReleaseMemory);
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));
    int rc = real_mbox_property(file_desc, p);
    if (rc < 0)
    {
        throw std::system_error(errno, std::generic_category(), "mem_free(): C‐style failed");
    }
    return;
#else
    real_mem_free(file_desc, handle);
#endif
}

/**
 * @brief Locks GPU memory (LOCK_MEMORY tag).
 * @param file_desc File descriptor returned by mbox_open().
 * @param handle    Handle returned by mem_alloc().
 * @return Bus‐address handle (>0) on success.
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
uint32_t mem_lock(int file_desc, uint32_t handle)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (mem_lock_impl)
    {
        int rc = mem_lock_impl(file_desc, handle);
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "mem_lock(): hook failed");
        return static_cast<uint32_t>(rc);
    }
    // Fall back to direct C‐style
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::LockMemory);
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));
    int rc = real_mbox_property(file_desc, p);
    if (rc < 0 || p[5] == 0)
    {
        throw std::system_error(errno, std::generic_category(), "mem_lock(): C‐style failed");
    }
    return p[5];
#else
    return real_mem_lock(file_desc, handle);
#endif
}

/**
 * @brief Unlocks GPU memory (UNLOCK_MEMORY tag).
 * @param file_desc File descriptor returned by mbox_open().
 * @param handle    Handle returned by mem_alloc().
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
void mem_unlock(int file_desc, uint32_t handle)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (mem_unlock_impl)
    {
        int rc = mem_unlock_impl(file_desc, handle);
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "mem_unlock(): hook failed");
        return;
    }
    // Fall back to direct C‐style
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::UnlockMemory);
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));
    int rc = real_mbox_property(file_desc, p);
    if (rc < 0)
    {
        throw std::system_error(errno, std::generic_category(), "mem_unlock(): C‐style failed");
    }
    return;
#else
    real_mem_unlock(file_desc, handle);
#endif
}

/**
 * @brief Maps physical memory via `/dev/mem`.
 * @param base Physical base address to map.
 * @param size Number of bytes to map.
 * @return Pointer on success.
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
void *mapmem(uint32_t base, size_t size)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (mapmem_impl)
    {
        int rc = mapmem_impl(base, size);
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "mapmem(): hook failed");
        // In hook scenario, we assume the hook itself did the mmap if it returned >=0; here return dummy
        return reinterpret_cast<void *>(static_cast<uintptr_t>(rc));
    }
    // Fall back to direct C‐style
    int fd = (get_mem_fd_impl) ? get_mem_fd_impl() : get_shared_mem_fd();
    if (fd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "mapmem(): get_mem_fd hook failed");
    }
    long page_l = sysconf(_SC_PAGESIZE);
    size_t page = (page_l < 0 ? 4096u : static_cast<size_t>(page_l));
    size_t offset = base % page;
    off_t aligned = static_cast<off_t>(base - offset);
    void *mapping = ::mmap(nullptr, size + offset, PROT_READ | PROT_WRITE, MAP_SHARED, fd, aligned);
    if (mapping == MAP_FAILED)
    {
        throw std::system_error(errno, std::generic_category(), "mapmem(): C‐style mmap failed");
    }
    return static_cast<uint8_t *>(mapping) + offset;
#else
    return real_mapmem(base, size);
#endif
}

/**
 * @brief Unmaps a region previously mapped by mapmem().
 * @param addr Pointer returned by mapmem().
 * @param size Same size passed into mapmem().
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
void unmapmem(void *addr, size_t size)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (unmapmem_impl)
    {
        int rc = unmapmem_impl(addr, size);
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "unmapmem(): hook failed");
        return;
    }
    // Fall back to direct C‐style
    if (!addr)
        return;
    long page_l = sysconf(_SC_PAGESIZE);
    size_t page = (page_l < 0 ? 4096u : static_cast<size_t>(page_l));
    uintptr_t addr_u = reinterpret_cast<uintptr_t>(addr);
    size_t offset = addr_u % page;
    void *map_base = reinterpret_cast<void *>(addr_u - offset);
    size_t map_len = size + offset;
    if (::munmap(map_base, map_len) < 0)
    {
        throw std::system_error(errno, std::generic_category(), "unmapmem(): C‐style munmap failed");
    }
    return;
#else
    real_unmapmem(addr, size);
#endif
}

/**
 * @brief Releases (closes) the cached `/dev/mem` FD.
 * @throws std::system_error on failure (real mode only or hook returning error).
 */
void mem_cleanup(void)
{
#ifdef ENABLE_MBOX_TEST_HOOKS
    if (mem_cleanup_impl)
    {
        int rc = mem_cleanup_impl();
        if (rc < 0)
            throw std::system_error(errno, std::generic_category(), "mem_cleanup(): hook failed");
        return;
    }
    // Fall back to direct C‐style
    if (s_mem_fd >= 0)
    {
        ::close(s_mem_fd);
        s_mem_fd = -1;
    }
    return;
#else
    real_mem_cleanup();
#endif
}

/*==============================================================================
   “REAL” (non‐hooked) IMPLEMENTATIONS
==============================================================================*/

/**
 * @brief Wrapper around ::open(), so hooks can override if needed.
 */
static int real_open_wrapper(const char *path, int flags)
{
    return ::open(path, flags);
}

/**
 * @brief Sends a mailbox property buffer via IOCTL().
 * @param file_desc Mailbox FD from mbox_open().
 * @param buf       Pointer to the property message buffer.
 * @return >=0 on success; -1 on error (errno set by ioctl).
 */
static int real_mbox_property(int file_desc, void *buf)
{
    if (buf == nullptr)
    {
        errno = EINVAL;
        return -1;
    }
    int ret = ::ioctl(file_desc, IOCTL_MBOX_PROPERTY, buf);

#ifdef DEBUG_MAILBOX
    uint32_t *p = reinterpret_cast<uint32_t *>(buf);
    size_t words = *reinterpret_cast<uint32_t *>(buf) / sizeof(uint32_t);
    for (size_t i = 0; i < words; ++i)
    {
        std::printf("%04zx: 0x%08x\n", i * sizeof(*p), p[i]);
    }
#endif

    return (ret < 0) ? -1 : ret;
}

#ifndef ENABLE_MBOX_TEST_HOOKS

/**
 * @brief Queries GPU firmware version (GET_FIRMWARE_VERSION tag).
 * @param file_desc Mailbox FD from mbox_open().
 * @return Nonzero version on success; throws std::system_error on error.
 */
static uint32_t real_get_version(int file_desc)
{
    uint32_t msg[7];
    msg[0] = sizeof(msg);
    msg[1] = 0;
    msg[2] = static_cast<uint32_t>(MailboxTags::Tag::GetFirmwareVersion);
    msg[3] = 4;
    msg[4] = 0;
    msg[5] = 0;
    msg[6] = 0;

    if (real_mbox_property(file_desc, msg) < 0)
    {
        errno = EIO;
        return 0;
    }
    return msg[5];
}

#endif

/**
 * @brief Allocates GPU memory (ALLOCATE_MEMORY tag).
 * @throws std::system_error on failure (real mode only), or sets errno+returns 0 (test mode).
 */
static uint32_t real_mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags)
{
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::AllocateMemory);
    p[i++] = 12;
    p[i++] = 12;
    p[i++] = size;
    p[i++] = align;
    p[i++] = flags;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    if (real_mbox_property(file_desc, p) < 0)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "mem_alloc(): real_mbox_property failed");
    }
    if (p[5] == 0)
    {
        throw std::system_error(
            EIO,
            std::generic_category(),
            "mem_alloc(): firmware returned 0 handle");
    }
    return p[5];
}

/**
 * @brief Frees GPU memory (RELEASE_MEMORY tag).
 * @throws std::system_error on failure (real mode only).
 */
static void real_mem_free(int file_desc, uint32_t handle)
{
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::ReleaseMemory);
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    if (real_mbox_property(file_desc, p) < 0)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "mem_free(): real_mbox_property failed");
    }
}

/**
 * @brief Locks GPU memory (LOCK_MEMORY tag) to obtain a bus address.
 * @return Bus‐address handle (>0) on success; throws on failure.
 */
static uint32_t real_mem_lock(int file_desc, uint32_t handle)
{
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::LockMemory);
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    if (real_mbox_property(file_desc, p) < 0)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "mem_lock(): real_mbox_property failed");
    }
    if (p[5] == 0)
    {
        throw std::system_error(
            EPROTO,
            std::generic_category(),
            "mem_lock(): firmware returned 0");
    }
    return p[5];
}

/**
 * @brief Unlocks GPU memory (UNLOCK_MEMORY tag).
 * @throws std::system_error on failure (real mode only).
 */
static void real_mem_unlock(int file_desc, uint32_t handle)
{
    uint32_t p[32];
    size_t i = 0;
    p[i++] = 0;
    p[i++] = 0;
    p[i++] = static_cast<uint32_t>(MailboxTags::Tag::UnlockMemory);
    p[i++] = 4;
    p[i++] = 4;
    p[i++] = handle;
    p[i++] = 0;
    p[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    if (real_mbox_property(file_desc, p) < 0)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "mem_unlock(): real_mbox_property failed");
    }
}

/**
 * @brief Maps physical memory via `/dev/mem`.
 *
 * Throws on error (real mode); returns nullptr + sets errno on error (test mode).
 */
static void *real_mapmem(uint32_t base, size_t size)
{
    int fd = get_shared_mem_fd(); // throws if open("/dev/mem") fails

    // Determine page size
    long page_l = sysconf(_SC_PAGESIZE);
    size_t page = (page_l < 0 ? 4096u : static_cast<size_t>(page_l));
    size_t offset = base % page;
    off_t aligned = static_cast<off_t>(base - offset);

    // Do the actual mmap
    void *mapping = ::mmap(
        nullptr,
        size + offset,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        aligned);
    if (mapping == MAP_FAILED)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "mapmem(): mmap failed");
    }

    // Return pointer offset into the mapping region
    return static_cast<uint8_t *>(mapping) + offset;
}

/**
 * @brief Unmaps a region previously mapped by real_mapmem().
 * @param addr Pointer returned by real_mapmem().
 * @param size Same size passed into real_mapmem().
 * @throws std::system_error on failure (real mode only).
 */
static void real_unmapmem(void *addr, size_t size)
{
    if (!addr)
        return;

    long page_l = sysconf(_SC_PAGESIZE);
    size_t page = (page_l < 0 ? 4096u : static_cast<size_t>(page_l));
    uintptr_t addr_u = reinterpret_cast<uintptr_t>(addr);
    size_t offset = addr_u % page;
    void *map_base = reinterpret_cast<void *>(addr_u - offset);
    size_t map_len = size + offset;

    if (::munmap(map_base, map_len) < 0)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "unmapmem(): munmap failed");
    }
}

/**
 * @brief Cleans up (closes) the cached `/dev/mem` FD.
 *        Registered via atexit(); safe to call multiple times.
 */
static void real_mem_cleanup(void)
{
    if (s_mem_fd >= 0)
    {
        ::close(s_mem_fd);
        s_mem_fd = -1;
    }
}