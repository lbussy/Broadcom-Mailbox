/**
 * @file mailbox.hpp
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

#ifndef _MAILBOX_HPP
#define _MAILBOX_HPP

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * @brief Opens the mailbox device for communication with VideoCore.
     *
     * On the first call, opens `/dev/vcio` exactly once (thread‐safe).
     * On subsequent calls, returns the same FD.
     *
     * @return File descriptor (>=0) on success; throws std::system_error on failure.
     */
    int mbox_open(void);

    /**
     * @brief Closes the mailbox device.
     *
     * Decrements an internal reference‐count (if implemented). The default here
     * simply calls ::close() on the shared FD (no refcount).
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @throws std::system_error on underlying close() error.
     */
    void mbox_close(int file_desc);

    /**
     * @brief Retrieves the GPU firmware version via the mailbox interface.
     *
     * Synchronously performs a mailbox‐property IOCTL with the GET_FIRMWARE_VERSION tag.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @return Nonzero firmware version on success; throws std::system_error on error.
     */
    uint32_t get_version(int file_desc);

    /**
     * @brief Allocates GPU‐accessible memory via the mailbox property interface.
     *
     * Sends an ALLOCATE_MEMORY tag requesting a contiguous GPU memory block.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param size      Number of bytes to allocate.
     * @param align     Required alignment in bytes.
     * @param flags     Allocation flags (e.g., caching, permissions).
     * @return Nonzero handle on success; throws std::system_error on error.
     */
    uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);

    /**
     * @brief Frees GPU memory previously allocated by mem_alloc().
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle    Handle returned by a prior mem_alloc() call.
     * @throws std::system_error on underlying IOCTL failure.
     */
    void mem_free(int file_desc, uint32_t handle);

    /**
     * @brief Locks a previously allocated GPU memory block to obtain a bus address.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle    Handle returned by a prior mem_alloc() call.
     * @return Bus‐address handle (>0) on success; throws std::system_error on error.
     */
    uint32_t mem_lock(int file_desc, uint32_t handle);

    /**
     * @brief Unlocks a GPU memory block that was previously locked by mem_lock().
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle    Handle returned by a prior mem_alloc() call.
     * @throws std::system_error on underlying IOCTL failure.
     */
    void mem_unlock(int file_desc, uint32_t handle);

    /**
     * @brief Maps a physical memory region into this process’s address space.
     *
     * Internally calls a thread‐safe open of `/dev/mem` exactly once, then mmap().
     *
     * @param base  Physical base address to map.
     * @param size  Number of bytes to map.
     * @return Pointer to the mapped region on success; throws std::system_error on error.
     */
    void *mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmaps a region that was previously mapped by mapmem().
     *
     * @param addr Pointer returned by mapmem().
     * @param size Number of bytes that were passed into mapmem().
     * @throws std::system_error on underlying munmap() failure.
     */
    void unmapmem(void *addr, size_t size);

    /**
     * @brief Releases (closes) the cached `/dev/mem` file descriptor.
     *
     * Safe to call multiple times. Registered via atexit() internally.
     */
    void mem_cleanup(void);

#ifdef ENABLE_MBOX_TEST_HOOKS

    /**
     * @brief Override the internal mailbox‐property IOCTL() function.
     *
     * @param hook If non‐NULL, future calls to get_version(), mem_alloc(), etc.
     *             will invoke `hook(int fd, void *buf)` instead of the real IOCTL.
     *             Passing NULL restores real behavior.
     */
    void mailbox_set_property_hook(int (*hook)(int, void *));

    /**
     * @brief Override the internal open() used by mbox_open().
     *
     * @param hook If non‐NULL, mbox_open() calls `hook(path, flags)` instead of the real ::open().
     *             Passing NULL restores real open("/dev/vcio", O_RDWR).
     */
    void mailbox_set_open_hook(int (*hook)(const char *, int));

    /**
     * @brief Override the function used to open `/dev/mem`.
     *
     * @param hook If non‐NULL, get_mem_fd() calls `hook()` instead of the real open("/dev/mem", …).
     *             Passing NULL restores the real behavior.
     */
    void mailbox_set_mem_fd_hook(int (*hook)(void));

    /**
     * @brief Override mbox_close().
     *
     * @param hook If non‐NULL, mbox_close(fd) will invoke `hook(fd)` instead of the real close().
     *             Passing NULL restores real close().
     */
    void mailbox_set_close_hook(int (*hook)(int));

    /**
     * @brief Override get_version().
     *
     * @param hook If non‐NULL, get_version(fd) calls `hook(fd)` instead of real logic.
     *             Passing NULL restores real get_version().
     */
    void mailbox_set_get_version_hook(uint32_t (*hook)(int));

    /**
     * @brief Override mem_alloc().
     *
     * @param hook If non‐NULL, mem_alloc(fd, size, align, flags) calls `hook(...)` instead of real logic.
     *             Passing NULL restores real mem_alloc().
     */
    void mailbox_set_mem_alloc_hook(uint32_t (*hook)(int, uint32_t, uint32_t, uint32_t));

    /**
     * @brief Override mem_free().
     *
     * @param hook If non‐NULL, mem_free(fd, handle) calls `hook(...)` instead of real logic.
     *             Passing NULL restores real mem_free().
     */
    void mailbox_set_mem_free_hook(uint32_t (*hook)(int, uint32_t));

    /**
     * @brief Override mem_lock().
     *
     * @param hook If non‐NULL, mem_lock(fd, handle) calls `hook(...)` instead of real logic.
     *             Passing NULL restores real mem_lock().
     */
    void mailbox_set_mem_lock_hook(uint32_t (*hook)(int, uint32_t));

    /**
     * @brief Override mem_unlock().
     *
     * @param hook If non‐NULL, mem_unlock(fd, handle) calls `hook(...)` instead of real logic.
     *             Passing NULL restores real mem_unlock().
     */
    void mailbox_set_mem_unlock_hook(uint32_t (*hook)(int, uint32_t));

    /**
     * @brief Override mapmem().
     *
     * @param hook If non‐NULL, mapmem(base, size) calls `hook(...)` instead of real logic.
     *             Passing NULL restores real mapmem().
     */
    void mailbox_set_mapmem_hook(void *(*hook)(uint32_t, size_t));

    /**
     * @brief Override unmapmem().
     *
     * @param hook If non‐NULL, unmapmem(addr, size) calls `hook(...)` instead of real logic.
     *             Passing NULL restores real unmapmem().
     */
    void mailbox_set_unmapmem_hook(void (*hook)(void *, size_t));

    /**
     * @brief Override mem_cleanup().
     *
     * @param hook If non‐NULL, mem_cleanup() calls `hook()` instead of real logic.
     *             Passing NULL restores real mem_cleanup().
     */
    void mailbox_set_mem_cleanup_hook(void (*hook)(void));

#endif // ENABLE_MBOX_TEST_HOOKS

#ifdef __cplusplus
} // extern "C"
#endif

#ifdef __cplusplus

namespace MailboxTags {
    enum class Tag : uint32_t {
        GetFirmwareVersion = 0x00000001,
        AllocateMemory     = 0x3000c,
        LockMemory         = 0x3000d,
        UnlockMemory       = 0x3000e,
        ReleaseMemory      = 0x3000f
    };
}

#endif // __cplusplus

#endif // _MAILBOX_HPP