/**
 * @file mailbox.h
 * @brief Mailbox property‐interface API for communicating with the Raspberry Pi GPU.
 *
 * @details
 * This header defines the constants, types, and function prototypes needed to
 * interact with the Raspberry Pi’s VideoCore GPU via the mailbox property‐interface.
 * It allows clients to:
 *   - Open and close the `/dev/vcio` mailbox device.
 *   - Query the GPU firmware version.
 *   - Allocate, lock, unlock, and free contiguous GPU‐accessible memory.
 *   - Map and unmap physical memory regions through `/dev/mem`.
 *   - (Optionally) install test hooks to override low‐level I/O calls, enabling
 *     unit tests without actual hardware access when `ENABLE_MBOX_TEST_HOOKS` is defined.
 *
 * The mailbox property‐interface is documented at:
 *   https://github.com/raspberrypi/firmware/wiki/Mailboxes
 *   https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface
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

#ifndef MAILBOX_H
#define MAILBOX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Mailbox property‐interface tag IDs.
     *
     * These tags are placed into the 32‐bit mailbox buffer that is sent to the
     * VideoCore GPU. Each tag instructs the GPU to perform a different property‐
     * interface operation:
     *   - TAG_GET_FIRMWARE_VERSION: Query the GPU firmware version.
     *   - TAG_ALLOCATE_MEMORY:       Allocate a contiguous block of GPU memory.
     *   - TAG_LOCK_MEMORY:           Lock a previously allocated GPU memory block.
     *   - TAG_UNLOCK_MEMORY:         Unlock a locked GPU memory block.
     *   - TAG_RELEASE_MEMORY:        Release (free) a previously allocated GPU memory block.
     */
    enum
    {
        TAG_GET_FIRMWARE_VERSION = 0x00000001, /**< Get firmware version */
        TAG_ALLOCATE_MEMORY = 0x3000c,         /**< Allocate contiguous GPU memory */
        TAG_LOCK_MEMORY = 0x3000d,             /**< Lock GPU memory to obtain a bus address */
        TAG_UNLOCK_MEMORY = 0x3000e,           /**< Unlock previously locked GPU memory */
        TAG_RELEASE_MEMORY = 0x3000f           /**< Free previously allocated GPU memory */
    };

    /**
     * @brief Opens the mailbox device for communication with VideoCore.
     *
     * @return File descriptor (>=0) on success; -1 on error (errno is set).
     */
    int mbox_open(void);

    /**
     * @brief Closes the mailbox device.
     *
     * @param file_desc File descriptor that was returned by mbox_open().
     */
    void mbox_close(int file_desc);

    /**
     * @brief Retrieves the GPU firmware version via the mailbox interface.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @return Nonzero firmware version on success; 0 on error (errno=EIO).
     */
    uint32_t get_version(int file_desc);

    /**
     * @brief Allocates GPU‐accessible memory using the mailbox interface.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param size      Number of bytes to allocate.
     * @param align     Required alignment in bytes.
     * @param flags     Allocation flags (e.g., caching and permission bits).
     * @return Nonzero handle on success; 0 on error (errno=EIO).
     */
    uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);

    /**
     * @brief Frees GPU memory that was previously allocated by mem_alloc().
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle    Handle returned by a prior mem_alloc() call.
     * @return 0 on success;
     *         nonzero on firmware‐level error;
     *         0 on ioctl failure (errno is set to EIO).
     */
    uint32_t mem_free(int file_desc, uint32_t handle);

    /**
     * @brief Locks a previously allocated GPU memory block to obtain a bus address.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle    Handle returned by a prior mem_alloc() call.
     * @return Bus‐address handle (>0) on success; 0 on error (errno is set).
     */
    uint32_t mem_lock(int file_desc, uint32_t handle);

    /**
     * @brief Unlocks a GPU memory block that was previously locked by mem_lock().
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle    Handle returned by a prior mem_alloc() call.
     * @return 0 on success;
     *         nonzero on firmware‐level error;
     *         0 on ioctl failure (errno is set to EIO).
     */
    uint32_t mem_unlock(int file_desc, uint32_t handle);

    /**
     * @brief Maps a physical memory region into this process’s address space.
     *
     * @param base  Physical base address to map.
     * @param size  Number of bytes to map.
     * @return Pointer to the mapped region on success; NULL on error (errno is set).
     */
    void *mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmaps a region that was previously mapped by mapmem().
     *
     * @param addr Pointer returned by a prior mapmem() call.
     * @param size Number of bytes that were passed into mapmem().
     */
    void unmapmem(void *addr, size_t size);

    /**
     * @brief Releases (closes) the cached /dev/mem file descriptor.
     *
     * @details This function can be called multiple times safely.  It is also
     * registered via atexit() automatically, so the descriptor is closed on exit.
     */
    void mem_cleanup(void);

#ifdef ENABLE_MBOX_TEST_HOOKS

    /**
     * @brief Override the internal mailbox‐property ioctl() function.
     *
     * After calling this, any future property‐interface calls (e.g., get_version,
     * mem_alloc, mem_lock, etc.) will invoke `hook(int fd, void *buf)` instead of
     * performing the real ioctl.  Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real ioctl.
     *             - If non‐NULL, all subsequent mailbox‐property calls go through this hook.
     *             - If NULL, the implementation reverts to the real ioctl logic.
     */
    void mailbox_set_property_hook(int (*hook)(int, void *));

    /**
     * @brief Override the internal open() used by mbox_open().
     *
     * After calling this, `mbox_open()` will call `hook(path, flags)` instead of
     * `open("/dev/vcio", O_RDWR)`.  Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real open().
     *             - If non‐NULL, `mbox_open()` calls this hook with the provided path and flags.
     *             - If NULL, `mbox_open()` reverts to calling `open("/dev/vcio", O_RDWR)`.
     */
    void mailbox_set_open_hook(int (*hook)(const char *, int));

    /**
     * @brief Override the function used to open /dev/mem.
     *
     * After calling this, `get_mem_fd()` will invoke `hook()` instead of calling
     * `open("/dev/mem", O_RDWR | O_SYNC)`.  Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real get_mem_fd().
     *             - If non‐NULL, `get_mem_fd()` calls this hook.
     *             - If NULL, `get_mem_fd()` reverts to the real open("/dev/mem") logic.
     */
    void mailbox_set_mem_fd_hook(int (*hook)(void));

    /**
     * @brief Override mbox_close().
     *
     * After calling this, `mbox_close(fd)` will invoke `hook(fd)` instead of
     * `close(fd)`.  Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real close().
     *             - If non‐NULL, `mbox_close(fd)` calls this hook.
     *             - If NULL, `mbox_close(fd)` reverts to calling `close(fd)`.
     */
    void mailbox_set_close_hook(void (*hook)(int));

    /**
     * @brief Override get_version().
     *
     * After calling this, `get_version(fd)` will call `hook(fd)` instead of the
     * real mailbox‐property logic.  Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real get_version().
     *             - If non‐NULL, `get_version(fd)` calls this hook.
     *             - If NULL, `get_version(fd)` reverts to the real implementation.
     */
    void mailbox_set_get_version_hook(uint32_t (*hook)(int));

    /**
     * @brief Override mem_alloc().
     *
     * After calling this, `mem_alloc(fd, size, align, flags)` will call
     * `hook(fd, size, align, flags)` instead of the real mailbox‐property logic.
     * Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real mem_alloc().
     *             - If non‐NULL, `mem_alloc(fd, size, align, flags)` calls this hook.
     *             - If NULL, `mem_alloc(...)` reverts to the real implementation.
     */
    void mailbox_set_mem_alloc_hook(uint32_t (*hook)(int, uint32_t, uint32_t, uint32_t));

    /**
     * @brief Override mem_free().
     *
     * After calling this, `mem_free(fd, handle)` will call `hook(fd, handle)` instead
     * of the real mailbox‐property logic.  Passing NULL restores the default behavior.
     *
     * @param hook Function pointer to use in place of the real mem_free().
     *             - If non‐NULL, `mem_free(fd, handle)` calls this hook.
     *             - If NULL, `mem_free(...)` reverts to the real implementation.
     */
    void mailbox_set_mem_free_hook(uint32_t (*hook)(int, uint32_t));

    /**
     * @brief Override mem_lock().
     *
     * After calling this, `mem_lock(fd, handle)` will call `hook(fd, handle)` instead
     * of the real mailbox‐property logic.  Passing NULL restores default behavior.
     *
     * @param hook Function pointer to use in place of the real mem_lock().
     *             - If non‐NULL, `mem_lock(fd, handle)` calls this hook.
     *             - If NULL, `mem_lock(...)` reverts to the real implementation.
     */
    void mailbox_set_mem_lock_hook(uint32_t (*hook)(int, uint32_t));

    /**
     * @brief Override mem_unlock().
     *
     * After calling this, `mem_unlock(fd, handle)` will call `hook(fd, handle)` instead
     * of the real mailbox‐property logic.  Passing NULL restores default behavior.
     *
     * @param hook Function pointer to use in place of the real mem_unlock().
     *             - If non‐NULL, `mem_unlock(fd, handle)` calls this hook.
     *             - If NULL, `mem_unlock(...)` reverts to the real implementation.
     */
    void mailbox_set_mem_unlock_hook(uint32_t (*hook)(int, uint32_t));

    /**
     * @brief Override mapmem().
     *
     * After calling this, `mapmem(base, size)` will call `hook(base, size)` instead
     * of the real logic that mmaps `/dev/mem`.  Passing NULL restores default behavior.
     *
     * @param hook Function pointer to use in place of the real mapmem().
     *             - If non‐NULL, `mapmem(base, size)` calls this hook.
     *             - If NULL, `mapmem(...)` reverts to the real implementation.
     */
    void mailbox_set_mapmem_hook(void *(*hook)(uint32_t, size_t));

    /**
     * @brief Override unmapmem().
     *
     * After calling this, `unmapmem(addr, size)` will call `hook(addr, size)` instead
     * of the real logic that unmaps memory.  Passing NULL restores default behavior.
     *
     * @param hook Function pointer to use in place of the real unmapmem().
     *             - If non‐NULL, `unmapmem(addr, size)` calls this hook.
     *             - If NULL, `unmapmem(...)` reverts to the real implementation.
     */
    void mailbox_set_unmapmem_hook(void (*hook)(void *, size_t));

    /**
     * @brief Override mem_cleanup().
     *
     * After calling this, `mem_cleanup()` will call `hook()` instead of closing the
     * cached `/dev/mem` file descriptor.  Passing NULL restores default behavior.
     *
     * @param hook Function pointer to use in place of the real mem_cleanup().
     *             - If non‐NULL, `mem_cleanup()` calls this hook.
     *             - If NULL, `mem_cleanup()` reverts to the real implementation.
     */
    void mailbox_set_mem_cleanup_hook(void (*hook)(void));

#endif // ENABLE_MBOX_TEST_HOOKS

#ifdef __cplusplus
}
#endif

#endif // MAILBOX_H
