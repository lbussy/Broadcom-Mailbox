/**
 * @file mailbox.h
 * @brief Header file for mailbox communication with the Raspberry Pi GPU.
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

#ifndef MAILBOX_H
#define MAILBOX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Opens the mailbox device for communication.
     *
     * @return File descriptor for the mailbox device, or -1 if opening fails.
     */
    int mbox_open();

    /**
     * @brief Closes the mailbox device.
     *
     * @param file_desc File descriptor returned by mbox_open().
     */
    void mbox_close(int file_desc);

    /**
     * @brief Gets the version of the mailbox interface.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @return Version of the mailbox interface.
     */
    uint32_t get_version(int file_desc);

    /**
     * @brief Allocates memory using the mailbox interface.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param size Size of memory to allocate in bytes.
     * @param align Alignment of memory.
     * @param flags Flags specifying memory properties.
     * @return Handle to the allocated memory.
     */
    uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);

    /**
     * @brief Frees previously allocated memory.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle Handle to the memory to free.
     * @return Result of the operation (0 for error, non-zero for success).
     */
    uint32_t mem_free(int file_desc, uint32_t handle);

    /**
     * @brief Locks allocated memory.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle Handle to the memory to lock.
     * @return Result of the operation (handle on success).
     */
    uint32_t mem_lock(int file_desc, uint32_t handle);

    /**
     * @brief Unlocks locked memory.
     *
     * @param file_desc File descriptor returned by mbox_open().
     * @param handle Handle to the memory to unlock.
     * @return Result of the operation (0 for error, non-zero for success).
     */
    uint32_t mem_unlock(int file_desc, uint32_t handle);

    /**
     * @brief Maps physical memory into the process’s address space.
     * @param base  Physical base address to map.
     * @param size  Number of bytes to map.
     * @return On success, pointer to [base…base+size); NULL on failure.
     */
    void *mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmaps a region previously mapped by mapmem().
     * @param addr  Pointer returned by mapmem().
     * @param size  Same size passed into mapmem().
     */
    void unmapmem(void *addr, size_t size);

    /**
     * @brief Explicitly cleans up the /dev/mem file descriptor.
     *
     * Clients can call this to release the cached descriptor obtained via
     * get_mem_fd(). If the descriptor is valid, it is closed; otherwise,
     * the function does nothing. Safe to call multiple times.
     */
    void mem_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // MAILBOX_H
