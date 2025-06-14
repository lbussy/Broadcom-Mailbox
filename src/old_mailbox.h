#ifndef _OLD_MAILBOX_H
#define _OLD_MAILBOX_H

// C Standard Library
#include <stdint.h>         // fixed-width integer types

// POSIX/system headers
#include <linux/ioctl.h>    // ioctl definitions for mailbox

/** New kernel version (>= 4.1) major device number. */
#define MAJOR_NUM_A 249
/** Older kernel version major device number. */
#define MAJOR_NUM_B 100
/** IOCTL command for mailbox property interface. */
#define IOCTL_MBOX_PROPERTY _IOWR(MAJOR_NUM_B, 0, char *)
/** Name of the mailbox device file. */
#define DEVICE_FILE_NAME "/dev/vcio"

#ifdef __cplusplus
extern "C" {
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
 * @brief Maps physical memory into the process's address space.
 *
 * @param base Base address of the memory to map.
 * @param size Size of the memory region to map in bytes.
 * @return Pointer to the mapped memory region.
 */
void *mapmem(uint32_t base, uint32_t size);

/**
 * @brief Unmaps memory previously mapped with mapmem().
 *
 * @param addr Pointer to the mapped memory.
 * @param size Size of the mapped memory region in bytes.
 */
void unmapmem(void *addr, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // _OLD_MAILBOX_H
