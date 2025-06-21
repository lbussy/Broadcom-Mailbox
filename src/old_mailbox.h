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

/** Name of the memory device file. */
#define MEM_FILE_NAME "/dev/mem"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Maps physical memory into the process's address space.
 *
 * @param base Base address of the memory to map.
 * @param size Size of the memory region to map in bytes.
 * @return Pointer to the mapped memory region.
 */
volatile uint8_t *mapmem(uint32_t base, uint32_t size);

/**
 * @brief Unmaps memory previously mapped with mapmem().
 *
 * @param addr Pointer to the mapped memory.
 * @param size Size of the mapped memory region in bytes.
 */
void unmapmem(volatile uint8_t *addr, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif // _OLD_MAILBOX_H
