# Mailbox Review

### Internal

- `#define IOCTL_MBOX_PROPERTY _IOWR(100, 0, char *)`

### External

- `mbox_open()`
- `mbox_close()`
- `uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);`
- `uint32_t mem_free(int file_desc, uint32_t handle);`
- `uint32_t mem_lock(int file_desc, uint32_t handle);`
- `uint32_t mem_unlock(int file_desc, uint32_t handle);`
- `void *mapmem(uint32_t base, uint32_t size);`
- `void unmapmem(void *addr, uint32_t size);`

