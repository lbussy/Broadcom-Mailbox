/**
 * @file mailbox.hpp
 * @brief Mailbox property‐interface API (C++17) for communicating with the
 *        Raspberry Pi GPU.
 *
 * @details
 *   - Open/close `/dev/vcio`
 *   - Query GPU firmware version
 *   - Allocate/lock/unlock/free GPU memory
 *   - Map/unmap physical memory via `/dev/mem`
 *   - Optional debug output and test‐hook support
 *
 * @copyright © 2025 Lee C. Bussy (@LBussy). All rights reserved.
 *
 * @license
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _MAILBOX_HPP
#define _MAILBOX_HPP

#include <cstddef>      // Needed for size_t and std::byte
#include <cstdint>      // Needed for uint32_t, uint64_t, etc.
#include <mutex>        // Needed for std::mutex member (init_mutex_)
#include <system_error> // Needed to mention/throw std::system_error in the documentation

#include <sys/mman.h>   // Needed for ::munmap() in MappedRegion::cleanup()
#include <unistd.h>     // Needed for ::close() in FileDescriptor’s destructor and reset()

namespace MailboxTags
{
    /**
     * @enum MailboxTags::Tag
     * @brief Tags used in mailbox property interface calls.
     *
     * These tags correspond to GPU property commands.
     */
    enum class Tag : uint32_t
    {
        GetFirmwareVersion = 0x00000001,  ///< Retrieve GPU firmware version
        AllocateMemory      = 0x3000c,    ///< Allocate GPU memory
        LockMemory          = 0x3000d,    ///< Lock allocated memory to get bus address
        UnlockMemory        = 0x3000e,    ///< Unlock previously locked memory
        ReleaseMemory       = 0x3000f     ///< Release previously allocated memory
    };
}

/**
 * @class FileDescriptor
 * @brief RAII wrapper around a raw POSIX file descriptor.
 *
 * Automatically closes the descriptor in the destructor. Non‐copyable, movable.
 */
class FileDescriptor
{
public:
    /**
     * @brief Construct with an optional raw descriptor.
     * @param fd  Raw file descriptor (default: -1 for “no descriptor”).
     */
    explicit FileDescriptor(int fd = -1) noexcept
        : fd_{fd}
    {
    }

    /**
     * @brief Close the descriptor if valid.
     */
    ~FileDescriptor() noexcept
    {
        if (fd_ >= 0)
        {
            ::close(fd_);
        }
    }

    FileDescriptor(const FileDescriptor &) = delete;            ///< Non‐copyable
    FileDescriptor &operator=(const FileDescriptor &) = delete; ///< Non‐copyable

    /**
     * @brief Move‐construct from another wrapper.
     * @param other  Other wrapper to take ownership from.
     */
    FileDescriptor(FileDescriptor &&other) noexcept
        : fd_{other.fd_}
    {
        other.fd_ = -1;
    }

    /**
     * @brief Move‐assign from another wrapper.
     * @param other  Other wrapper to take ownership from.
     * @return Reference to this.
     */
    FileDescriptor &operator=(FileDescriptor &&other) noexcept
    {
        if (this != &other)
        {
            if (fd_ >= 0)
            {
                ::close(fd_);
            }
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    /**
     * @brief Get the raw descriptor.
     * @return Raw file descriptor, or -1 if none.
     */
    int get() const noexcept { return fd_; }

    /**
     * @brief Reset to a new descriptor, closing the old one if valid.
     * @param new_fd  New raw descriptor (default: -1).
     */
    void reset(int new_fd = -1) noexcept
    {
        if (fd_ >= 0)
        {
            ::close(fd_);
        }
        fd_ = new_fd;
    }

private:
    int fd_; ///< Underlying file descriptor.
};

/**
 * @class MappedRegion
 * @brief RAII wrapper around a memory‐mapped region.
 *
 * Takes ownership of a pointer returned by mmap (or a fake‐hook). On destruction,
 * it unmaps via munmap if still valid. Non‐copyable, movable.
 */
class MappedRegion
{
public:
    /**
     * @brief Construct a region wrapper.
     *
     * @param addr  Pointer returned by mmap. nullptr indicates failure or no mapping.
     * @param size  Length of the mapping (must match the size originally passed to mmap).
     */
    MappedRegion(void *addr, std::size_t size) noexcept
        : ptr_{reinterpret_cast<std::byte *>(addr)}, length_{size}
    {
    }

    MappedRegion(const MappedRegion &) = delete;            ///< Non‐copyable
    MappedRegion &operator=(const MappedRegion &) = delete; ///< Non‐copyable

    /**
     * @brief Move‐construct from another region.
     * @param other  Other region to take ownership from.
     */
    MappedRegion(MappedRegion &&other) noexcept
        : ptr_{other.ptr_}, length_{other.length_}
    {
        other.ptr_    = nullptr;
        other.length_ = 0;
    }

    /**
     * @brief Move‐assign from another region.
     * @param other  Other region to take ownership from.
     * @return Reference to this.
     */
    MappedRegion &operator=(MappedRegion &&other) noexcept
    {
        if (this != &other)
        {
            cleanup();
            ptr_    = other.ptr_;
            length_ = other.length_;
            other.ptr_    = nullptr;
            other.length_ = 0;
        }
        return *this;
    }

    /**
     * @brief Destructor: unmap if still valid.
     */
    ~MappedRegion() noexcept
    {
        cleanup();
    }

    /**
     * @brief Get the underlying mapped pointer.
     * @return `std::byte*` to the mapped region, or nullptr if mapping failed.
     */
    std::byte *get() const noexcept { return ptr_; }

    /**
     * @brief Bool conversion to check validity.
     * @return true if the mapping pointer is non‐null.
     */
    explicit operator bool() const noexcept { return ptr_ != nullptr; }

private:
    /**
     * @brief Internal cleanup: call munmap on the region if still mapped.
     */
    void cleanup() noexcept
    {
        if (ptr_)
        {
            ::munmap(static_cast<void *>(ptr_), length_);
            ptr_    = nullptr;
            length_ = 0;
        }
    }

    std::byte     *ptr_    = nullptr; ///< Mapped pointer (nullptr if none).
    std::size_t    length_ = 0;       ///< Length of the mapping.
};

/**
 * @class Mailbox
 * @brief Singleton interface to the Raspberry Pi mailbox property API.
 *
 * Provides thread‐safe, RAII‐style access to:
 *   - `/dev/vcio` for mailbox property calls
 *   - `/dev/mem` for physical memory mapping
 *   - GPU memory allocation/locking via mailbox property interface
 *   - Optional test‐hook support for unit testing
 */
class Mailbox
{
public:
    /**
     * @brief Get the singleton instance.
     * @return Reference to the unique Mailbox instance.
     */
    static Mailbox &instance();

    /**
     * @brief Enable verbose debug output for mailbox transactions.
     *
     * When enabled, each 32‐bit word sent or received over the mailbox
     * interface will be printed to stderr for debugging.
     */
    void set_debug() noexcept;

    /**
     * @brief Enter “test-hook” mode with default fake‐hook implementations.
     *
     * In test-hook mode, all low-level I/O calls (open, read/write, ioctl)
     * are routed through in-library fake functions. Call set_debug() first
     * if you wish to log the fake buffers.
     */
    void set_test_hooks() noexcept;

    /**
     * @brief Open `/dev/vcio` (mailbox) once, thread-safe.
     *
     * On the first call, opens `/dev/vcio` and caches the file descriptor.
     * Subsequent calls return the same descriptor. Throws if the open fails.
     *
     * @return Non-negative file descriptor on success.
     * @throws std::system_error if the underlying ::open fails.
     */
    [[nodiscard]] int mbox_open();

    /**
     * @brief Close a mailbox descriptor.
     *
     * Closes the given descriptor. If a test-hook is installed, routes to
     * the fake hook. Throws on underlying close() error.
     *
     * @param file_desc  Descriptor to close (returned by mbox_open()).
     * @throws std::system_error if ::close fails.
     */
    void mbox_close(int file_desc);

    /**
     * @brief Retrieve the GPU firmware version.
     *
     * Uses the mailbox property interface to query the firmware version.
     * Throws on any error.
     *
     * @param file_desc  Open mailbox descriptor (from mbox_open()).
     * @return GPU firmware version (nonzero) on success.
     * @throws std::system_error on mailbox transaction or IOCTL failure.
     */
    [[nodiscard]] uint32_t get_version(int file_desc);

    /**
     * @brief Allocate GPU-accessible memory via the mailbox property interface.
     *
     * Requests a contiguous block of physical memory from the GPU. Throws on failure.
     *
     * @param file_desc  Open mailbox descriptor.
     * @param size       Size in bytes to allocate.
     * @param align      Alignment (in bytes) for the allocation.
     * @param flags      Allocation flags (e.g., cached/non-cached).
     * @return Handle > 0 on success.
     * @throws std::system_error on mailbox transaction or IOCTL failure.
     */
    [[nodiscard]] uint32_t mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags);

    /**
     * @brief Free GPU memory previously allocated by mem_alloc().
     *
     * Frees the block identified by the handle. Throws on error.
     *
     * @param file_desc  Open mailbox descriptor.
     * @param handle     Handle returned by mem_alloc().
     * @throws std::system_error on mailbox transaction or IOCTL failure.
     */
    void mem_free(int file_desc, uint32_t handle);

    /**
     * @brief Lock a previously allocated GPU memory block to obtain a bus address.
     *
     * Locks the block and returns a bus address handle (>0). Throws on error.
     *
     * @param file_desc  Open mailbox descriptor.
     * @param handle     Handle returned by mem_alloc().
     * @return Bus address handle (>0) on success.
     * @throws std::system_error on mailbox transaction or IOCTL failure.
     */
    [[nodiscard]] uint32_t mem_lock(int file_desc, uint32_t handle);

    /**
     * @brief Unlock a GPU memory block previously locked by mem_lock().
     *
     * Unlocks the memory block. Throws on error.
     *
     * @param file_desc  Open mailbox descriptor.
     * @param handle     Handle returned by mem_lock().
     * @throws std::system_error on mailbox transaction or IOCTL failure.
     */
    void mem_unlock(int file_desc, uint32_t handle);

    /**
     * @brief Map a physical memory region into process address space.
     *
     * Uses `/dev/mem` to map physical pages. If a test-hook is installed,
     * routes to the fake hook. Throws on mmap failure.
     *
     * @param base  Physical base address to map (page-aligned).
     * @param size  Number of bytes to map (including any page offset).
     * @return MappedRegion wrapping the mapped address (std::byte*), or
     *         throws on failure.
     * @throws std::system_error if mmap fails or `/dev/mem` cannot be opened.
     */
    [[nodiscard]] MappedRegion mapmem(uint32_t base, size_t size);

    /**
     * @brief Unmap a region previously mapped by mapmem().
     *
     * This is a no‐op because MappedRegion’s destructor already calls munmap().
     *
     * @param addr  Pointer to the region (unused).
     * @param size  Length of the region (unused).
     */
    void unmapmem(void * /*unused*/, size_t /*unused*/) noexcept { /* no-op */ }

    /**
     * @brief Close the cached `/dev/mem` file descriptor if open.
     *
     * Safe to call multiple times; also registered via atexit() so that
     * the `/dev/mem` descriptor is closed at program exit.
     */
    void mem_cleanup();

private:
    Mailbox();               ///< Private constructor for singleton pattern.
    ~Mailbox();              ///< Destructor closes any open FDs.

    // Disable copy/move:
    Mailbox(const Mailbox &) = delete;
    Mailbox &operator=(const Mailbox &) = delete;
    Mailbox(Mailbox &&) = delete;
    Mailbox &operator=(Mailbox &&) = delete;

    //----------------------------------------------------------------------//
    // Internal “real” implementations for the hooks
    //----------------------------------------------------------------------//

    /**
     * @brief Real mailbox property call via ioctl.
     * @param file_desc  Open mailbox descriptor.
     * @param buf        Buffer for property message.
     * @return 0 on success.
     */
    int real_mbox_property(int file_desc, void *buf);

    //----------------------------------------------------------------------//
    // Test-hook function pointer types
    //----------------------------------------------------------------------//

    using OpenHook        = int (*)(const char *, int);
    using CloseHook       = int (*)(int);
    using VersionHook     = int (*)(int, void *);
    using MemAllocHook    = int (*)(int, uint32_t, uint32_t, uint32_t);
    using MemFreeHook     = int (*)(int, uint32_t);
    using MemLockHook     = int (*)(int, uint32_t);
    using MemUnlockHook   = int (*)(int, uint32_t);
    using MapMemHook      = int (*)(uint32_t, size_t);
    using UnmapMemHook    = int (*)(void *, size_t);
    using MemCleanupHook  = int (*)(void);

    //----------------------------------------------------------------------//
    // Test‐hook placeholders (initialized by set_test_hooks())
    //----------------------------------------------------------------------//

    OpenHook       open_impl_         = nullptr; ///< Hook for open
    CloseHook      close_impl_        = nullptr; ///< Hook for close
    VersionHook    version_impl_      = nullptr; ///< Hook for get_version
    MemAllocHook   mem_alloc_impl_    = nullptr; ///< Hook for mem_alloc
    MemFreeHook    mem_free_impl_     = nullptr; ///< Hook for mem_free
    MemLockHook    mem_lock_impl_     = nullptr; ///< Hook for mem_lock
    MemUnlockHook  mem_unlock_impl_   = nullptr; ///< Hook for mem_unlock
    MapMemHook     mapmem_impl_       = nullptr; ///< Hook for mapmem
    UnmapMemHook   unmapmem_impl_     = nullptr; ///< Hook for unmapmem
    MemCleanupHook mem_cleanup_impl_  = nullptr; ///< Hook for mem_cleanup

    //----------------------------------------------------------------------//
    // Private hook‐setters (invoked by set_test_hooks())
    //----------------------------------------------------------------------//

    void set_open_hook(OpenHook hook) noexcept        { open_impl_        = hook; }
    void set_close_hook(CloseHook hook) noexcept      { close_impl_       = hook; }
    void set_version_hook(VersionHook hook) noexcept  { version_impl_     = hook; }
    void set_mem_alloc_hook(MemAllocHook hook) noexcept   { mem_alloc_impl_   = hook; }
    void set_mem_free_hook(MemFreeHook hook) noexcept     { mem_free_impl_    = hook; }
    void set_mem_lock_hook(MemLockHook hook) noexcept     { mem_lock_impl_    = hook; }
    void set_mem_unlock_hook(MemUnlockHook hook) noexcept { mem_unlock_impl_  = hook; }
    void set_mapmem_hook(MapMemHook hook) noexcept        { mapmem_impl_      = hook; }
    void set_unmapmem_hook(UnmapMemHook hook) noexcept    { unmapmem_impl_    = hook; }
    void set_mem_cleanup_hook(MemCleanupHook hook) noexcept { mem_cleanup_impl_ = hook; }

    //----------------------------------------------------------------------//
    // One‐time initialization control
    //----------------------------------------------------------------------//

    std::mutex init_mutex_;                   ///< Protects one‐time init of mailbox & mem fd
    bool      mailbox_initialized_ = false;   ///< True after first mbox_open()
    bool      mem_initialized_     = false;   ///< True after first mapmem()

    int mbox_errno_ = 0; ///< Error code if mailbox init fails
    int mem_errno_  = 0; ///< Error code if mem init fails

    //----------------------------------------------------------------------//
    // RAII file descriptors
    //----------------------------------------------------------------------//

    FileDescriptor mbox_fd_{-1}; ///< Wrapped `/dev/vcio` descriptor
    FileDescriptor mem_fd_{-1};  ///< Wrapped `/dev/mem` descriptor

    bool debug_ = false; ///< True if verbose debug output is enabled

    //----------------------------------------------------------------------//
    // Static cleanup callbacks registered via atexit()
    //----------------------------------------------------------------------//

    static void cleanup_mailbox_fd() noexcept; ///< atexit callback to close `/dev/vcio`
    static void cleanup_mem_fd() noexcept;     ///< atexit callback to close `/dev/mem`

    //----------------------------------------------------------------------//
    // One‐time init helpers (must match mailbox.cpp definitions)
    //----------------------------------------------------------------------//

    /**
     * @brief Initialize the cached `/dev/vcio` file descriptor.
     * @details Called once in a thread-safe manner via std::call_once.
     * @throws std::system_error if ::open("/dev/vcio") fails.
     */
    void init_mailbox_fd() noexcept;

    /**
     * @brief Initialize the cached `/dev/mem` file descriptor.
     * @details Called once in a thread-safe manner via std::call_once.
     * @throws std::system_error if ::open("/dev/mem") fails.
     */
    void init_mem_fd() noexcept;
};

/// @brief Global reference to the Mailbox singleton.
extern Mailbox &mailbox;

#endif // _MAILBOX_HPP