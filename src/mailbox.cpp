/**
 * @file mailbox.cpp
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

#include "mailbox.hpp"

#include <array>        // neededd for std::array<uint32_t, 32>
#include <cstddef>      // for size_t
#include <cerrno>       // needed for errno
#include <cstdint>      // for uint32_t
#include <cstdio>       // for std::printf
#include <cstring>      // needed for std::strerror
#include <mutex>        // needed for std::mutex member
#include <system_error> // needed for std::system_error

#include <fcntl.h>     // needed for O_RDWR, O_SYNC (open flags)
#include <sys/ioctl.h> // needed for ioctl() calls
#include <sys/mman.h>  // needed for mmap(), munmap(), MAP_SHARED, PROT_READ/WRITE
#include <unistd.h>    // needed for close(), open(), sysconf()

/**
 * @struct MboxMessage
 * @brief Represents a mailbox message buffer for GPU communication.
 *
 * This structure encapsulates a fixed-size array of 32 32-bit words,
 * corresponding to a standard mailbox property interface message. It
 * includes a convenience factory method for constructing a “GetFirmwareVersion”
 * request.
 */
struct MboxMessage
{
    /// Fixed buffer of 32 words (each 32 bits) comprising the message.
    std::array<uint32_t, 32> words;

    /**
     * @brief Create a “GetFirmwareVersion” request message.
     *
     * Populates the mailbox buffer fields according to the GPU mailbox
     * property interface specification for the GetFirmwareVersion tag:
     *   - [0]: Total buffer size (in bytes) = 32 words × 4 bytes/word.
     *   - [1]: Request/response indicator flags (0 for request).
     *   - [2]: Tag identifier (GetFirmwareVersion).
     *   - [3]: Payload buffer size (4 bytes for version number).
     *   - [4]: Value-length field (0 when sending request).
     *   - [5]: Placeholder for the GPU to write the returned version.
     *   - [6..31]: Unused (set to zero).
     *
     * @return MboxMessage
     *   A fully initialized message ready to be sent via mailbox property ioctl.
     *
     * @note This function does not throw exceptions.
     */
    static MboxMessage make_get_version() noexcept
    {
        MboxMessage m;
        m.words.fill(0);

        // [0] Buffer size in bytes: 32 words × 4 bytes/word = 128 bytes
        m.words[0] = static_cast<uint32_t>(m.words.size() * sizeof(uint32_t));

        // [1] Request/response indicator (0 for request)
        m.words[1] = 0;

        // [2] Tag: GetFirmwareVersion
        m.words[2] = static_cast<uint32_t>(MailboxTags::Tag::GetFirmwareVersion);

        // [3] Payload size: 4 bytes (we expect a 32-bit version number)
        m.words[3] = 4;

        // [4] Value-length: 0 for request (GPU will fill this on response)
        m.words[4] = 0;

        // [5]–[31] remain zero; GPU will write version into [5].

        return m;
    }
};

/**
 * @brief Print the contents of a mailbox buffer for debugging purposes.
 *
 * Iterates through `word_count` 32-bit words in `buf` and prints each
 * with its byte-offset in hexadecimal, followed by the word’s value in hex.
 * Only intended to be called when verbose debug output is enabled.
 *
 * @param buf         Pointer to the first element of the mailbox buffer.
 * @param word_count  Number of 32-bit words to print from `buf`.
 *
 * @note This function does not throw exceptions.
 */
static void dump_buffer(const uint32_t *buf, size_t word_count) noexcept
{
    for (size_t i = 0; i < word_count; ++i)
    {
        std::printf("%04zx: 0x%08x\n", i * sizeof(uint32_t), buf[i]);
    }
}

/**
 * @brief Global reference to the Mailbox singleton.
 *
 * Provides convenient access to the one-and-only Mailbox instance for
 * performing mailbox operations (open, property calls, memory management).
 */
Mailbox &mailbox = Mailbox::instance();

/**
 * @brief Returns the singleton Mailbox instance.
 *
 * Implements Meyers’ singleton pattern: first call constructs the single
 * Mailbox object; subsequent calls return the same reference.
 *
 * @return Mailbox&  Reference to the singleton Mailbox.
 *
 * @note Thread-safe in C++11 and later due to guaranteed static local initialization.
 */
Mailbox &Mailbox::instance()
{
    static Mailbox inst;
    return inst;
}

/**
 * @brief Constructs a Mailbox object.
 *
 * Initializes internal state but does not open any file descriptors.
 * Actual opening of `/dev/vcio` and `/dev/mem` is deferred until mbox_open()
 * or mapmem() are called.
 *
 * @note This constructor does not throw.
 */
Mailbox::Mailbox() = default;

/**
 * @brief Destroys the Mailbox object and closes any open file descriptors.
 *
 * If the cached mailbox FD (`mbox_fd_`) is ≥ 0, calls ::close() and resets it to –1.
 * Similarly, if the cached `/dev/mem` FD (`mem_fd_`) is ≥ 0, calls ::close() and resets it.
 *
 * @note Marked noexcept: any errors from ::close() are ignored.
 */
Mailbox::~Mailbox() noexcept
{
    // Close the `/dev/vcio` FD if still open
    if (mbox_fd_.get() >= 0)
    {
        ::close(mbox_fd_.get());
        mbox_fd_.reset(-1);
    }

    // Close the `/dev/mem` FD if still open
    if (mem_fd_.get() >= 0)
    {
        ::close(mem_fd_.get());
        mem_fd_.reset(-1);
    }
}

/**
 * @brief Enable verbose debug output for mailbox operations.
 *
 * When called, every 32-bit word exchanged over the mailbox interface
 * will be printed to stdout (via dump_buffer).
 *
 * @note No exceptions are thrown.
 */
void Mailbox::set_debug() noexcept
{
    debug_ = true;
}

/**
 * @brief Opens the `/dev/vcio` mailbox device (singleton, thread-safe).
 *
 * On the first invocation, attempts to open `/dev/vcio` exactly once and
 * caches the file descriptor for future calls. On subsequent invocations,
 * returns the cached FD. If a test‐hook has been installed via set_test_hooks(),
 * calls the fake/open‐hook implementation instead of the real open.
 *
 * @return int  File descriptor for `/dev/vcio` on success.
 *
 * @throws std::system_error if:
 *   - The fake‐hook `open_impl_` is set and returns < 0 (errno preserved).
 *   - The real open fails (errno stored in mbox_errno_, used in exception).
 */
int Mailbox::mbox_open()
{
    if (open_impl_)
    {
        // Fake‐hook version: call the user‐provided open implementation
        int fake_fd = open_impl_("/dev/vcio", O_RDWR);
        if (fake_fd < 0)
        {
            // Preserve errno from the fake hook
            throw std::system_error(errno, std::generic_category(),
                                    "mbox_open(): fake_open failed");
        }
        return fake_fd;
    }

    // Real path: guard with mutex to ensure thread‐safe one‐time open
    std::scoped_lock lk(init_mutex_);
    if (!mailbox_initialized_)
    {
        // First time: attempt to open /dev/vcio
        int fd = ::open("/dev/vcio", O_RDWR);
        if (fd < 0)
        {
            // Store errno for later exception if needed
            mbox_errno_ = errno;
            mbox_fd_.reset(-1);
        }
        else
        {
            mbox_fd_.reset(fd);
        }
        mailbox_initialized_ = true;
    }

    if (mbox_fd_.get() < 0)
    {
        // If the cached FD is still invalid, throw with stored errno
        throw std::system_error(mbox_errno_, std::generic_category(),
                                "mbox_open(): cannot open /dev/vcio");
    }
    return mbox_fd_.get();
}

/**
 * @brief Closes the `/dev/vcio` mailbox device.
 *
 * If a fake‐hook has been installed via `set_test_hooks()`, invokes the hook
 * and returns immediately. Otherwise, only closes the cached file descriptor
 * if `file_desc` matches and is still open.
 *
 * @param[in] file_desc
 *   The file descriptor to close. Must match the cached descriptor from `mbox_open()`
 *   for the real path to actually close it.
 *
 * @throws std::system_error if:
 *   - The fake‐hook `close_impl_` is set and returns < 0 (errno preserved).
 *   - The underlying `::close(raw_fd)` call fails (errno preserved).
 */
void Mailbox::mbox_close(int file_desc)
{
    if (close_impl_)
    {
        // Fake‐hook version: invoke the user‐provided close implementation
        int rc = close_impl_(file_desc);
        if (rc < 0)
        {
            throw std::system_error(errno, std::generic_category(),
                                    "mbox_close(): hook failed");
        }
        return;
    }

    // Only close if this is our cached FD and it is still open
    int raw_fd = mbox_fd_.get();
    if (file_desc == raw_fd && raw_fd >= 0)
    {
        if (::close(raw_fd) < 0)
        {
            throw std::system_error(errno, std::generic_category(),
                                    "mbox_close(): ::close failed");
        }
        mbox_fd_.reset(-1);
    }
}

/**
 * @brief Retrieves the GPU firmware version via the mailbox interface.
 *
 * Constructs a “GetFirmwareVersion” message, sends it through the mailbox
 * (either via a fake‐hook if installed or via the real ioctl path), and
 * returns the version word from the response.
 *
 * @param[in] file_desc
 *   The open `/dev/vcio` mailbox file descriptor (obtained from `mbox_open()`).
 *
 * @return The 32‐bit firmware version returned by the GPU.
 *
 * @throws std::system_error if:
 *   - The fake‐hook `version_impl_` is set and returns < 0 (errno preserved).
 *   - The real mailbox property ioctl (`real_mbox_property`) returns < 0 (errno preserved).
 *
 * @note If `debug_` is true, prints the entire 32‐word buffer to stdout via `dump_buffer()`.
 */
uint32_t Mailbox::get_version(int file_desc)
{
    // Build a GetFirmwareVersion request buffer
    MboxMessage msg = MboxMessage::make_get_version();

    // Send either via hook or real ioctl
    int rc = version_impl_
                 ? version_impl_(file_desc, msg.words.data())
                 : real_mbox_property(file_desc, msg.words.data());
    if (rc < 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "get_version(): hook/ioctl failed");
    }

    if (debug_)
    {
        dump_buffer(msg.words.data(), msg.words.size());
    }

    // The GPU writes its version into word index 5
    return msg.words[5];
}

/**
 * @brief Allocate GPU‐accessible memory via the mailbox property interface.
 *
 * Constructs and sends an “AllocateMemory” mailbox property request to allocate
 * a contiguous block of GPU‐accessible memory. Returns the memory handle on success.
 *
 * If a fake‐hook (`mem_alloc_impl_`) is installed, this method invokes the hook
 * instead of performing the real ioctl transaction.
 *
 * @param[in] file_desc
 *   The `/dev/vcio` mailbox file descriptor (from `mbox_open()`).
 * @param[in] size
 *   Requested size of the memory block, in bytes (must be multiple of page size).
 * @param[in] align
 *   Alignment requirement for the block, in bytes (power‐of‐two, e.g. 4096).
 * @param[in] flags
 *   Allocation flags (e.g., cache‐coherent or non‐coherent) as defined by the GPU API.
 *
 * @return A nonzero GPU memory handle identifying the allocated block.
 *
 * @throws std::system_error if:
 *   - A fake‐hook is installed and returns < 0 (errno preserved).
 *   - The real ioctl call (`real_mbox_property`) returns < 0.
 *   - The GPU responds with a zero handle (allocation failed).
 *
 * @note If `debug_` is true, the entire 32‐word response buffer is printed via `dump_buffer()`.
 */
uint32_t Mailbox::mem_alloc(int file_desc, uint32_t size, uint32_t align, uint32_t flags)
{
    // If a fake‐hook is set, call it directly
    if (mem_alloc_impl_)
    {
        int rc = mem_alloc_impl_(file_desc, size, align, flags);
        if (rc < 0)
        {
            throw std::system_error(errno, std::generic_category(),
                                    "mem_alloc(): hook failed");
        }
        return static_cast<uint32_t>(rc);
    }

    // Prepare a 32‐word mailbox buffer initialized to zero
    uint32_t buf[32] = {};
    size_t i = 0;

    // Buffer layout:
    //   buf[0] = total message size in bytes (filled later)
    //   buf[1] = request code (zero)
    //   buf[2] = tag AllocateMemory
    //   buf[3] = value buffer size (in bytes) for this tag
    //   buf[4] = request/response indicator (set to request size)
    //   buf[5] = size argument
    //   buf[6] = align argument
    //   buf[7] = flags argument
    //   buf[8] = space for returned handle
    buf[i++] = 0; // placeholder for total size
    buf[i++] = 0; // request code
    buf[i++] = static_cast<uint32_t>(MailboxTags::Tag::AllocateMemory);
    buf[i++] = 12; // 3 words (size, align, flags) = 12 bytes
    buf[i++] = 12; // same as above
    buf[i++] = size;
    buf[i++] = align;
    buf[i++] = flags;
    buf[i++] = 0; // returned handle

    // Fill in total size (word count × 4 bytes)
    buf[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    // Perform the real mailbox transaction
    int rc = real_mbox_property(file_desc, buf);
    if (rc < 0 || buf[5] == 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "mem_alloc(): C‐style failed");
    }

    if (debug_)
    {
        size_t words = buf[0] / sizeof(uint32_t);
        dump_buffer(buf, words);
    }

    // The GPU returns the handle in buf[5]
    return buf[5];
}

/**
 * @brief Frees a previously allocated GPU memory block.
 *
 * Constructs and sends a “ReleaseMemory” mailbox property request to free
 * the block identified by the given handle. If a fake‐hook (`mem_free_impl_`)
 * is installed, that hook is invoked instead of performing the real ioctl.
 *
 * @param[in] file_desc
 *   The `/dev/vcio` mailbox file descriptor (from `mbox_open()`).
 * @param[in] handle
 *   The GPU memory handle returned by `mem_alloc()`, identifying the block to free.
 *
 * @throws std::system_error if:
 *   - A fake‐hook is installed and returns < 0 (errno preserved).
 *   - The real ioctl call (`real_mbox_property`) returns < 0.
 *
 * @note If `debug_` is true, the entire 32‐word response buffer is printed via `dump_buffer()`.
 */
void Mailbox::mem_free(int file_desc, uint32_t handle)
{
    // (no override hook)
    uint32_t buf[32] = {};
    size_t i = 0;

    // reserve space for total‐size and response code
    buf[i++] = 0; // will fill in later
    buf[i++] = 0; // request code = 0

    // “ReleaseMemory” tag
    buf[i++] = static_cast<uint32_t>(MailboxTags::Tag::ReleaseMemory);

    // value‐length  (we’re passing exactly 4 bytes: the handle)
    buf[i++] = 4; // value‐length

    // request‐length  (the same 4 bytes of handle)
    buf[i++] = 4; // request‐length

    // the handle to free
    buf[i++] = handle;

    // end tag (0) must be present
    buf[i++] = 0;

    // Now fill in word 0 := total size in bytes
    buf[0] = static_cast<uint32_t>(i * sizeof(uint32_t)); // i==7 → 28

    // Finally invoke the real mailbox‐property IOCTL
    int rc = real_mbox_property(file_desc, buf);
    if (rc < 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "mem_free(): C-style failed");
    }
    if (debug_)
    {
        size_t words = buf[0] / sizeof(uint32_t);
        dump_buffer(buf, words);
    }
    return; // void
}

/**
 * @brief Locks a previously allocated GPU memory block to obtain a bus address.
 *
 * Constructs and sends a “LockMemory” mailbox property request for the block
 * identified by the given handle. Returns the bus address for DMA use.
 * If a fake‐hook (`mem_lock_impl_`) is installed, that hook is invoked
 * instead of performing the real ioctl.
 *
 * @param[in] file_desc
 *   The `/dev/vcio` mailbox file descriptor (from `mbox_open()`).
 * @param[in] handle
 *   The GPU memory handle returned by `mem_alloc()`, identifying the block to lock.
 *
 * @return uint32_t
 *   The bus address (> 0) on success.
 *
 * @throws std::system_error if:
 *   - A fake‐hook is installed and returns < 0 (errno preserved).
 *   - The real ioctl call (`real_mbox_property`) returns < 0.
 *   - The returned bus address (`buf[5]`) is 0 (indicating failure).
 *
 * @note If `debug_` is true, the entire 32‐word response buffer is printed via `dump_buffer()`.
 */
uint32_t Mailbox::mem_lock(int file_desc, uint32_t handle)
{
    // If a fake‐hook is set, call it directly
    if (mem_lock_impl_)
    {
        int rc = mem_lock_impl_(file_desc, handle);
        if (rc < 0)
        {
            throw std::system_error(errno, std::generic_category(),
                                    "mem_lock(): hook failed");
        }
        return static_cast<uint32_t>(rc);
    }

    // Prepare a 32‐word mailbox buffer initialized to zero
    uint32_t buf[32] = {};
    size_t i = 0;

    // Buffer layout for “LockMemory”:
    //   buf[0] = total message size in bytes (filled later)
    //   buf[1] = request code (zero)
    //   buf[2] = tag LockMemory
    //   buf[3] = value buffer size (4 bytes: one word for handle)
    //   buf[4] = request/response indicator (same 4 bytes)
    //   buf[5] = memory handle to lock
    //   buf[6] = value placeholder for returned bus address
    buf[i++] = 0; // placeholder for total size
    buf[i++] = 0; // request code
    buf[i++] = static_cast<uint32_t>(MailboxTags::Tag::LockMemory);
    buf[i++] = 4;      // 1 word (4 bytes) for handle
    buf[i++] = 4;      // same as above
    buf[i++] = handle; // handle to lock
    buf[i++] = 0;      // placeholder for returned bus address

    // Fill in total size (word count × 4 bytes)
    buf[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    // Perform the real mailbox transaction
    int rc = real_mbox_property(file_desc, buf);
    if (rc < 0 || buf[5] == 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "mem_lock(): C‐style failed");
    }

    if (debug_)
    {
        size_t words = buf[0] / sizeof(uint32_t);
        dump_buffer(buf, words);
    }

    return buf[5];
}

/**
 * @brief Unlocks a previously locked GPU memory block.
 *
 * Constructs and sends an “UnlockMemory” mailbox property request for the block
 * identified by the given handle. If a fake‐hook (`mem_unlock_impl_`) is installed,
 * that hook is invoked instead of performing the real ioctl.
 *
 * @param[in] file_desc
 *   The `/dev/vcio` mailbox file descriptor (from `mbox_open()`).
 * @param[in] handle
 *   The GPU memory handle returned by `mem_alloc()` and locked by `mem_lock()`.
 *
 * @throws std::system_error if:
 *   - A fake‐hook is installed and returns < 0 (errno preserved).
 *   - The real ioctl call (`real_mbox_property`) returns < 0.
 *
 * @note If `debug_` is true, the entire 32‐word response buffer is printed via `dump_buffer()`.
 */
void Mailbox::mem_unlock(int file_desc, uint32_t handle)
{
    // If a fake‐hook is set, call it directly
    if (mem_unlock_impl_)
    {
        int rc = mem_unlock_impl_(file_desc, handle);
        if (rc < 0)
        {
            throw std::system_error(errno, std::generic_category(),
                                    "mem_unlock(): hook failed");
        }
        return;
    }

    // Prepare a 32‐word mailbox buffer initialized to zero
    uint32_t buf[32] = {};
    size_t i = 0;

    // Buffer layout for “UnlockMemory”:
    //   buf[0] = total message size in bytes (filled later)
    //   buf[1] = request code (zero)
    //   buf[2] = tag UnlockMemory
    //   buf[3] = value buffer size (4 bytes: one word for handle)
    //   buf[4] = request/response indicator (same 4 bytes)
    //   buf[5] = memory handle to unlock
    buf[i++] = 0; // placeholder for total size
    buf[i++] = 0; // request code
    buf[i++] = static_cast<uint32_t>(MailboxTags::Tag::UnlockMemory);
    buf[i++] = 4;      // 1 word (4 bytes) for handle
    buf[i++] = 4;      // same as above
    buf[i++] = handle; // handle to unlock
    buf[i++] = 0;      // unused

    // Fill in total size (word count × 4 bytes)
    buf[0] = static_cast<uint32_t>(i * sizeof(uint32_t));

    // Perform the real mailbox transaction
    int rc = real_mbox_property(file_desc, buf);
    if (rc < 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "mem_unlock(): C‐style failed");
    }

    if (debug_)
    {
        size_t words = buf[0] / sizeof(uint32_t);
        dump_buffer(buf, words);
    }
}

/**
 * @brief Map a physical memory region into this process’s address space.
 *
 * Constructs and sends an mmap request (or invokes a fake‐hook if installed) to
 * map the physical address range [base, base + size) via `/dev/mem`. Returns a
 * MappedRegion RAII wrapper that will unmap on destruction.
 *
 * @param[in] base
 *   The physical base address (bus address masked to physical) to map.
 * @param[in] size
 *   The length, in bytes, of the region to map.
 * @return A MappedRegion owning the mapped pointer. The underlying pointer is
 *         nullptr if mapping failed.
 *
 * @throws std::system_error if:
 *   - A fake‐hook (`mapmem_impl_`) is installed and returns < 0 (errno preserved).
 *   - Opening `/dev/mem` fails (error stored in `mem_errno_`).
 *   - The mmap system call fails (errno preserved).
 *
 * @note The returned MappedRegion’s `get()` points to the first byte of usable
 *       memory, adjusted for any page‐aligned offset. The total mapped length
 *       is (size + offset), so `MappedRegion` will unmap exactly that length.
 */
[[nodiscard]] MappedRegion Mailbox::mapmem(uint32_t base, size_t size)
{
    // If a fake‐hook is set, call it instead of doing a real mmap
    if (mapmem_impl_)
    {
        int fake = mapmem_impl_(base, size);
        if (fake < 0)
        {
            throw std::system_error(
                errno,
                std::generic_category(),
                "mapmem(): hook failed");
        }
        // Cast to uintptr_t first to avoid narrowing conversion warnings
        void *fake_ptr = reinterpret_cast<void *>(static_cast<uintptr_t>(fake));
        return MappedRegion(fake_ptr, size);
    }

    // Real path: ensure /dev/mem is opened exactly once (thread‐safe)
    {
        std::scoped_lock lk(init_mutex_);
        if (!mem_initialized_)
        {
            int fd = ::open("/dev/mem", O_RDWR | O_SYNC);
            if (fd < 0)
            {
                mem_errno_ = errno;
                mem_fd_.reset(-1);
            }
            else
            {
                mem_fd_.reset(fd);
            }
            mem_initialized_ = true;
        }
    }

    if (mem_fd_.get() < 0)
    {
        throw std::system_error(
            mem_errno_,
            std::generic_category(),
            "mapmem(): cannot open /dev/mem");
    }

    // Determine page size and compute page‐aligned address and offset
    long page_l = sysconf(_SC_PAGESIZE);
    size_t page = (page_l < 0 ? 4096u : static_cast<size_t>(page_l));
    size_t offset = base % page;
    off_t aligned = static_cast<off_t>(base - offset);

    // Perform mmap for (size + offset) bytes, starting at the page‐aligned address
    void *raw = ::mmap(
        /*addr=*/nullptr,
        /*length=*/size + offset,
        /*prot=*/PROT_READ | PROT_WRITE,
        /*flags=*/MAP_SHARED,
        /*fd=*/mem_fd_.get(),
        /*offset=*/aligned);

    if (raw == MAP_FAILED)
    {
        throw std::system_error(
            errno,
            std::generic_category(),
            "mapmem(): mmap failed");
    }

    // Adjust returned pointer by the computed offset so that the returned
    // address corresponds exactly to 'base'
    auto mapped_ptr = static_cast<std::byte *>(raw) + offset;
    return MappedRegion(
        /*addr=*/static_cast<void *>(mapped_ptr),
        /*size=*/size + offset);
}

/**
 * @brief Release (close) the cached `/dev/mem` file descriptor.
 *
 * If a fake‐hook for mem_cleanup is installed, invokes the hook instead of
 * closing the real file descriptor. Otherwise, resets the RAII‐wrapped FileDescriptor,
 * causing it to close the underlying FD if it is still ≥ 0. Safe to call multiple times.
 *
 * @throws std::system_error if a fake‐hook (`mem_cleanup_impl_`) is installed and returns < 0.
 */
void Mailbox::mem_cleanup()
{
    // If a fake‐hook is set, call it and throw on failure.
    if (mem_cleanup_impl_)
    {
        int rc = mem_cleanup_impl_();
        if (rc < 0)
        {
            throw std::system_error(
                errno,
                std::generic_category(),
                "mem_cleanup(): hook failed");
        }
        return;
    }

    // Real path: close /dev/mem FD if it's open (FileDescriptor::reset closes it).
    if (mem_fd_.get() >= 0)
    {
        mem_fd_.reset(); // closes old FD and sets it to -1
    }
}

/**
 * @brief Static cleanup function for the cached mailbox file descriptor.
 *
 * Invoked (e.g., via atexit) to ensure that `/dev/vcio` is closed if still open.
 * Retrieves the singleton Mailbox instance and, if its `mbox_fd_` is ≥ 0, calls
 * the raw `::close()` on it and resets it to -1. Safe to call multiple times.
 *
 * @note This function is marked noexcept and will not throw.
 */
void Mailbox::cleanup_mailbox_fd() noexcept
{
    auto &inst = Mailbox::instance();
    if (inst.mbox_fd_.get() >= 0)
    {
        ::close(inst.mbox_fd_.get());
        inst.mbox_fd_.reset(-1);
    }
}

/**
 * @brief Static cleanup function for the cached `/dev/mem` file descriptor.
 *
 * Invoked (e.g., via atexit) to ensure that `/dev/mem` is closed if still open.
 * Retrieves the singleton Mailbox instance and, if its `mem_fd_` is ≥ 0, calls
 * the raw `::close()` on it and resets it to -1. Safe to call multiple times.
 *
 * @note This function is marked noexcept and will not throw.
 */
void Mailbox::cleanup_mem_fd() noexcept
{
    auto &inst = Mailbox::instance();
    if (inst.mem_fd_.get() >= 0)
    {
        ::close(inst.mem_fd_.get());
        inst.mem_fd_.reset(-1);
    }
}

//------------------------------------------------------------------------------
/// @brief Perform a raw mailbox‐property ioctl on `/dev/vcio`.
///
/// This helper sends the buffer `buf` to the GPU via the mailbox property
/// interface (ioctl( _IOWR(100, 0, char*) )) and optionally dumps the
/// request/response words when debug mode is enabled.
///
/// @param file_desc   File descriptor returned by mbox_open().
/// @param buf         Pointer to a word‐aligned buffer containing the
///                    mailbox request.  Upon return, this buffer holds the
///                    response from the GPU.  Must not be nullptr.
///
/// @return Returns the raw ioctl(2) return value (>= 0 on success).  Returns
///         -1 on error and sets `errno` accordingly (e.g., EINVAL if `buf`
///         is nullptr, or whatever `ioctl` sets on failure).
///
/// @note When `debug_ == true`, the contents of the buffer (word count and
///       each 32-bit word) are printed to stdout via `dump_buffer()`.
///
/// @see _IOWR(100, 0, char*)
/// @see dump_buffer()
int Mailbox::real_mbox_property(int file_desc, void *buf)
{
    if (!buf)
    {
        errno = EINVAL;
        return -1;
    }

    int ret = ::ioctl(file_desc, static_cast<unsigned long>(_IOWR(100, 0, char *)), buf);
    if (debug_)
    {
        auto p = reinterpret_cast<uint32_t *>(buf);
        size_t words = p[0] / sizeof(uint32_t);
        dump_buffer(p, words);
    }
    return (ret < 0) ? -1 : ret;
}

//------------------------------------------------------------------------------
/// @brief Initialize and open the `/dev/vcio` mailbox device once (thread-safe).
///
/// Attempts to open `/dev/vcio` for read/write access and caches the file
/// descriptor in the singleton’s `mbox_fd_`.  If this is the first successful
/// open, registers `cleanup_mailbox_fd()` with `std::atexit()` to ensure the
/// descriptor is closed when the program exits.
///
/// @note This method is intended to be called exactly once via a thread-safe
///       check (`mailbox_initialized_` guard).  Subsequent calls should be
///       no-ops.
///
/// @remarks On failure to open `/dev/vcio`, `mbox_errno_` is set to `errno`,
///          and `mbox_fd_` is reset to –1.  On success, `mbox_fd_` holds the
///          valid file descriptor and `cleanup_mailbox_fd()` will run at exit.
///
/// @post If the open succeeds, `mbox_fd_.get() >= 0`; otherwise, `mbox_fd_.get() == -1`.
///
/// @see cleanup_mailbox_fd()
void Mailbox::init_mailbox_fd() noexcept
{
    int raw = ::open("/dev/vcio", O_RDWR);
    if (raw < 0)
    {
        mbox_errno_ = errno;
        mbox_fd_.reset(-1);
    }
    else
    {
        mbox_fd_.reset(raw);
        std::atexit(&Mailbox::cleanup_mailbox_fd);
    }
}

//------------------------------------------------------------------------------
/// @brief Initialize and open the `/dev/mem` device once (thread-safe).
///
/// Attempts to open `/dev/mem` for read/write access with synchronous I/O
/// and caches the file descriptor in the singleton’s `mem_fd_`.  This is
/// intended to be called exactly once, guarded by `mem_initialized_`.
///
/// @note On failure to open `/dev/mem`, `mem_errno_` is set to `errno`,
///       and `mem_fd_` is reset to –1.  On success, `mem_fd_` holds the valid
///       file descriptor for subsequent calls to `mmap()`.
///
/// @post If the open succeeds, `mem_fd_.get() >= 0`; otherwise, `mem_fd_.get() == -1`.
void Mailbox::init_mem_fd() noexcept
{
    int fd = ::open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0)
    {
        mem_errno_ = errno;
        mem_fd_.reset(-1);
    }
    else
    {
        mem_fd_.reset(fd);
    }
}

//------------------------------------------------------------------------------
/// @brief Fake “open” hook for test‐hook mode.
///
/// Simulates opening `/dev/vcio` by returning a dummy file descriptor.
///
/// @param /*path*/  Path to open (ignored).
/// @param /*flags*/ Open flags (ignored).
/// @return Always returns 100 to represent a valid FD in testing scenarios.
static int fake_open(const char * /*path*/, int /*flags*/)
{
    return 100;
}

//------------------------------------------------------------------------------
/// @brief Fake “close” hook for test‐hook mode.
///
/// Simulates closing a file descriptor by returning success.
///
/// @param /*fd*/  File descriptor to close (ignored).
/// @return Always returns 0 to indicate success.
static int fake_close(int /*fd*/)
{
    return 0;
}

//------------------------------------------------------------------------------
/// @brief Fake “get firmware version” hook for test‐hook mode.
///
/// Checks if the mailbox tag in the buffer corresponds to
/// `GetFirmwareVersion`.  If so, writes a fake version value into the response.
///
/// @param /*fd*/  Mailbox file descriptor (ignored).
/// @param buf     Pointer to a mailbox message buffer.
/// @return 0 on success; sets `errno = EINVAL` and returns -1 on invalid tag.
///
/// @throws None (operates in “no‐throw” C‐style).
static int fake_version(int /*fd*/, void *buf)
{
    auto msg = static_cast<uint32_t *>(buf);
    if (msg[2] == static_cast<uint32_t>(MailboxTags::Tag::GetFirmwareVersion))
    {
        msg[5] = 0x00020000; // Fake version number
        return 0;
    }
    errno = EINVAL;
    return -1;
}

//------------------------------------------------------------------------------
/// @brief Fake “memory allocate” hook for test‐hook mode.
///
/// Simulates GPU memory allocation by returning a dummy handle.
///
/// @param /*fd*/    Mailbox file descriptor (ignored).
/// @param /*size*/  Requested allocation size (ignored).
/// @param /*align*/ Alignment requirement (ignored).
/// @param /*flags*/ Allocation flags (ignored).
/// @return Always returns 123 as the fake memory handle.
static int fake_mem_alloc(int /*fd*/, uint32_t /*size*/, uint32_t /*align*/, uint32_t /*flags*/)
{
    return 123;
}

//------------------------------------------------------------------------------
/// @brief Fake “memory free” hook for test‐hook mode.
///
/// Simulates freeing GPU memory by returning success.
///
/// @param /*fd*/      Mailbox file descriptor (ignored).
/// @param /*handle*/  Memory handle to free (ignored).
/// @return Always returns 0 to indicate success.
static int fake_mem_free(int /*fd*/, uint32_t /*handle*/)
{
    return 0;
}

//------------------------------------------------------------------------------
/// @brief Fake “memory lock” hook for test‐hook mode.
///
/// Simulates locking GPU memory and returns a dummy bus address.
///
/// @param /*fd*/      Mailbox file descriptor (ignored).
/// @param /*handle*/  Memory handle to lock (ignored).
/// @return Always returns 0xABC as the fake bus address.
static int fake_mem_lock(int /*fd*/, uint32_t /*handle*/)
{
    return 0xABC;
}

//------------------------------------------------------------------------------
/// @brief Fake “memory unlock” hook for test‐hook mode.
///
/// Simulates unlocking GPU memory by returning success.
///
/// @param /*fd*/      Mailbox file descriptor (ignored).
/// @param /*handle*/  Memory handle to unlock (ignored).
/// @return Always returns 0 to indicate success.
static int fake_mem_unlock(int /*fd*/, uint32_t /*handle*/)
{
    return 0;
}

//------------------------------------------------------------------------------
/// @brief Fake “map physical memory” hook for test‐hook mode.
///
/// Simulates a mapping failure by setting `errno = EPERM` and returning -1.
///
/// @param /*base*/  Physical base address (ignored).
/// @param /*size*/  Size of the region to map (ignored).
/// @return Always returns -1 and sets `errno = EPERM` to simulate a permission error.
static int fake_mapmem(uint32_t /*base*/, size_t /*size*/)
{
    errno = EPERM;
    return -1;
}

//------------------------------------------------------------------------------
/// @brief Fake “unmap physical memory” hook for test‐hook mode.
///
/// Simulates unmapping by returning success.
///
/// @param /*addr*/  Mapped address (ignored).
/// @param /*size*/  Size of the region (ignored).
/// @return Always returns 0 to indicate success.
static int fake_unmapmem(void * /*addr*/, size_t /*size*/)
{
    return 0;
}

//------------------------------------------------------------------------------
/// @brief Fake “memory cleanup” hook for test‐hook mode.
///
/// Simulates closing `/dev/mem` by returning success.
///
/// @return Always returns 0 to indicate success.
static int fake_mem_cleanup(void)
{
    return 0;
}

//------------------------------------------------------------------------------
/// @brief Install default fake hooks to enable test‐hook mode.
///
/// Sets each mailbox API hook (`open`, `close`, `version`, `mem_alloc`, `mem_free`,
/// `mem_lock`, `mem_unlock`, `mapmem`, `unmapmem`, `mem_cleanup`) to its corresponding
/// fake implementation.  After calling this, all mailbox operations invoke the fakes.
///
/// @note This method does not throw; it simply assigns function pointers.
void Mailbox::set_test_hooks() noexcept
{
    set_open_hook(&fake_open);
    set_close_hook(&fake_close);
    set_version_hook(&fake_version);
    set_mem_alloc_hook(&fake_mem_alloc);
    set_mem_free_hook(&fake_mem_free);
    set_mem_lock_hook(&fake_mem_lock);
    set_mem_unlock_hook(&fake_mem_unlock);
    set_mapmem_hook(&fake_mapmem);
    set_unmapmem_hook(&fake_unmapmem);
    set_mem_cleanup_hook(&fake_mem_cleanup);
}
