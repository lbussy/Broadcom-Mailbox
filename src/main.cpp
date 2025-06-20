// main.cpp
#include <iostream>
#include <cstdlib>
#include "mailbox.hpp"

int main()
{
    try
    {
        std::cout << "Opening mailbox.\n";
        ::mailbox.mbox_open();

        std::cout << "Mailbox FD: " << ::mailbox.get_fd() << "\n";

        std::cout << "Discovering peripheral base.\n";
        uint32_t base = Mailbox::discover_peripheral_base();
        std::cout << "Peripheral base: 0x" << std::hex << base << std::dec << "\n";

        std::cout << "Allocating " << Mailbox::PAGE_SIZE << " bytes.\n";
        uint32_t handle = ::mailbox.mem_alloc(Mailbox::PAGE_SIZE, Mailbox::BLOCK_SIZE);
        std::cout << "Allocated handle: " << handle << "\n";

        std::cout << "Locking handle.\n";
        uint32_t bus_addr = ::mailbox.mem_lock(handle);
        std::cout << "Locked bus address: 0x" << std::hex << bus_addr << std::dec << "\n";

        std::cout << "Unlocking handle.\n";
        uint32_t unlock_res = ::mailbox.mem_unlock(handle);
        std::cout << "Unlock result: " << unlock_res << "\n";

        std::cout << "Freeing handle.\n";
        uint32_t free_res = ::mailbox.mem_free(handle);
        std::cout << "Free result: " << free_res << "\n";

        std::cout << "Mapping memory region at peripheral base.\n";
        volatile uint8_t *vaddr = ::mailbox.mapmem(base, Mailbox::BLOCK_SIZE);
        std::cout << "Mapped address: " << vaddr << "\n";

        std::cout << "Unmapping memory region.\n";
        ::mailbox.unmapmem(vaddr, Mailbox::PAGE_SIZE);
        std::cout << "Unmapped.\n";

        std::cout << "Closing mailbox.\n";
        ::mailbox.mbox_close();
        std::cout << "Done.\n";

        return EXIT_SUCCESS;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        // Attempt to close if open
        if (::mailbox.get_fd() >= 0)
        {
            ::mailbox.mbox_close();
        }
        return EXIT_FAILURE;
    }
}
