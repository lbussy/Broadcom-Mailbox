/**
 * @file main.cpp
 * @brief A test harness for the C++17 `Mailbox` class to interface with the
 *        Broadcom GPU mailbox.
 *
 * This project is is licensed under the MIT License. See LICENSE.md
 * for more information.
 *
 * Copyright (C) 2025 Lee C. Bussy (@LBussy). All rights reserved.
 *
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
        std::uintptr_t bus_addr = ::mailbox.mem_lock(handle);
        std::cout << "Locked bus address: 0x" << std::hex << bus_addr << std::dec << "\n";

        std::cout << "Unlocking handle.\n";
        uint32_t unlock_res = ::mailbox.mem_unlock(handle);
        std::cout << "Unlock result: " << unlock_res << "\n";

        std::cout << "Freeing handle.\n";
        uint32_t free_res = ::mailbox.mem_free(handle);
        std::cout << "Free result: " << free_res << "\n";

        std::cout << "Mapping memory region at peripheral base.\n";
        volatile uint8_t *vaddr = ::mailbox.mapmem(base, Mailbox::PAGE_SIZE);
        std::cout << "Mapped address: 0x"
                  << std::hex << reinterpret_cast<std::uintptr_t>(vaddr)
                  << std::dec << "\n";

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
