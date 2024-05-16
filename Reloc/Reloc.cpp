#include <print>

#include "file.h"

typedef int (*MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

MessageBoxA_t MessageBoxA_Original = MessageBoxA;

extern "C" int MessageBoxA_Custom(HWND window, LPCSTR text, LPCSTR title, UINT flags) {
    auto forDescriptor = window == NULL ? "us" : "another window";
    std::println("Message box for {} is being created with the text \"{}\"", forDescriptor, text);
    return MessageBoxA_Original(window, text, title, flags);
}

int main()
{
    auto us = reinterpret_cast<PBYTE>(GetModuleHandleA(NULL));
    // NOTE: This function returns the address of the original. 
    if (hook_iat(us, "User32.dll", "MessageBoxA", MessageBoxA_Custom) == NULL) {
        std::println("[-] Failed to hook MessageBoxA!");
        return -1;
    }

    MessageBoxA(NULL, "This is a hooked message box", "Hello!", MB_OK);

    // Return the function back to its original state.
    if (hook_iat(us, "User32.dll", "MessageBoxA", MessageBoxA_Original) == NULL) {
        std::println("[-] Failed to restore MessageBoxA to its original pointer");
        return -1;
    }
}
