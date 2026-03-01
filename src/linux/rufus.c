/* Linux main entry point and rufus.c function stubs */
#include "rufus.h"
#include "missing.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* ---- Function stubs ---- */
void EnableControls(BOOL enable, BOOL remove_checkboxes)  { (void)enable;(void)remove_checkboxes; }

BOOL CALLBACK LogCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
    { (void)hDlg;(void)message;(void)wParam;(void)lParam; return FALSE; }

enum ArchType MachineToArch(WORD machine) {
    switch(machine) {
    case IMAGE_FILE_MACHINE_I386:  return ARCH_X86_32;
    case IMAGE_FILE_MACHINE_AMD64: return ARCH_X86_64;
    case IMAGE_FILE_MACHINE_ARM:   return ARCH_ARM_32;
    case IMAGE_FILE_MACHINE_ARMNT: return ARCH_ARM_32;
    case IMAGE_FILE_MACHINE_ARM64: return ARCH_ARM_64;
    default:                       return ARCH_UNKNOWN;
    }
}

void GetBootladerInfo(void) {}
DWORD WINAPI ImageScanThread(LPVOID param) { (void)param; return 0; }
void ClrAlertPromptHook(void) {}
HANDLE CreatePreallocatedFile(const char* path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, LONGLONG size)
    { (void)path;(void)access;(void)share;(void)sa;(void)disp;(void)flags;(void)size; return INVALID_HANDLE_VALUE; }

/* ---- Linux main entry point ---- */
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    fprintf(stderr, "Rufus Linux port - not yet implemented\n");
    return 1;
}
