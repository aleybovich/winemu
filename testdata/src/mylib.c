#include <windows.h>
#include <stdio.h>
static int attached = 0; static __thread int tcount = 0;
__declspec(dllexport) int mylib_add(int a, int b) { tcount++; return a + b + attached * 1000; }
__declspec(dllexport) const char *mylib_name(void) { return "mylib v1"; }
__declspec(dllexport) int mylib_tcount(void) { return tcount; }
__declspec(dllexport) int mylib_value = 77;
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) attached = 1;
    if (reason == DLL_PROCESS_DETACH) { printf("mylib detach\n"); fflush(stdout); }
    return TRUE;
}
