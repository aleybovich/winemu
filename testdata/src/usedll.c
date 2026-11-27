#include <windows.h>
#include <stdio.h>
__declspec(dllimport) int mylib_add(int, int);
__declspec(dllimport) const char *mylib_name(void);
__declspec(dllimport) int mylib_tcount(void);
__declspec(dllimport) int mylib_value;
typedef int (*addfn)(int, int);
int main(void) {
    printf("implicit: %s add=%d value=%d tcount=%d\n", mylib_name(), mylib_add(2, 3), mylib_value, mylib_tcount());
    HMODULE h = LoadLibraryA("mylib.dll");
    addfn f = (addfn)GetProcAddress(h, "mylib_add");
    printf("dynamic: same module=%d add=%d\n", h == GetModuleHandleA("mylib"), f(10, 20));
    char path[MAX_PATH]; GetModuleFileNameA(h, path, MAX_PATH); const char *b = strrchr(path, '\\');
    printf("dll path tail=%s\n", b ? b + 1 : path);
    return 0;
}
