#include <stdio.h>
#include <windows.h>
int main(void) {
    SetEnvironmentVariableA("PARENT_VAR", "hello-from-parent");
    int r = system("child.exe one \"two three\"");
    printf("parent: system returned %d\n", r);
    FILE *p = _popen("child.exe popen-mode", "r"); char buf[128];
    while (fgets(buf, sizeof buf, p)) printf("parent read: %s", buf);
    printf("parent: _pclose=%d\n", _pclose(p));
    // CreateProcess with redirected stdin/stdout pipes
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE}; HANDLE inR, inW, outR, outW;
    CreatePipe(&inR, &inW, &sa, 0); CreatePipe(&outR, &outW, &sa, 0);
    // the parent's ends must not be inherited, or the child keeps the pipes open
    SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0); SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si = {sizeof si}; si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = inR; si.hStdOutput = outW; si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi; char cmd[] = "child echo-stdin";
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    printf("parent: CreateProcess ok=%d\n", ok);
    CloseHandle(inR); CloseHandle(outW);
    DWORD n; WriteFile(inW, "alpha\nbeta\n", 11, &n, NULL); CloseHandle(inW);
    char out[512]; DWORD total = 0;
    while (ReadFile(outR, out + total, sizeof out - 1 - total, &n, NULL) && n > 0) total += n;
    out[total] = 0; printf("parent captured:\n%s", out);
    WaitForSingleObject(pi.hProcess, INFINITE); DWORD code; GetExitCodeProcess(pi.hProcess, &code);
    printf("parent: child exit code %lu\n", code);
    printf("parent: missing -> %d\n", system("nosuchprogram"));
    return 0;
}
