// Launching a program by a path without extension whose directory names
// contain dots ("rel.1.0\bin\kid"): CreateProcess (relative and absolute),
// system, _popen and cmd /C must all append .exe to the last component.
//
//   exepath_dotdir         parent: copies itself to rel.1.0\bin\kid.exe
//   exepath_dotdir child   the launched program: prints argc, exits 7
#include <windows.h>
#include <stdio.h>
#include <string.h>

static DWORD run(const char *cmdline) {
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi;
    char buf[MAX_PATH * 2];
    strcpy(buf, cmdline);
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        return 1000 + GetLastError();
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) {
        printf("kid argc=%d\n", argc);
        fflush(stdout);
        return 7;
    }
    char self[MAX_PATH], abs[MAX_PATH], cmd[MAX_PATH * 2];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    CreateDirectoryA("rel.1.0", NULL);
    CreateDirectoryA("rel.1.0\\bin", NULL);
    if (!CopyFileA(self, "rel.1.0\\bin\\kid.exe", FALSE)) {
        printf("FAIL copy %lu\n", GetLastError());
        return 1;
    }
    GetFullPathNameA("rel.1.0\\bin\\kid", MAX_PATH, abs, NULL);

    printf("createprocess rel=%lu\n", run("rel.1.0\\bin\\kid child"));
    fflush(stdout);
    snprintf(cmd, sizeof cmd, "\"%s\" child", abs);
    printf("createprocess abs=%lu\n", run(cmd));
    fflush(stdout);
    printf("createprocess missing=%lu\n", run("rel.1.0\\bin\\nokid child"));
    fflush(stdout);

    int rc = system("rel.1.0\\bin\\kid child");
    printf("system=%d\n", rc);
    fflush(stdout);

    FILE *p = _popen("rel.1.0\\bin\\kid child", "r");
    char line[64] = "";
    if (p) {
        if (!fgets(line, sizeof line, p))
            line[0] = 0;
        line[strcspn(line, "\r\n")] = 0;
    }
    printf("popen [%s] close=%d\n", line, p ? _pclose(p) : -1);
    fflush(stdout);

    printf("cmd=%lu\n", run("cmd /C rel.1.0\\bin\\kid child"));
    return 0;
}
