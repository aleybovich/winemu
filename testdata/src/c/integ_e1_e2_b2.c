// LDFLAGS: -lws2_32
// Cross-workstream integration: cross-process memory/handles/jobs (WS-E1),
// named pipes + builtin cmd (WS-E2) and shared sockets (WS-B1/B2) together.
//
//   integ_e1_e2_b2              parent
//   integ_e1_e2_b2 child <addr> suspended child: section at <addr>, pipe, TCP
//   integ_e1_e2_b2 log          child started via cmd /D /C with redirection
//   integ_e1_e2_b2 sleep        child killed by closing the job
//
// The parent creates a named pagefile section and a named pipe server, starts
// the child CREATE_SUSPENDED inside a kill-on-close job, reserves the view's
// address range in the child (VirtualAllocEx), passes a WSADuplicateSocketW'd
// listening socket and a DuplicateHandle'd event through the section and
// resumes the child. The child frees the reservation, maps the section at the
// parent's address, reports over CallNamedPipe, accepts one TCP connection on
// the shared socket and signals the event.
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c, msg) do { if (!(c)) { printf("FAIL %s (wsa %d, err %lu, line %d)\n", msg, WSAGetLastError(), GetLastError(), __LINE__); return 1; } } while (0)

#define SEC_NAME "Local\\integ_e1e2b2_section"
#define PIPE_NAME "\\\\.\\pipe\\integ_e1e2b2"
#define SEC_SIZE 0x10000

typedef struct {
    char greeting[64];
    WSAPROTOCOL_INFOW sock;
    HANDLE event;
    volatile LONG counter;
} shared;

static int child(void *addr) {
    HANDLE hs = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SEC_NAME);
    CHECK(hs != NULL, "OpenFileMapping");
    CHECK(VirtualFree(addr, 0, MEM_RELEASE), "VirtualFree(reservation)");
    shared *s = (shared *)MapViewOfFileEx(hs, FILE_MAP_ALL_ACCESS, 0, 0, 0, addr);
    CHECK(s == addr, "MapViewOfFileEx(parent address)");
    char msg[128], reply[16] = {0};
    int len = sprintf(msg, "mapped at parent address: %s", s->greeting);
    DWORD n = 0;
    CHECK(CallNamedPipeA(PIPE_NAME, msg, len, reply, sizeof reply - 1, &n, 5000), "CallNamedPipe");
    CHECK(n == 2 && !strcmp(reply, "go"), "pipe reply");
    WSADATA wd;
    CHECK(WSAStartup(MAKEWORD(2, 2), &wd) == 0, "WSAStartup");
    SOCKET ls = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &s->sock, 0, WSA_FLAG_OVERLAPPED);
    CHECK(ls != INVALID_SOCKET, "WSASocketW(FROM_PROTOCOL_INFO)");
    SOCKET c = accept(ls, NULL, NULL);
    CHECK(c != INVALID_SOCKET, "accept");
    char buf[32] = {0}, out[64];
    int r = recv(c, buf, sizeof buf - 1, 0);
    CHECK(r > 0, "recv");
    len = sprintf(out, "child got [%s]", buf);
    CHECK(send(c, out, len, 0) == len, "send");
    closesocket(c);
    closesocket(ls);
    InterlockedIncrement(&s->counter);
    CHECK(SetEvent(s->event), "SetEvent(duplicated event)");
    return 0;
}

static int child_log(void) {
    BOOL in = FALSE;
    IsProcessInJob(GetCurrentProcess(), NULL, &in);
    HANDLE hs = OpenFileMappingA(FILE_MAP_READ, FALSE, SEC_NAME);
    CHECK(hs != NULL, "OpenFileMapping(log)");
    shared *s = (shared *)MapViewOfFile(hs, FILE_MAP_READ, 0, 0, 0);
    CHECK(s != NULL, "MapViewOfFile(log)");
    printf("injob=%d greeting=%s counter=%ld\n", in, s->greeting, s->counter);
    return 0;
}

// spawn creates a suspended process in job and resumes it.
static int spawn(HANDLE job, char *cmd, PROCESS_INFORMATION *pi, BOOL resume) {
    STARTUPINFOA si = {sizeof si};
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi)) return 0;
    if (!AssignProcessToJobObject(job, pi->hProcess)) return 0;
    return !resume || ResumeThread(pi->hThread) == 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && !strcmp(argv[1], "child")) return child((void *)_strtoui64(argv[2], NULL, 16));
    if (argc > 1 && !strcmp(argv[1], "log")) return child_log();
    if (argc > 1 && !strcmp(argv[1], "sleep")) { Sleep(30000); return 5; }

    char self[MAX_PATH], cmd[2 * MAX_PATH];
    CHECK(GetModuleFileNameA(NULL, self, sizeof self), "GetModuleFileName");

    HANDLE job = CreateJobObjectA(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li = {0};
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    CHECK(job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li), "job");

    HANDLE hs = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SEC_SIZE, SEC_NAME);
    CHECK(hs != NULL && GetLastError() == 0, "CreateFileMapping");
    shared *s = (shared *)MapViewOfFile(hs, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    CHECK(s != NULL, "MapViewOfFile");
    strcpy(s->greeting, "hello from parent");
    HANDLE pipe = CreateNamedPipeA(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 512, 512, 0, NULL);
    CHECK(pipe != INVALID_HANDLE_VALUE, "CreateNamedPipe");

    WSADATA wd;
    CHECK(WSAStartup(MAKEWORD(2, 2), &wd) == 0, "WSAStartup");
    SOCKET ls = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int alen = sizeof a;
    CHECK(ls != INVALID_SOCKET && bind(ls, (struct sockaddr *)&a, sizeof a) == 0 && listen(ls, 1) == 0, "listen");
    CHECK(getsockname(ls, (struct sockaddr *)&a, &alen) == 0, "getsockname");
    SetHandleInformation((HANDLE)ls, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    printf("section=1 pipe=1 listen=1\n");

    PROCESS_INFORMATION pi;
    sprintf(cmd, "\"%s\" child %llx", self, (unsigned long long)(ULONG_PTR)s);
    CHECK(spawn(job, cmd, &pi, FALSE), "spawn child");
    BOOL in = FALSE;
    IsProcessInJob(pi.hProcess, job, &in);
    void *res = VirtualAllocEx(pi.hProcess, s, SEC_SIZE, MEM_RESERVE, PAGE_NOACCESS);
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    int dup = WSADuplicateSocketW(ls, pi.dwProcessId, &s->sock);
    BOOL dupev = DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &s->event, 0, FALSE, DUPLICATE_SAME_ACCESS);
    printf("suspended injob=%d reserve=%d dupsock=%d dupevent=%d\n", in, res == s, dup, dupev);
    printf("resume=%lu\n", ResumeThread(pi.hThread));

    CHECK(ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED, "ConnectNamedPipe");
    char buf[128] = {0};
    DWORD n = 0;
    CHECK(ReadFile(pipe, buf, sizeof buf - 1, &n, NULL), "ReadFile(pipe)");
    printf("pipe got [%s]\n", buf);
    CHECK(WriteFile(pipe, "go", 2, &n, NULL) && n == 2, "WriteFile(pipe)");
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);

    SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(c != INVALID_SOCKET && connect(c, (struct sockaddr *)&a, sizeof a) == 0, "connect");
    CHECK(send(c, "ping", 4, 0) == 4, "send");
    memset(buf, 0, sizeof buf);
    int got = 0, r;
    while ((r = recv(c, buf + got, sizeof buf - 1 - got, 0)) > 0) got += r;
    closesocket(c);
    printf("tcp reply [%s]\n", buf);
    DWORD wev = WaitForSingleObject(ev, 10000), code = 99;
    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("event=%lu child=%lu counter=%ld\n", wev, code, s->counter);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // once more through the builtin cmd, output redirected to a log file
    DeleteFileA("integ_e1e2b2.log");
    sprintf(cmd, "cmd.exe /D /C \"\"%s\" log >integ_e1e2b2.log\"", self);
    CHECK(spawn(job, cmd, &pi, TRUE), "spawn cmd");
    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    FILE *f = fopen("integ_e1e2b2.log", "r");
    CHECK(f != NULL, "open log");
    memset(buf, 0, sizeof buf);
    fgets(buf, sizeof buf, f);
    fclose(f);
    buf[strcspn(buf, "\r\n")] = 0;
    printf("cmd=%lu log [%s]\n", code, buf);

    // kill-on-close: a running member dies with the last job handle
    sprintf(cmd, "\"%s\" sleep", self);
    CHECK(spawn(job, cmd, &pi, TRUE), "spawn sleep");
    DWORD alive = WaitForSingleObject(pi.hProcess, 100);
    CloseHandle(job);
    DWORD after = WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("alive=%lu after close=%lu code=%lu\n", alive, after, code);
    closesocket(ls);
    return 0;
}
