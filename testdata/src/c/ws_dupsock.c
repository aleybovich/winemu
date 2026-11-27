// LDFLAGS: -lws2_32
// Socket sharing between processes:
//   1. the parent accepts a connection, WSADuplicateSocketW()s it for a child,
//      passes the WSAPROTOCOL_INFOW through the child's stdin pipe and closes
//      its own descriptor; the child (WSASocketW FROM_PROTOCOL_INFO) serves it;
//   2. a child inherits the listening socket (bInheritHandles) and accepts
//      and serves the next connection itself.
//
//   ws_dupsock                    parent
//   ws_dupsock dup                child for 1 (info on stdin)
//   ws_dupsock inherit <socket>   child for 2
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c, msg) do { if (!(c)) { printf("FAIL %s (wsa %d, err %lu, line %d)\n", msg, WSAGetLastError(), GetLastError(), __LINE__); return 1; } } while (0)

static int serve(SOCKET s, const char *who) {
    char buf[64] = {0};
    int n = recv(s, buf, sizeof buf - 1, 0);
    if (n <= 0) return 10;
    char reply[96];
    int len = sprintf(reply, "%s got [%s]", who, buf);
    if (send(s, reply, len, 0) != len) return 11;
    closesocket(s);
    return 0;
}

static int child_dup(void) {
    WSAPROTOCOL_INFOW info;
    DWORD got = 0, n;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    while (got < sizeof info && ReadFile(in, (char *)&info + got, sizeof info - got, &n, NULL) && n > 0) got += n;
    if (got != sizeof info) return 20;
    SOCKET s = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) return 21;
    return serve(s, "dup child");
}

static int child_inherit(SOCKET l) {
    SOCKET s = accept(l, NULL, NULL);
    if (s == INVALID_SOCKET) return 30;
    return serve(s, "inherit child");
}

static struct sockaddr_in addr;

static int talk(const char *msg, char *reply, int size) {
    SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect(c, (struct sockaddr *)&addr, sizeof addr)) return -1;
    send(c, msg, (int)strlen(msg), 0);
    int n = recv(c, reply, size - 1, 0);
    reply[n > 0 ? n : 0] = 0;
    closesocket(c);
    return n;
}

static char reply1[128];
static DWORD WINAPI client1(LPVOID p) { (void)p; return talk("one", reply1, sizeof reply1) <= 0; }

static int spawn(const char *args, HANDLE in, PROCESS_INFORMATION *pi) {
    char cmd[MAX_PATH + 64], exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    sprintf(cmd, "\"%s\" %s", exe, args);
    STARTUPINFOA si = {sizeof si};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    return CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi);
}

static int child_code(PROCESS_INFORMATION *pi) {
    DWORD code = 99;
    if (WaitForSingleObject(pi->hProcess, 20000) != WAIT_OBJECT_0) return -1;
    GetExitCodeProcess(pi->hProcess, &code);
    return (int)code;
}

int main(int argc, char **argv) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd)) return 2;
    if (argc > 1 && !strcmp(argv[1], "dup")) return child_dup();
    if (argc > 2 && !strcmp(argv[1], "inherit")) return child_inherit((SOCKET)_strtoui64(argv[2], NULL, 10));

    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(l, (struct sockaddr *)&addr, sizeof addr) == 0, "bind");
    CHECK(listen(l, 5) == 0, "listen");
    int alen = sizeof addr;
    getsockname(l, (struct sockaddr *)&addr, &alen);

    // 1. WSADuplicateSocket
    HANDLE th = CreateThread(NULL, 0, client1, NULL, 0, NULL);
    SOCKET s = accept(l, NULL, NULL);
    CHECK(s != INVALID_SOCKET, "accept");
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE rd, wr;
    CHECK(CreatePipe(&rd, &wr, &sa, 0), "CreatePipe");
    SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation((HANDLE)l, HANDLE_FLAG_INHERIT, 0); // not for this child
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    PROCESS_INFORMATION pi;
    CHECK(spawn("dup", rd, &pi), "CreateProcess dup");
    CloseHandle(rd);
    WSAPROTOCOL_INFOW info;
    CHECK(WSADuplicateSocketW(s, pi.dwProcessId, &info) == 0, "WSADuplicateSocketW");
    closesocket(s); // the child's descriptor keeps the connection open
    DWORD n;
    CHECK(WriteFile(wr, &info, sizeof info, &n, NULL) && n == sizeof info, "write info");
    CloseHandle(wr);
    int code = child_code(&pi);
    CHECK(code == 0, "dup child exit code");
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0, "client 1");
    CHECK(!strcmp(reply1, "dup child got [one]"), "dup reply");
    printf("%s\n", reply1);

    // 2. inherited listening socket
    SetHandleInformation((HANDLE)l, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    char args[64];
    sprintf(args, "inherit %llu", (unsigned long long)l);
    CHECK(spawn(args, GetStdHandle(STD_INPUT_HANDLE), &pi), "CreateProcess inherit");
    char reply2[128];
    CHECK(talk("two", reply2, sizeof reply2) > 0, "client 2");
    CHECK(child_code(&pi) == 0, "inherit child exit code");
    CHECK(!strcmp(reply2, "inherit child got [two]"), "inherit reply");
    printf("%s\nALL OK\n", reply2);
    closesocket(l);
    return 0;
}
