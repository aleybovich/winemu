// LDFLAGS: -lws2_32
// Cross-workstream guest test (sockets + multi-process + deadlock detector):
// the parent listens on loopback and starts itself as a child; the child
// connects, both exchange data, and the parent waits INFINITE for the child
// while one of its threads is parked in a blocking recv (a host wait) for
// longer than the deadlock window.
//
//   integ_proc_sock               parent
//   integ_proc_sock child <port>  child
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int recv_str(SOCKET s, char *buf, int n) {
    int k = recv(s, buf, n - 1, 0);
    buf[k > 0 ? k : 0] = 0;
    return k;
}

static int child(int port) {
    Sleep(300); // the parent blocks in accept meanwhile
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) return 100 + WSAGetLastError() % 100;
    char buf[64];
    if (send(s, "ping", 4, 0) != 4) return 2;
    if (recv_str(s, buf, sizeof buf) <= 0 || strcmp(buf, "pong")) return 3;
    Sleep(2500); // longer than the deadlock window
    if (send(s, "bye", 3, 0) != 3) return 4;
    shutdown(s, SD_SEND);
    if (recv(s, buf, sizeof buf, 0) != 0) return 5; // parent closes -> EOF
    closesocket(s);
    return 7;
}

static DWORD WINAPI reader(LPVOID p) {
    SOCKET s = (SOCKET)p;
    char buf[64];
    int n = recv_str(s, buf, sizeof buf); // blocks ~2.5 s
    printf("reader got=%s\n", n > 0 ? buf : "?");
    closesocket(s);
    return 0;
}

int main(int argc, char **argv) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return 90;
    if (argc >= 3 && !strcmp(argv[1], "child")) return child(atoi(argv[2]));
    setvbuf(stdout, NULL, _IONBF, 0);

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a = {0};
    int al = sizeof a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 1) || getsockname(ls, (struct sockaddr *)&a, &al)) {
        printf("listen failed %d\n", WSAGetLastError());
        return 1;
    }
    char self[MAX_PATH], cmd[2 * MAX_PATH];
    GetModuleFileNameA(NULL, self, sizeof self);
    snprintf(cmd, sizeof cmd, "\"%s\" child %d", self, ntohs(a.sin_port));
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed %lu\n", GetLastError());
        return 1;
    }
    SOCKET s = accept(ls, NULL, NULL);
    printf("accept=%d\n", s != INVALID_SOCKET);
    closesocket(ls);
    char buf[64];
    recv_str(s, buf, sizeof buf);
    printf("parent got=%s\n", buf);
    printf("send=%d\n", send(s, "pong", 4, 0));
    HANDLE th = CreateThread(NULL, 0, reader, (LPVOID)s, 0, NULL);
    DWORD w = WaitForSingleObject(pi.hProcess, INFINITE), code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    WaitForSingleObject(th, INFINITE);
    printf("wait=%lu child code=%lu\n", w, code);
    WSACleanup();
    return 0;
}
