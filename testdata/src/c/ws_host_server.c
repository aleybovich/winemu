// LDFLAGS: -lws2_32
// Winsock guest test: listens on 127.0.0.1:<argv[1]>, serves one host-side
// client: reads a line and answers "echo: <line>".
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL excl = TRUE;
    setsockopt(ls, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&excl, sizeof excl);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)atoi(argv[1]));
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(ls, 1) != 0) {
        printf("listen failed: %d\n", WSAGetLastError());
        return 1;
    }
    struct sockaddr_in peer;
    int pl = sizeof peer;
    SOCKET s = accept(ls, (struct sockaddr *)&peer, &pl);
    if (s == INVALID_SOCKET) { printf("accept failed: %d\n", WSAGetLastError()); return 1; }
    char line[256];
    int n = 0;
    while (n < (int)sizeof line - 1) {
        int k = recv(s, line + n, 1, 0);
        if (k <= 0 || line[n] == '\n') break;
        n += k;
    }
    line[n] = 0;
    char reply[300];
    int rn = sprintf(reply, "echo: %s\n", line);
    send(s, reply, rn, 0);
    shutdown(s, SD_SEND);
    char tmp[16];
    while (recv(s, tmp, sizeof tmp, 0) > 0) {}
    closesocket(s);
    closesocket(ls);
    printf("served %s from %s\n", line, inet_ntoa(peer.sin_addr));
    WSACleanup();
    return 0;
}
