// LDFLAGS: -lws2_32
// Winsock guest test: blocking echo server thread + client over IPv4 and
// IPv6 loopback, MSG_WAITALL with a large transfer, getaddrinfo("localhost"),
// connection refused and address in use.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIG (1 << 20)

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf(" (WSAGetLastError %d)\n", WSAGetLastError()); fails++; } } while (0)

static DWORD WINAPI echo_server(LPVOID p) {
    SOCKET ls = (SOCKET)p;
    SOCKET s = accept(ls, NULL, NULL);
    if (s == INVALID_SOCKET) { printf("FAIL accept %d\n", WSAGetLastError()); return 1; }
    char *buf = malloc(65536);
    int n;
    while ((n = recv(s, buf, 65536, 0)) > 0) {
        int off = 0;
        while (off < n) {
            int k = send(s, buf + off, n - off, 0);
            if (k <= 0) { printf("FAIL server send %d\n", WSAGetLastError()); return 1; }
            off += k;
        }
    }
    if (n < 0) printf("FAIL server recv %d\n", WSAGetLastError());
    closesocket(s);
    free(buf);
    return 0;
}

// receiver thread for the big transfer: the client's blocking send of BIG
// bytes needs the echo to be drained concurrently
static char *bigIn;
static SOCKET bigSock;
static DWORD WINAPI big_reader(LPVOID p) {
    (void)p;
    int n = recv(bigSock, bigIn, BIG, MSG_WAITALL);
    return n == BIG ? 0 : 1;
}

static void echo_test(int af) {
    SOCKET ls = socket(af, SOCK_STREAM, IPPROTO_TCP);
    CHECK(ls != INVALID_SOCKET, "socket");
    struct sockaddr_storage ss; memset(&ss, 0, sizeof ss);
    int len;
    if (af == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback;
        len = sizeof *a;
    }
    CHECK(bind(ls, (struct sockaddr *)&ss, len) == 0, "bind");
    CHECK(listen(ls, SOMAXCONN) == 0, "listen");
    int sl = sizeof ss;
    CHECK(getsockname(ls, (struct sockaddr *)&ss, &sl) == 0 && sl == len, "getsockname");
    HANDLE th = CreateThread(NULL, 0, echo_server, (LPVOID)ls, 0, NULL);

    SOCKET c = socket(af, SOCK_STREAM, IPPROTO_TCP);
    CHECK(connect(c, (struct sockaddr *)&ss, len) == 0, "connect");
    const char *msg = "hello over winsock";
    CHECK(send(c, msg, (int)strlen(msg), 0) == (int)strlen(msg), "send");
    char buf[64] = {0};
    CHECK(recv(c, buf, (int)strlen(msg), MSG_WAITALL) == (int)strlen(msg) && strcmp(buf, msg) == 0, "recv echo '%s'", buf);

    // large transfer: 1 MiB, received with MSG_WAITALL by another thread
    char *out = malloc(BIG);
    bigIn = malloc(BIG);
    for (int i = 0; i < BIG; i++) out[i] = (char)(i * 7 + (i >> 8));
    bigSock = c;
    HANDLE rt = CreateThread(NULL, 0, big_reader, NULL, 0, NULL);
    CHECK(send(c, out, BIG, 0) == BIG, "big send");
    CHECK(WaitForSingleObject(rt, 30000) == WAIT_OBJECT_0, "big reader finished");
    DWORD rc = 1; GetExitCodeThread(rt, &rc);
    CHECK(rc == 0 && memcmp(out, bigIn, BIG) == 0, "big echo intact");

    struct sockaddr_storage peer; int pl = sizeof peer;
    CHECK(getpeername(c, (struct sockaddr *)&peer, &pl) == 0 && peer.ss_family == af, "getpeername");
    CHECK(shutdown(c, SD_SEND) == 0, "shutdown");
    CHECK(recv(c, buf, sizeof buf, 0) == 0, "recv EOF");
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0, "server thread");
    closesocket(c);
    closesocket(ls);
    printf("echo af=%d ok\n", af);
}

int main(void) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) { printf("WSAStartup failed\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    echo_test(AF_INET);
    echo_test(AF_INET6);

    struct addrinfo hints = {0}, *res = NULL, *p;
    hints.ai_socktype = SOCK_STREAM;
    CHECK(getaddrinfo("localhost", "8080", &hints, &res) == 0 && res, "getaddrinfo");
    int v4 = 0, v6 = 0;
    for (p = res; p; p = p->ai_next) {
        char host[64];
        CHECK(getnameinfo(p->ai_addr, (int)p->ai_addrlen, host, sizeof host, NULL, 0, NI_NUMERICHOST) == 0, "getnameinfo");
        if (p->ai_family == AF_INET) v4 = strcmp(host, "127.0.0.1") == 0;
        if (p->ai_family == AF_INET6) v6 = strcmp(host, "::1") == 0;
    }
    CHECK(v4 && v6, "localhost resolves to 127.0.0.1 and ::1");
    freeaddrinfo(res);
    printf("getaddrinfo ok\n");

    // address in use, then connection refused once the listener is gone
    SOCKET a = socket(AF_INET, SOCK_STREAM, 0), b = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int sl = sizeof sa;
    CHECK(bind(a, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(a, 1) == 0, "listen");
    getsockname(a, (struct sockaddr *)&sa, &sl);
    CHECK(bind(b, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR && WSAGetLastError() == WSAEADDRINUSE, "WSAEADDRINUSE");
    closesocket(a);
    SOCKET c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR && WSAGetLastError() == WSAECONNREFUSED, "WSAECONNREFUSED");
    printf("errors ok\n");
    WSACleanup();
    printf(fails ? "FAILED\n" : "ALL OK\n");
    return fails ? 1 : 0;
}
