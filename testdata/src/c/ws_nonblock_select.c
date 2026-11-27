// LDFLAGS: -lws2_32
// Winsock guest test: single-threaded non-blocking echo driven by select():
// non-blocking connect (WSAEWOULDBLOCK, then writable), accept
// (WSAEWOULDBLOCK when idle), recv (WSAEWOULDBLOCK), FIONREAD, select timeout,
// and a failed non-blocking connect reported in exceptfds.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf(" (WSAGetLastError %d)\n", WSAGetLastError()); fails++; } } while (0)

static void nb(SOCKET s) { u_long on = 1; ioctlsocket(s, FIONBIO, &on); }

int main(void) {
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
    setvbuf(stdout, NULL, _IONBF, 0);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int sl = sizeof sa;
    CHECK(bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 4) == 0, "listen");
    getsockname(ls, (struct sockaddr *)&sa, &sl);
    nb(ls);
    CHECK(accept(ls, NULL, NULL) == INVALID_SOCKET && WSAGetLastError() == WSAEWOULDBLOCK, "idle accept");

    SOCKET c = socket(AF_INET, SOCK_STREAM, 0);
    nb(c);
    int r = connect(c, (struct sockaddr *)&sa, sizeof sa);
    CHECK(r == 0 || WSAGetLastError() == WSAEWOULDBLOCK, "nb connect");
    fd_set wr, rd, ex;
    struct timeval tv = {5, 0};
    FD_ZERO(&wr); FD_SET(c, &wr);
    CHECK(select(0, NULL, &wr, NULL, &tv) == 1 && FD_ISSET(c, &wr), "connect writable");

    FD_ZERO(&rd); FD_SET(ls, &rd);
    CHECK(select(0, &rd, NULL, NULL, &tv) == 1 && FD_ISSET(ls, &rd), "listener readable");
    SOCKET s = accept(ls, NULL, NULL);
    CHECK(s != INVALID_SOCKET, "accept");
    nb(s);
    char buf[256];
    CHECK(recv(s, buf, sizeof buf, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "nb recv");

    struct timeval shortTv = {0, 50000};
    FD_ZERO(&rd); FD_SET(s, &rd);
    DWORD t0 = GetTickCount();
    CHECK(select(0, &rd, NULL, NULL, &shortTv) == 0 && rd.fd_count == 0, "select timeout");
    CHECK(GetTickCount() - t0 >= 40, "select waited %lu ms", GetTickCount() - t0);

    // echo 10 rounds through select
    for (int i = 0; i < 10; i++) {
        char msg[32];
        int n = sprintf(msg, "round %d", i);
        CHECK(send(c, msg, n, 0) == n, "send");
        FD_ZERO(&rd); FD_SET(s, &rd);
        CHECK(select(0, &rd, NULL, NULL, &tv) == 1, "data readable");
        u_long avail = 0;
        ioctlsocket(s, FIONREAD, &avail);
        CHECK(avail > 0, "FIONREAD");
        int k = recv(s, buf, sizeof buf, 0);
        CHECK(k > 0, "recv");
        CHECK(send(s, buf, k, 0) == k, "echo");
        int got = 0;
        while (got < n) {
            FD_ZERO(&rd); FD_SET(c, &rd);
            if (select(0, &rd, NULL, NULL, &tv) != 1) { CHECK(0, "echo readable"); break; }
            int m = recv(c, buf + got, sizeof buf - got, 0);
            if (m <= 0) { CHECK(0, "echo recv"); break; }
            got += m;
        }
        CHECK(got == n && memcmp(buf, msg, n) == 0, "echo round %d", i);
    }

    // peer close -> readable and recv returns 0
    closesocket(c);
    FD_ZERO(&rd); FD_SET(s, &rd);
    CHECK(select(0, &rd, NULL, NULL, &tv) == 1 && recv(s, buf, sizeof buf, 0) == 0, "EOF");
    closesocket(s);
    closesocket(ls);

    // failed non-blocking connect -> exceptfds, SO_ERROR = WSAECONNREFUSED
    SOCKET f = socket(AF_INET, SOCK_STREAM, 0);
    nb(f);
    r = connect(f, (struct sockaddr *)&sa, sizeof sa);
    if (r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        FD_ZERO(&wr); FD_SET(f, &wr);
        FD_ZERO(&ex); FD_SET(f, &ex);
        CHECK(select(0, NULL, &wr, &ex, &tv) == 1 && FD_ISSET(f, &ex) && !FD_ISSET(f, &wr), "connect failure in exceptfds");
        int err = 0, el = sizeof err;
        CHECK(getsockopt(f, SOL_SOCKET, SO_ERROR, (char *)&err, &el) == 0 && err == WSAECONNREFUSED, "SO_ERROR %d", err);
    } else {
        CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAECONNREFUSED, "immediate refuse");
    }
    closesocket(f);
    WSACleanup();
    printf(fails ? "FAILED\n" : "ALL OK\n");
    return fails ? 1 : 0;
}
