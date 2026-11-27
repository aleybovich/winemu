// LDFLAGS: -lws2_32
// Winsock guest test: WSAEventSelect server loop (WaitForMultipleObjects +
// WSAEnumNetworkEvents) serving clients that run on another thread with
// blocking calls. Checks FD_ACCEPT/FD_READ/FD_WRITE/FD_CLOSE delivery and
// the re-enabling rules.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CLIENTS 3
static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf(" (WSAGetLastError %d)\n", WSAGetLastError()); fails++; } } while (0)

static struct sockaddr_in addr;

static DWORD WINAPI client(LPVOID p) {
    int id = (int)(INT_PTR)p;
    SOCKET c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&addr, sizeof addr) != 0) return 1;
    char msg[64], buf[64];
    int n = sprintf(msg, "client %d says hi", id);
    for (int i = 0; i < 3; i++) {
        if (send(c, msg, n, 0) != n) return 2;
        if (recv(c, buf, n, MSG_WAITALL) != n || memcmp(buf, msg, n) != 0) return 3;
    }
    closesocket(c);
    return 0;
}

int main(void) {
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
    setvbuf(stdout, NULL, _IONBF, 0);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int al = sizeof addr;
    CHECK(bind(ls, (struct sockaddr *)&addr, sizeof addr) == 0 && listen(ls, 8) == 0, "listen");
    getsockname(ls, (struct sockaddr *)&addr, &al);

    SOCKET socks[WSA_MAXIMUM_WAIT_EVENTS];
    WSAEVENT evs[WSA_MAXIMUM_WAIT_EVENTS];
    int nsock = 1;
    socks[0] = ls;
    evs[0] = WSACreateEvent();
    CHECK(WSAEventSelect(ls, evs[0], FD_ACCEPT) == 0, "WSAEventSelect listener");
    u_long off = 0;
    CHECK(ioctlsocket(ls, FIONBIO, &off) == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "FIONBIO off while selected");

    HANDLE th[CLIENTS];
    for (int i = 0; i < CLIENTS; i++) th[i] = CreateThread(NULL, 0, client, (LPVOID)(INT_PTR)i, 0, NULL);

    int accepted = 0, closed = 0, reads = 0, writes = 0;
    while (closed < CLIENTS) {
        DWORD w = WaitForMultipleObjects(nsock, evs, FALSE, 10000);
        if (w == WAIT_TIMEOUT) { CHECK(0, "server timed out (accepted %d closed %d)", accepted, closed); break; }
        int i = (int)(w - WAIT_OBJECT_0);
        WSANETWORKEVENTS ne;
        CHECK(WSAEnumNetworkEvents(socks[i], evs[i], &ne) == 0, "WSAEnumNetworkEvents");
        if (ne.lNetworkEvents & FD_ACCEPT) {
            CHECK(ne.iErrorCode[FD_ACCEPT_BIT] == 0, "FD_ACCEPT error");
            SOCKET s = accept(ls, NULL, NULL);
            if (s == INVALID_SOCKET) {
                CHECK(WSAGetLastError() == WSAEWOULDBLOCK, "accept");
            } else {
                accepted++;
                socks[nsock] = s;
                evs[nsock] = WSACreateEvent();
                CHECK(WSAEventSelect(s, evs[nsock], FD_READ | FD_WRITE | FD_CLOSE) == 0, "WSAEventSelect conn");
                nsock++;
            }
        }
        if (ne.lNetworkEvents & FD_WRITE) writes++;
        if (ne.lNetworkEvents & FD_READ) {
            char buf[256];
            int n = recv(socks[i], buf, sizeof buf, 0);
            if (n > 0) {
                reads++;
                CHECK(send(socks[i], buf, n, 0) == n, "echo send");
            } else {
                CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "recv after FD_READ %d", n);
            }
        }
        if (ne.lNetworkEvents & FD_CLOSE) {
            CHECK(ne.iErrorCode[FD_CLOSE_BIT] == 0, "FD_CLOSE error %d", ne.iErrorCode[FD_CLOSE_BIT]);
            char buf[256];
            while (recv(socks[i], buf, sizeof buf, 0) > 0) {}
            closesocket(socks[i]);
            WSACloseEvent(evs[i]);
            socks[i] = socks[nsock - 1];
            evs[i] = evs[nsock - 1];
            nsock--;
            closed++;
        }
    }
    CHECK(WaitForMultipleObjects(CLIENTS, th, TRUE, 10000) == WAIT_OBJECT_0, "clients done");
    for (int i = 0; i < CLIENTS; i++) {
        DWORD rc = 99;
        GetExitCodeThread(th[i], &rc);
        CHECK(rc == 0, "client %d exit %lu", i, rc);
    }
    CHECK(accepted == CLIENTS && writes >= CLIENTS && reads >= CLIENTS, "accepted %d writes %d reads %d", accepted, writes, reads);
    printf("accepted=%d closed=%d\n", accepted, closed);
    closesocket(ls);
    WSACleanup();
    printf(fails ? "FAILED\n" : "ALL OK\n");
    return fails ? 1 : 0;
}
