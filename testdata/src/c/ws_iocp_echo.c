// LDFLAGS: -lws2_32 -lmswsock
// Overlapped sockets: AcceptEx/ConnectEx echo over an I/O completion port
// served by a worker thread (GetQueuedCompletionStatus), plus WSARecv with
// a completion routine run by an alertable SleepEx.
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CHECK(c, msg) do { if (!(c)) { printf("FAIL %s (err %d, line %d)\n", msg, WSAGetLastError(), __LINE__); return 1; } } while (0)

enum { OP_ACCEPT = 1, OP_RECV, OP_SEND };

typedef struct {
    OVERLAPPED ov;
    int op;
    SOCKET s;
    WSABUF wb;
    char buf[256];
} IoCtx;

static HANDLE port;
static SOCKET listener;
static LPFN_CONNECTEX pConnectEx;
static int served;

static int post_recv(IoCtx *c) {
    DWORD flags = 0;
    memset(&c->ov, 0, sizeof c->ov);
    c->op = OP_RECV;
    c->wb.buf = c->buf;
    c->wb.len = sizeof c->buf;
    if (WSARecv(c->s, &c->wb, 1, NULL, &flags, &c->ov, NULL) == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) return -1;
    return 0;
}

// echo server: accept one connection, echo until EOF
static DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    for (;;) {
        DWORD n; ULONG_PTR key; OVERLAPPED *ov;
        BOOL ok = GetQueuedCompletionStatus(port, &n, &key, &ov, 10000);
        if (!ov) { printf("worker: GQCS timeout/err %lu\n", GetLastError()); return 1; }
        IoCtx *c = (IoCtx *)ov;
        if (!ok) { printf("worker: op %d failed %lu\n", c->op, GetLastError()); return 1; }
        switch (c->op) {
        case OP_ACCEPT:
            if (setsockopt(c->s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&listener, sizeof listener)) return 2;
            if (!CreateIoCompletionPort((HANDLE)c->s, port, 2, 0)) return 3;
            if (post_recv(c)) return 4;
            break;
        case OP_RECV:
            if (n == 0) { closesocket(c->s); return 0; } // client closed
            memset(&c->ov, 0, sizeof c->ov);
            c->op = OP_SEND;
            c->wb.len = n;
            if (WSASend(c->s, &c->wb, 1, NULL, 0, &c->ov, NULL) == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) return 5;
            break;
        case OP_SEND:
            served++;
            if (post_recv(c)) return 6;
            break;
        }
    }
}

static int crCalls;
static DWORD crBytes;
static void CALLBACK on_recv(DWORD err, DWORD n, LPWSAOVERLAPPED ov, DWORD flags) {
    (void)ov; (void)flags;
    if (err == 0) { crCalls++; crBytes = n; }
}

int main(void) {
    WSADATA wd;
    CHECK(WSAStartup(MAKEWORD(2, 2), &wd) == 0, "WSAStartup");
    port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(port, "CreateIoCompletionPort");

    listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listener, (struct sockaddr *)&a, sizeof a) == 0, "bind");
    CHECK(listen(listener, 5) == 0, "listen");
    int alen = sizeof a;
    getsockname(listener, (struct sockaddr *)&a, &alen);
    CHECK(CreateIoCompletionPort((HANDLE)listener, port, 1, 0) == port, "associate listener");

    // AcceptEx (direct mswsock import)
    static IoCtx actx;
    actx.op = OP_ACCEPT;
    actx.s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    DWORD got = 0;
    if (!AcceptEx(listener, actx.s, actx.buf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &got, &actx.ov))
        CHECK(WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx");
    HANDLE th = CreateThread(NULL, 0, worker, NULL, 0, NULL);

    // client: ConnectEx via WSAIoctl, waited for with the OVERLAPPED event
    SOCKET c = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    GUID gid = WSAID_CONNECTEX;
    DWORD nret;
    CHECK(WSAIoctl(c, SIO_GET_EXTENSION_FUNCTION_POINTER, &gid, sizeof gid, &pConnectEx, sizeof pConnectEx, &nret, NULL, NULL) == 0, "get ConnectEx");
    struct sockaddr_in any = {0};
    any.sin_family = AF_INET;
    CHECK(bind(c, (struct sockaddr *)&any, sizeof any) == 0, "bind client");
    OVERLAPPED cov = {0};
    cov.hEvent = WSACreateEvent();
    if (!pConnectEx(c, (struct sockaddr *)&a, sizeof a, NULL, 0, NULL, &cov))
        CHECK(WSAGetLastError() == ERROR_IO_PENDING, "ConnectEx");
    DWORD n, fl;
    CHECK(WSAGetOverlappedResult(c, &cov, &n, TRUE, &fl), "ConnectEx result");
    CHECK(setsockopt(c, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0, "SO_UPDATE_CONNECT_CONTEXT");

    // echo rounds: blocking send, recv with a completion routine
    for (int i = 0; i < 5; i++) {
        char msg[32], back[64] = {0};
        int len = sprintf(msg, "round %d", i);
        CHECK(send(c, msg, len, 0) == len, "send");
        WSAOVERLAPPED rov = {0};
        WSABUF wb = {sizeof back, back};
        DWORD flags = 0;
        crCalls = 0;
        if (WSARecv(c, &wb, 1, NULL, &flags, &rov, on_recv) == SOCKET_ERROR)
            CHECK(WSAGetLastError() == WSA_IO_PENDING, "WSARecv(routine)");
        while (crCalls == 0) CHECK(SleepEx(5000, TRUE) == WAIT_IO_COMPLETION, "SleepEx alertable");
        CHECK(crBytes == (DWORD)len && memcmp(back, msg, len) == 0, "echo data");
    }
    closesocket(c);
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0, "worker exit");
    DWORD code;
    GetExitCodeThread(th, &code);
    CHECK(code == 0 && served == 5, "worker result");

    // CancelIoEx of a pending AcceptEx: the packet reports ERROR_OPERATION_ABORTED
    IoCtx c2 = {0};
    c2.s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (!AcceptEx(listener, c2.s, c2.buf, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &got, &c2.ov))
        CHECK(WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx 2");
    CHECK(CancelIoEx((HANDLE)listener, &c2.ov), "CancelIoEx");
    ULONG_PTR key; OVERLAPPED *ov;
    CHECK(!GetQueuedCompletionStatus(port, &n, &key, &ov, 5000) && ov == &c2.ov && GetLastError() == ERROR_OPERATION_ABORTED, "aborted completion");
    printf("served %d echoes\nALL OK\n", served);
    return 0;
}
