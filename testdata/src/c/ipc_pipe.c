// Named pipe guest test (WS-E2).
//   ipc_pipe msg    : message-mode server with an overlapped ConnectNamedPipe
//                     in a signal thread; a child process uses CallNamedPipe.
//   ipc_pipe multi  : byte-mode server, two instances, two concurrent clients
//                     in child processes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static char self[MAX_PATH];

static HANDLE spawn(const char *args) {
	char cmd[1024];
	snprintf(cmd, sizeof cmd, "\"%s\" %s", self, args);
	STARTUPINFOA si = {sizeof si};
	PROCESS_INFORMATION pi;
	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("CreateProcess failed %lu\n", GetLastError());
		exit(1);
	}
	CloseHandle(pi.hThread);
	return pi.hProcess;
}

static DWORD waitCode(HANDLE p) {
	DWORD code = 99;
	WaitForSingleObject(p, INFINITE);
	GetExitCodeProcess(p, &code);
	CloseHandle(p);
	return code;
}

// ---- message mode + CallNamedPipe ----

static char msgName[128];
static volatile LONG served;

static DWORD WINAPI signalThread(LPVOID arg) {
	HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
	for (int i = 0; i < 3; i++) {
		HANDLE pipe = CreateNamedPipeA(msgName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		                               PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		                               PIPE_UNLIMITED_INSTANCES, 16, 16, 1000, NULL);
		if (pipe == INVALID_HANDLE_VALUE) {
			printf("CreateNamedPipe failed %lu\n", GetLastError());
			return 1;
		}
		if (i == 0)
			SetEvent((HANDLE)arg); // the pipe exists: start the client
		OVERLAPPED ov = {0};
		ov.hEvent = ev;
		if (!ConnectNamedPipe(pipe, &ov)) {
			DWORD err = GetLastError();
			if (err == ERROR_PIPE_CONNECTED)
				SetEvent(ev);
			else if (err != ERROR_IO_PENDING) {
				printf("ConnectNamedPipe failed %lu\n", err);
				return 1;
			}
		}
		WaitForSingleObject(ev, INFINITE);
		DWORD n;
		if (!GetOverlappedResult(pipe, &ov, &n, FALSE)) {
			printf("GetOverlappedResult failed %lu\n", GetLastError());
			return 1;
		}
		ResetEvent(ev);
		BYTE sig, reply;
		if (ReadFile(pipe, &sig, 1, &n, NULL) && n == 1) {
			reply = sig + 1;
			WriteFile(pipe, &reply, 1, &n, NULL);
			FlushFileBuffers(pipe);
			InterlockedIncrement(&served);
		} else {
			printf("server ReadFile failed %lu\n", GetLastError());
		}
		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
	}
	return 0;
}

static int msgServer(void) {
	snprintf(msgName, sizeof msgName, "\\\\.\\pipe\\ipc_sig_%lu", GetCurrentProcessId());
	HANDLE ready = CreateEventA(NULL, TRUE, FALSE, NULL);
	HANDLE th = CreateThread(NULL, 0, signalThread, ready, 0, NULL);
	WaitForSingleObject(ready, INFINITE);
	char args[64];
	snprintf(args, sizeof args, "call %lu", GetCurrentProcessId());
	DWORD code = waitCode(spawn(args));
	WaitForSingleObject(th, 5000);
	printf("client code=%lu served=%ld\n", code, served);
	return 0;
}

static int msgClient(const char *pid) {
	char name[128];
	snprintf(name, sizeof name, "\\\\.\\pipe\\ipc_sig_%s", pid);
	for (int i = 0; i < 3; i++) {
		BYTE sig = (BYTE)('a' + i), reply = 0;
		DWORD n = 0;
		BOOL ok = FALSE;
		for (int tries = 0; tries < 50 && !ok; tries++) {
			ok = CallNamedPipeA(name, &sig, 1, &reply, 1, &n, 1000);
			if (!ok && GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND)
				break;
			if (!ok)
				Sleep(10);
		}
		if (!ok) {
			printf("CallNamedPipe failed %lu\n", GetLastError());
			return 1;
		}
		printf("call %c -> %c n=%lu\n", sig, reply, n);
	}
	BYTE x;
	DWORD n;
	BOOL ok = CallNamedPipeA("\\\\.\\pipe\\ipc_no_such_pipe", &x, 1, &x, 1, &n, 100);
	printf("missing ok=%d err=%lu\n", ok, GetLastError());
	return 7;
}

// ---- byte mode, two instances, two concurrent clients ----

#define MULTI_NAME "\\\\.\\pipe\\ipc_multi"

static DWORD WINAPI instanceThread(LPVOID arg) {
	HANDLE pipe = (HANDLE)arg;
	if (!ConnectNamedPipe(pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
		printf("ConnectNamedPipe failed %lu\n", GetLastError());
		return 1;
	}
	char buf[64];
	DWORD n, total = 0;
	// read until the client's line is complete (byte mode: any split)
	while (total < sizeof buf - 1 && ReadFile(pipe, buf + total, 1, &n, NULL) && n == 1) {
		if (buf[total++] == '\n')
			break;
	}
	buf[total] = 0;
	char reply[80];
	int len = snprintf(reply, sizeof reply, "ack %s", buf);
	WriteFile(pipe, reply, len, &n, NULL);
	FlushFileBuffers(pipe);
	// the client closes: reads report a broken pipe
	BOOL ok = ReadFile(pipe, buf, 1, &n, NULL);
	return ok ? 2 : GetLastError();
}

static int multiServer(void) {
	HANDLE p[2], th[2];
	for (int i = 0; i < 2; i++) {
		p[i] = CreateNamedPipeA(MULTI_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		                        PIPE_UNLIMITED_INSTANCES, 64, 64, 0, NULL);
		if (p[i] == INVALID_HANDLE_VALUE) {
			printf("CreateNamedPipe %d failed %lu\n", i, GetLastError());
			return 1;
		}
		th[i] = CreateThread(NULL, 0, instanceThread, p[i], 0, NULL);
	}
	HANDLE c1 = spawn("client 1"), c2 = spawn("client 2");
	DWORD k1 = waitCode(c1), k2 = waitCode(c2);
	WaitForMultipleObjects(2, th, TRUE, 5000);
	DWORD r[2];
	GetExitCodeThread(th[0], &r[0]);
	GetExitCodeThread(th[1], &r[1]);
	printf("clients %lu %lu instances %lu %lu\n", k1, k2, r[0], r[1]);
	return 0;
}

static int multiClient(const char *id) {
	HANDLE h = INVALID_HANDLE_VALUE;
	for (int tries = 0; tries < 100 && h == INVALID_HANDLE_VALUE; tries++) {
		h = CreateFileA(MULTI_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h == INVALID_HANDLE_VALUE) {
			if (GetLastError() == ERROR_PIPE_BUSY)
				WaitNamedPipeA(MULTI_NAME, 1000);
			else
				Sleep(10);
		}
	}
	if (h == INVALID_HANDLE_VALUE) {
		printf("client %s: open failed %lu\n", id, GetLastError());
		return 1;
	}
	char line[32], buf[80];
	int len = snprintf(line, sizeof line, "client %s\n", id);
	DWORD n;
	WriteFile(h, line, len, &n, NULL);
	DWORD total = 0;
	while (total < sizeof buf - 1 && ReadFile(h, buf + total, sizeof buf - 1 - total, &n, NULL) && n > 0) {
		total += n;
		if (buf[total - 1] == '\n')
			break;
	}
	buf[total] = 0;
	printf("%s", buf);
	CloseHandle(h);
	return 10 + atoi(id);
}

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc >= 2 && !strcmp(argv[1], "msg"))
		return msgServer();
	if (argc >= 3 && !strcmp(argv[1], "call"))
		return msgClient(argv[2]);
	if (argc >= 2 && !strcmp(argv[1], "multi"))
		return multiServer();
	if (argc >= 3 && !strcmp(argv[1], "client"))
		return multiClient(argv[2]);
	printf("usage\n");
	return 2;
}
