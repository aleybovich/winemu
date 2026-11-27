// qa_wsd: WS-D QA guest (tests/qa_wsd_test.go).
//
//   qa_wsd pipethread readfile|crtread|ntread
//       a second thread blocks reading an empty anonymous pipe while the main
//       thread keeps running, then the main thread writes one byte
//   qa_wsd inheritfile          CreateFile with bInheritHandle TRUE/FALSE, child writes to the value
//   qa_wsd writeh <handle>      WriteFile on a handle value, exit 10+HANDLE_FLAG_INHERIT or 100+GetLastError()
//   qa_wsd terminatehost        TerminateProcess of a child blocked in getchar() on a pipe
//   qa_wsd getchar              read one char from stdin
//   qa_wsd rootexit             start "sleep" children (one grandchild deep), exit 9
//   qa_wsd sleep [spawn]        (optionally start another "sleep"), then sleep forever
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

typedef LONG(NTAPI *NtReadFileFn)(HANDLE, HANDLE, void *, void *, void *, void *, ULONG, void *, void *);

static char self[MAX_PATH];
static HANDLE rd;
static const char *api;
static volatile LONG mainRan;
static char got;
static long gotN = -1;

static DWORD WINAPI reader(void *arg) {
	(void)arg;
	if (!strcmp(api, "readfile")) {
		DWORD n = 0;
		if (ReadFile(rd, &got, 1, &n, NULL)) gotN = (long)n;
	} else if (!strcmp(api, "crtread")) {
		int fd = _open_osfhandle((intptr_t)rd, _O_RDONLY | _O_BINARY);
		gotN = _read(fd, &got, 1);
	} else {
		NtReadFileFn f = (NtReadFileFn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile");
		ULONG_PTR iosb[2] = {0, 0};
		LONG st = f(rd, NULL, NULL, NULL, iosb, &got, 1, NULL, NULL);
		gotN = st == 0 ? (long)iosb[1] : -2;
	}
	return 0;
}

static int spawn(const char *args, BOOL inherit, PROCESS_INFORMATION *pi) {
	char cmd[2 * MAX_PATH];
	snprintf(cmd, sizeof cmd, "\"%s\" %s", self, args);
	STARTUPINFOA si = {sizeof si};
	if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit, 0, NULL, NULL, &si, pi)) {
		printf("CreateProcess(%s) failed %lu\n", args, GetLastError());
		return 0;
	}
	return 1;
}

static void inheritCase(BOOL inheritable) {
	char path[MAX_PATH];
	snprintf(path, sizeof path, "qa_wsd_inherit_%d.txt", inheritable);
	SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, inheritable};
	HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) {
		printf("CreateFile failed %lu\n", GetLastError());
		return;
	}
	char args[64];
	snprintf(args, sizeof args, "writeh %#llx", (unsigned long long)(ULONG_PTR)f);
	PROCESS_INFORMATION pi;
	if (!spawn(args, TRUE, &pi)) return;
	WaitForSingleObject(pi.hProcess, INFINITE);
	DWORD code = 0;
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	DWORD n;
	BOOL ok = WriteFile(f, "+parent", 7, &n, NULL); // the child's exit must not close our handle
	CloseHandle(f);
	char buf[64] = {0};
	FILE *in = fopen(path, "rb");
	if (in) {
		fread(buf, 1, sizeof buf - 1, in);
		fclose(in);
	}
	DeleteFileA(path);
	printf("inherit=%d child=%lu write=%d content=%s\n", inheritable, code, ok, buf);
}

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	if (argc >= 3 && !strcmp(argv[1], "pipethread")) {
		HANDLE wr;
		api = argv[2];
		if (!CreatePipe(&rd, &wr, NULL, 0)) return 1;
		HANDLE t = CreateThread(NULL, 0, reader, NULL, 0, NULL);
		Sleep(100); // the reader is blocked in the read by now
		for (int i = 0; i < 1000; i++) InterlockedIncrement(&mainRan);
		Sleep(50); // a timed wait: the scheduler must run us while the reader blocks
		DWORD n;
		WriteFile(wr, "x", 1, &n, NULL);
		DWORD w = WaitForSingleObject(t, 5000);
		printf("%s wait=%lu got=%ld byte=%c mainran=%ld\n", api, w, gotN, got ? got : '-', mainRan);
		return 0;
	}
	if (argc >= 3 && !strcmp(argv[1], "writeh")) {
		HANDLE h = (HANDLE)(ULONG_PTR)strtoull(argv[2], NULL, 0);
		DWORD n, fl = 0;
		if (!WriteFile(h, "inherited", 9, &n, NULL)) return 100 + (int)GetLastError();
		GetHandleInformation(h, &fl);
		return 10 + (int)(fl & HANDLE_FLAG_INHERIT); // inherited handles stay inheritable
	}
	if (argc >= 2 && !strcmp(argv[1], "getchar")) {
		return getchar() == EOF ? 2 : 1;
	}
	if (argc >= 2 && !strcmp(argv[1], "terminatehost")) {
		// the child blocks inside a CRT stream read of its stdin pipe
		SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
		HANDLE r, w;
		if (!CreatePipe(&r, &w, &sa, 0)) return 1;
		SetHandleInformation(w, HANDLE_FLAG_INHERIT, 0);
		char cmd[2 * MAX_PATH];
		snprintf(cmd, sizeof cmd, "\"%s\" getchar", self);
		STARTUPINFOA si = {sizeof si};
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = r;
		si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
		PROCESS_INFORMATION pi;
		if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) return 1;
		CloseHandle(r);
		Sleep(300);
		BOOL t = TerminateProcess(pi.hProcess, 77);
		DWORD wr = WaitForSingleObject(pi.hProcess, 5000), code = 0;
		GetExitCodeProcess(pi.hProcess, &code);
		printf("terminate=%d wait=%lu code=%lu\n", t, wr, code);
		return 0;
	}
	if (argc >= 2 && !strcmp(argv[1], "inheritfile")) {
		inheritCase(TRUE);
		inheritCase(FALSE);
		return 0;
	}
	PROCESS_INFORMATION pi;
	if (argc >= 2 && !strcmp(argv[1], "rootexit")) {
		if (!spawn("sleep spawn", FALSE, &pi)) return 1;
		Sleep(200);
		printf("root done\n");
		return 9;
	}
	if (argc >= 2 && !strcmp(argv[1], "sleep")) {
		if (argc >= 3 && !spawn("sleep", FALSE, &pi)) return 1;
		for (;;) Sleep(1000);
	}
	return 100;
}
