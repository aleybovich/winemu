// cmd.exe / system / _popen / RegisterWaitForSingleObject guest test (WS-E2).
//   ipc_cmd run     : all checks below, printed one per line
//   ipc_cmd child ..: helper modes (-V, exit N, cat, sleep MS, args)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static char self[MAX_PATH];

static int child(int argc, char **argv) {
	if (!strcmp(argv[2], "-V")) {
		printf("ipc_cmd child 1.0\n");
		return 0;
	}
	if (!strcmp(argv[2], "exit"))
		return atoi(argv[3]);
	if (!strcmp(argv[2], "sleep")) {
		Sleep(atoi(argv[3]));
		return 3;
	}
	if (!strcmp(argv[2], "cat")) {
		char buf[256];
		size_t n = 0, k;
		while ((k = fread(buf + n, 1, sizeof buf - 1 - n, stdin)) > 0)
			n += k;
		buf[n] = 0;
		// the writer's close is end-of-file, not an error
		printf("cat got %d [%s] eof=%d err=%d\n", (int)n, buf, feof(stdin) != 0, ferror(stdin) != 0);
		return 5;
	}
	// args: echo the arguments to stdout and a line to stderr
	for (int i = 2; i < argc; i++)
		printf("arg[%d]=%s\n", i - 2, argv[i]);
	fprintf(stderr, "to stderr\n");
	int c = getchar();
	printf("stdin=%d\n", c);
	return 42;
}

static volatile LONG ticks, fired;
static HANDLE firedEv;

static DWORD WINAPI ticker(LPVOID arg) {
	while (!*(volatile LONG *)arg) {
		InterlockedIncrement(&ticks);
		Sleep(1);
	}
	return 0;
}

static VOID CALLBACK onExit(PVOID ctx, BOOLEAN timedOut) {
	InterlockedIncrement(&fired);
	if (!timedOut)
		SetEvent((HANDLE)ctx);
}

static void run(void) {
	char cmd[1024], comspec[MAX_PATH];
	GetEnvironmentVariableA("COMSPEC", comspec, sizeof comspec);
	printf("comspec=%s\n", comspec);

	// cmd /D /C ""child" args < NUL >> log.txt 2>&1"
	DeleteFileA("log.txt");
	for (int round = 0; round < 2; round++) {
		snprintf(cmd, sizeof cmd, "%s /D /C \"\"%s\" child \"a b\" c < \"NUL\" >> \"log.txt\" 2>&1\"", comspec, self);
		STARTUPINFOA si = {sizeof si};
		PROCESS_INFORMATION pi;
		BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
		DWORD code = 0;
		WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &code);
		printf("cmd ok=%d code=%lu\n", ok, code);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	FILE *f = fopen("log.txt", "r");
	char line[256];
	while (f && fgets(line, sizeof line, f))
		printf("log: %s", line);
	if (f)
		fclose(f);

	// _popen "r": the child's output
	snprintf(cmd, sizeof cmd, "\"%s\" child -V", self);
	FILE *p = _popen(cmd, "r");
	while (p && fgets(line, sizeof line, p))
		printf("popen: %s", line);
	printf("pclose=%d\n", p ? _pclose(p) : -1);

	// _popen "w": the child reads its stdin
	snprintf(cmd, sizeof cmd, "\"%s\" child cat", self);
	p = _popen(cmd, "w");
	Sleep(200); // the child reads an empty pipe first
	fputs("to child", p);
	fflush(p);
	Sleep(100);
	fputs(" more", p);
	printf("pclose w=%d\n", _pclose(p));

	// system: exit code; other threads keep running while it waits
	volatile LONG stop = 0;
	HANDLE th = CreateThread(NULL, 0, ticker, (LPVOID)&stop, 0, NULL);
	Sleep(20);
	snprintf(cmd, sizeof cmd, "\"%s\" child sleep 300", self);
	LONG before = ticks;
	int r = system(cmd);
	LONG during = ticks - before;
	stop = 1;
	WaitForSingleObject(th, INFINITE);
	printf("system=%d ticked=%d\n", r, during > 20);
	snprintf(cmd, sizeof cmd, "\"%s\" child exit 4", self);
	printf("system exit=%d\n", system(cmd));
	printf("system missing=%d\n", system("no_such_program_xyz"));
	printf("system(NULL)=%d\n", system(NULL));

	// RegisterWaitForSingleObject on a child process handle
	firedEv = CreateEventA(NULL, TRUE, FALSE, NULL);
	snprintf(cmd, sizeof cmd, "\"%s\" child sleep 200", self);
	STARTUPINFOA si = {sizeof si};
	PROCESS_INFORMATION pi;
	CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	HANDLE wh;
	BOOL ok = RegisterWaitForSingleObject(&wh, pi.hProcess, onExit, firedEv, INFINITE,
	                                      WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD);
	DWORD w = WaitForSingleObject(firedEv, 10000);
	Sleep(100);
	DWORD code = 0;
	GetExitCodeProcess(pi.hProcess, &code);
	printf("regwait ok=%d wait=%lu fired=%ld code=%lu\n", ok, w, fired, code);
	printf("unregister=%d\n", UnregisterWaitEx(wh, INVALID_HANDLE_VALUE));
	printf("ctrl=%d\n", GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId));
}

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc >= 3 && !strcmp(argv[1], "child"))
		return child(argc, argv);
	run();
	return 0;
}
