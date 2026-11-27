// mp_proc: multi-process guest for tests/multiprocess_test.go (WS-D).
//
//   mp_proc exit <code> [sleep_ms]   sleep, print "child <pid>", exit <code>
//   mp_proc setevent <handle>        SetEvent on an inherited handle value, exit 0
//   mp_proc sleep                    sleep forever (to be terminated)
//   mp_proc deadlock                 wait forever on an event nobody can set
//   mp_proc orphan                   start "exit 5 500" without waiting, exit 3
//   mp_proc waitdeadlocked           start "deadlock", wait INFINITE, print its code
//   mp_proc parent                   run every scenario, print results, exit 0
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char self[MAX_PATH];

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

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	if (argc >= 3 && !strcmp(argv[1], "exit")) {
		if (argc >= 4) Sleep((DWORD)atoi(argv[3]));
		printf("child %lu\n", GetCurrentProcessId());
		fflush(stdout);
		return atoi(argv[2]);
	}
	if (argc >= 3 && !strcmp(argv[1], "setevent")) {
		HANDLE h = (HANDLE)(ULONG_PTR)strtoull(argv[2], NULL, 0);
		return SetEvent(h) ? 0 : 100 + (int)GetLastError();
	}
	if (argc >= 2 && !strcmp(argv[1], "sleep")) {
		for (;;) Sleep(1000);
	}
	if (argc >= 2 && !strcmp(argv[1], "deadlock")) {
		WaitForSingleObject(CreateEventA(NULL, TRUE, FALSE, NULL), INFINITE);
		return 1;
	}
	PROCESS_INFORMATION pi;
	DWORD code = 0;
	if (argc >= 2 && !strcmp(argv[1], "orphan")) {
		if (!spawn("exit 5 500", FALSE, &pi)) return 1;
		printf("parent done\n");
		return 3;
	}
	if (argc >= 2 && !strcmp(argv[1], "waitdeadlocked")) {
		if (!spawn("deadlock", FALSE, &pi)) return 1;
		DWORD w = WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &code);
		printf("wait=%lu code=%#lx\n", w, code);
		return 0;
	}
	if (argc < 2 || strcmp(argv[1], "parent")) return 100;

	// 1. INFINITE wait on a child that runs longer than the deadlock window
	if (!spawn("exit 7 3000", FALSE, &pi)) return 1;
	DWORD w = WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	printf("wait=%lu code=%lu pidmatch=%d\n", w, code, GetProcessId(pi.hProcess) == pi.dwProcessId);
	printf("thread wait=%lu\n", WaitForSingleObject(pi.hThread, 0));
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// 2. GetExitCodeProcess while running, OpenProcess by pid, TerminateProcess
	if (!spawn("sleep", FALSE, &pi)) return 1;
	GetExitCodeProcess(pi.hProcess, &code);
	printf("running code=%lu\n", code);
	HANDLE h2 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	printf("open=%d same=%d\n", h2 != NULL, h2 && GetProcessId(h2) == pi.dwProcessId);
	printf("terminate=%d\n", TerminateProcess(h2, 42));
	w = WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	printf("terminated wait=%lu code=%lu\n", w, code);
	SetLastError(0);
	printf("terminate again=%d err=%lu\n", TerminateProcess(h2, 1), GetLastError());
	CloseHandle(h2);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	SetLastError(0);
	printf("open stale=%d err=%lu\n", OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId) != NULL, GetLastError());

	// 3. inherited event: identical handle value in the child wakes the parent
	SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
	HANDLE ev = CreateEventA(&sa, TRUE, FALSE, NULL);
	char args[64];
	snprintf(args, sizeof args, "setevent %#llx", (unsigned long long)(ULONG_PTR)ev);
	if (!spawn(args, TRUE, &pi)) return 1;
	w = WaitForSingleObject(ev, INFINITE);
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	printf("event wait=%lu child code=%lu\n", w, code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// 4. not inherited: the same value is invalid in the child
	HANDLE ev2 = CreateEventA(NULL, TRUE, FALSE, NULL);
	snprintf(args, sizeof args, "setevent %#llx", (unsigned long long)(ULONG_PTR)ev2);
	if (!spawn(args, TRUE, &pi)) return 1;
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	printf("uninherited child code=%lu signaled=%lu\n", code, WaitForSingleObject(ev2, 0));
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// 5. WaitForMultipleObjects on two children (wait all)
	PROCESS_INFORMATION a, b;
	if (!spawn("exit 1 200", FALSE, &a) || !spawn("exit 2 400", FALSE, &b)) return 1;
	HANDLE both[2] = {a.hProcess, b.hProcess};
	w = WaitForMultipleObjects(2, both, TRUE, INFINITE);
	DWORD ca, cb;
	GetExitCodeProcess(a.hProcess, &ca);
	GetExitCodeProcess(b.hProcess, &cb);
	printf("waitall=%lu codes=%lu,%lu\n", w, ca, cb);
	return 0;
}
