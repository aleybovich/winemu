// qa_c_smoke: C guest for tests/qa_ws0_test.go (WS0 harness QA).
//
//   qa_c_smoke echo <code> [args...]  print args, stdin, %QA_VAR%; exit <code>
//   qa_c_smoke sleep <ms>             print "sleeping", sleep, exit 0
//   qa_c_smoke spawn                  start "qa_c_smoke sleep 600000" with
//                                     inherited std handles, print its pid, wait
//
// LDFLAGS: -lshell32
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	if (argc < 2) return 100;
	if (!strcmp(argv[1], "echo") && argc >= 3) {
		int wargc = 0;
		LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
		printf("argc=%d wargc=%d\n", argc, wargv ? wargc : -1);
		for (int i = 3; i < argc; i++) printf("arg[%d]=%s\n", i - 3, argv[i]);
		char buf[256];
		size_t n = fread(buf, 1, sizeof buf - 1, stdin);
		buf[n] = 0;
		printf("stdin=%s\n", buf);
		const char *v = getenv("QA_VAR");
		printf("QA_VAR=%s\n", v ? v : "(unset)");
		fprintf(stderr, "to stderr\n");
		return atoi(argv[2]);
	}
	if (!strcmp(argv[1], "sleep") && argc >= 3) {
		printf("sleeping\n");
		fflush(stdout);
		Sleep((DWORD)atoi(argv[2]));
		return 0;
	}
	if (!strcmp(argv[1], "spawn")) {
		char self[MAX_PATH], cmd[MAX_PATH + 32];
		GetModuleFileNameA(NULL, self, sizeof self);
		snprintf(cmd, sizeof cmd, "\"%s\" sleep 600000", self);
		STARTUPINFOA si = {sizeof si};
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
		PROCESS_INFORMATION pi;
		if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
			printf("CreateProcess failed %lu\n", GetLastError());
			return 101;
		}
		printf("child=%lu\n", pi.dwProcessId);
		fflush(stdout);
		WaitForSingleObject(pi.hProcess, INFINITE);
		return 0;
	}
	return 100;
}
