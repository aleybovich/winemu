// Guest test for the block engine: code modified by Go-side API writes while
// it is hot in the block cache (docs/engine.md, tests/engine_test.go).
//
//   engine_xsmc protect   VirtualProtect RX -> RW, store, -> RX, same process
//   engine_xsmc wpm       parent WriteProcessMemory into a child's private
//                         code after the child ran it hot
//   engine_xsmc section   parent stores through its view of a shared section
//                         whose other view holds the code a child is calling
//
// Child modes: engine_xsmc wpmchild <params> | sectionchild <params>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*fn_t)(void);

typedef struct {
	unsigned char *code; // child's code address (wpm)
	volatile LONG ready; // child: code ran hot
	volatile LONG seen;  // child: last value the code returned
	volatile LONG written; // parent: code rewritten
	char name[64];       // section name
} params;

static char self[MAX_PATH];

static void emit_ret_imm(unsigned char *p, int v) { // mov eax, imm32 ; ret
	p[0] = 0xB8;
	*(int *)(p + 1) = v;
	p[5] = 0xC3;
}

static HANDLE h(const char *s) { return (HANDLE)(ULONG_PTR)strtoull(s, NULL, 0); }

static params *param_block(HANDLE *hm) {
	SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
	*hm = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(params), NULL);
	return *hm ? (params *)MapViewOfFile(*hm, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
}

// hot runs code until it is cached, waits for the parent's write, then calls
// it exactly once (a stale decoded block would still return the old value).
static int hot(params *p, fn_t f, int want) {
	for (int i = 0; i < 1000; i++)
		p->seen = f();
	InterlockedExchange(&p->ready, 1);
	DWORD t0 = GetTickCount();
	while (!p->written)
		if (GetTickCount() - t0 > 20000)
			return 20;
	p->seen = f();
	return p->seen == want ? 0 : 21;
}

static int spawn_wait(const char *mode, HANDLE hm, params *p, PROCESS_INFORMATION *pi) {
	char cmd[2 * MAX_PATH];
	STARTUPINFOA si = {sizeof si};
	snprintf(cmd, sizeof cmd, "\"%s\" %s %llu", self, mode, (unsigned long long)(ULONG_PTR)hm);
	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi))
		return 1;
	DWORD t0 = GetTickCount();
	while (!p->ready) {
		if (GetTickCount() - t0 > 20000)
			return 2;
		Sleep(1);
	}
	return 0;
}

static DWORD finish(PROCESS_INFORMATION *pi) {
	DWORD code = 99;
	WaitForSingleObject(pi->hProcess, 30000);
	GetExitCodeProcess(pi->hProcess, &code);
	CloseHandle(pi->hThread);
	CloseHandle(pi->hProcess);
	return code;
}

static int mode_protect(void) {
	unsigned char *code = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD old;
	if (!code)
		return 1;
	emit_ret_imm(code, 41);
	if (!VirtualProtect(code, 0x1000, PAGE_EXECUTE_READ, &old))
		return 2;
	int a = 0;
	for (int i = 0; i < 1000; i++)
		a = ((fn_t)code)();
	if (!VirtualProtect(code, 0x1000, PAGE_READWRITE, &old))
		return 3;
	code[1] = 42;
	if (!VirtualProtect(code, 0x1000, PAGE_EXECUTE_READ, &old))
		return 4;
	FlushInstructionCache(GetCurrentProcess(), code, 6);
	printf("protect: %d %d\n", a, ((fn_t)code)());
	return 0;
}

static int mode_wpm(void) {
	HANDLE hm;
	PROCESS_INFORMATION pi;
	params *p = param_block(&hm);
	if (!p)
		return 1;
	int r = spawn_wait("wpmchild", hm, p, &pi);
	if (r)
		return 10 + r;
	unsigned char patch = 52; // low byte of the imm32: 51 -> 52
	SIZE_T n = 0;
	if (!WriteProcessMemory(pi.hProcess, p->code + 1, &patch, 1, &n) || n != 1)
		return 13;
	FlushInstructionCache(pi.hProcess, p->code, 6);
	InterlockedExchange(&p->written, 1);
	DWORD code = finish(&pi);
	printf("wpm: child exit %lu seen %ld\n", code, p->seen);
	return 0;
}

static int wpm_child(HANDLE hm) {
	params *p = (params *)MapViewOfFile(hm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!p)
		return 30;
	unsigned char *code = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!code)
		return 31;
	emit_ret_imm(code, 51);
	p->code = code;
	return hot(p, (fn_t)code, 52);
}

static int mode_section(void) {
	HANDLE hm;
	PROCESS_INFORMATION pi;
	params *p = param_block(&hm);
	if (!p)
		return 1;
	snprintf(p->name, sizeof p->name, "engine_xsmc_%lu", GetCurrentProcessId());
	HANDLE hs = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x10000, p->name);
	if (!hs)
		return 2;
	unsigned char *view = MapViewOfFile(hs, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
	if (!view)
		return 3;
	emit_ret_imm(view, 61);
	int r = spawn_wait("sectionchild", hm, p, &pi);
	if (r)
		return 10 + r;
	view[1] = 62;
	InterlockedExchange(&p->written, 1);
	DWORD code = finish(&pi);
	printf("section: child exit %lu seen %ld\n", code, p->seen);
	return 0;
}

static int section_child(HANDLE hm) {
	params *p = (params *)MapViewOfFile(hm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!p)
		return 40;
	HANDLE hs = OpenFileMappingA(FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, FALSE, p->name);
	if (!hs)
		return 41;
	unsigned char *view = MapViewOfFile(hs, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
	if (!view)
		return 42;
	return hot(p, (fn_t)view, 62);
}

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc < 2)
		return 100;
	const char *m = argv[1];
	if (!strcmp(m, "protect"))
		return mode_protect();
	if (!strcmp(m, "wpm"))
		return mode_wpm();
	if (!strcmp(m, "section"))
		return mode_section();
	if (!strcmp(m, "wpmchild") && argc >= 3)
		return wpm_child(h(argv[2]));
	if (!strcmp(m, "sectionchild") && argc >= 3)
		return section_child(h(argv[2]));
	return 101;
}
