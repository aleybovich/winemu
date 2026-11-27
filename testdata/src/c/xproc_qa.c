// WS-E1 QA guest tests: a busy child stays accessible from another process
// (run lock released between slices), and reserve-then-commit-on-fault.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
	volatile LONG ready, stop;
	volatile LONG *addr; // child's global, read by the parent
} spinblk;

static volatile LONG g_value = 0x1234;
static char self[MAX_PATH];

static spinblk *open_blk(BOOL create) {
	HANDLE m = create ? CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, "xpqa-spin")
	                  : OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "xpqa-spin");
	return m ? (spinblk *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
}

static int spin_child(void) {
	spinblk *b = open_blk(FALSE);
	if (!b) return 2;
	b->addr = &g_value;
	InterlockedExchange(&b->ready, 1);
	while (!b->stop) {} // never idles: only slice boundaries let others in
	return 0;
}

static int spin_parent(void) {
	spinblk *b = open_blk(TRUE);
	char cmd[2 * MAX_PATH];
	STARTUPINFOA si = {sizeof si};
	PROCESS_INFORMATION pi;
	snprintf(cmd, sizeof cmd, "\"%s\" spinchild", self);
	if (!b || !CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 1;
	while (!b->ready) Sleep(1);
	int ok = 0;
	for (int i = 0; i < 50; i++) {
		LONG v = 0;
		SIZE_T n = 0;
		if (ReadProcessMemory(pi.hProcess, (LPCVOID)b->addr, &v, sizeof v, &n) && n == sizeof v && v == 0x1234) ok++;
	}
	InterlockedExchange(&b->stop, 1);
	DWORD code = 99;
	WaitForSingleObject(pi.hProcess, 10000);
	GetExitCodeProcess(pi.hProcess, &code);
	printf("rpm busy child ok=%d code=%lu\n", ok, code);
	return 0;
}

static char *g_res;
static int g_faults;

static LONG CALLBACK commit_on_fault(EXCEPTION_POINTERS *x) {
	EXCEPTION_RECORD *r = x->ExceptionRecord;
	char *a = (char *)r->ExceptionInformation[1];
	if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || a < g_res || a >= g_res + (1 << 20)) return EXCEPTION_CONTINUE_SEARCH;
	g_faults++;
	return VirtualAlloc(a, 1, MEM_COMMIT, PAGE_READWRITE) ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static int reserve(void) {
	MEMORY_BASIC_INFORMATION mi;
	g_res = VirtualAlloc(NULL, 1 << 20, MEM_RESERVE, PAGE_READWRITE);
	VirtualQuery(g_res, &mi, sizeof mi);
	printf("reserved state=%#lx protect=%#lx\n", mi.State, mi.Protect);
	AddVectoredExceptionHandler(1, commit_on_fault);
	for (int i = 0; i < 4; i++) g_res[i * 0x40000 + 8] = (char)(i + 1); // 4 untouched chunks
	int sum = 0;
	for (int i = 0; i < 4; i++) sum += g_res[i * 0x40000 + 8];
	VirtualQuery(g_res + 0x40000, &mi, sizeof mi);
	printf("faults=%d sum=%d committed state=%#lx size=%#llx\n", g_faults, sum, mi.State, (unsigned long long)mi.RegionSize);
	BOOL dec = VirtualFree(g_res, 0x1000, MEM_DECOMMIT);
	VirtualQuery(g_res, &mi, sizeof mi);
	printf("decommit=%d state=%#lx release=%d\n", dec, mi.State, VirtualFree(g_res, 0, MEM_RELEASE));
	return 0;
}

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	if (argc < 2) return 1;
	if (!strcmp(argv[1], "spinchild")) return spin_child();
	if (!strcmp(argv[1], "spin")) return spin_parent();
	if (!strcmp(argv[1], "reserve")) return reserve();
	return 1;
}
