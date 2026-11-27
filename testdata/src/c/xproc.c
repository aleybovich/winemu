// xproc: cross-process memory & handles guest for tests/xproc_test.go (WS-E1).
//
//   xproc shm          suspended child + VirtualAllocEx reservation + named
//                      section at the same fixed address in both processes,
//                      shared InterlockedIncrement counter, duplicated event
//   xproc job          kill-on-close job, grandchild joins, breakaway refused
//   xproc asuser       CreateRestrictedToken + CreateProcessAsUserA
//   xproc handlelist   PROC_THREAD_ATTRIBUTE_HANDLE_LIST limits inheritance
//
// Child modes (started by the modes above):
//   xproc shmchild <param mapping handle>
//   xproc jobchild <param mapping handle>
//   xproc sleep | xproc exit <code> | xproc setevents <h1> <h2>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_INC 1000000
#define SHM_SIZE 0x20000

static char self[MAX_PATH];

typedef struct {
	void *base;       // fixed address of the shared section
	SIZE_T size;
	char name[64];    // section name
	HANDLE event;     // event duplicated into the child
	char *wpm;        // address in the child written by WriteProcessMemory
	DWORD gcpid;      // job: grandchild pid
	DWORD gcinjob;    // job: IsProcessInJob(grandchild) in the child
	DWORD breakerr;   // job: GetLastError of the refused breakaway
	HANDLE ready;     // job: inherited event set when the child is set up
} params;

typedef struct {
	volatile LONG ready;
	volatile LONG counter;
} shared;

static HANDLE h(const char *s) { return (HANDLE)(ULONG_PTR)strtoull(s, NULL, 0); }

static BOOL spawn(const char *args, BOOL inherit, DWORD flags, STARTUPINFOA *si, PROCESS_INFORMATION *pi) {
	char cmd[2 * MAX_PATH];
	STARTUPINFOA def = {sizeof def};
	snprintf(cmd, sizeof cmd, "\"%s\" %s", self, args);
	return CreateProcessA(NULL, cmd, NULL, NULL, inherit, flags, NULL, NULL, si ? si : &def, pi);
}

// anonymous inheritable mapping holding a params block
static params *param_block(HANDLE *hm) {
	SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
	*hm = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(params), NULL);
	return *hm ? (params *)MapViewOfFile(*hm, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
}

static void bump(shared *s) {
	while (s->ready < 2) YieldProcessor();
	for (int i = 0; i < N_INC; i++) InterlockedIncrement(&s->counter);
}

static int shm_child(HANDLE hm) {
	params *p = (params *)MapViewOfFile(hm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!p) return 10;
	if (memcmp(p->wpm, "written by parent", 18)) return 11;
	HANDLE hs = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, p->name);
	if (!hs) return 12;
	// the reservation still occupies the address
	if (MapViewOfFileEx(hs, FILE_MAP_ALL_ACCESS, 0, 0, 0, p->base) || GetLastError() != ERROR_INVALID_ADDRESS) return 13;
	if (!VirtualFree(p->base, 0, MEM_RELEASE)) return 14;
	shared *s = (shared *)MapViewOfFileEx(hs, FILE_MAP_ALL_ACCESS, 0, 0, 0, p->base);
	if ((void *)s != p->base) return 15;
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(s, &mbi, sizeof mbi) || mbi.Type != MEM_MAPPED || mbi.State != MEM_COMMIT) return 16;
	HANDLE again = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHM_SIZE, p->name);
	if (!again || GetLastError() != ERROR_ALREADY_EXISTS) return 17;
	CloseHandle(again);
	InterlockedIncrement(&s->ready);
	bump(s);
	if (!SetEvent(p->event)) return 18;
	return 0;
}

static int shm_parent(void) {
	HANDLE hm, ev = CreateEventA(NULL, TRUE, FALSE, NULL); // not inheritable
	params *p = param_block(&hm);
	if (!p || !ev) return 1;
	snprintf(p->name, sizeof p->name, "Local\\xproc_shm_%lu", GetCurrentProcessId());
	HANDLE hs = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHM_SIZE, p->name);
	printf("create=%d err=%lu\n", hs != NULL, GetLastError());
	shared *s = (shared *)MapViewOfFile(hs, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!s) return 2;
	p->base = s, p->size = SHM_SIZE;

	char args[64];
	PROCESS_INFORMATION pi;
	snprintf(args, sizeof args, "shmchild %#llx", (unsigned long long)(ULONG_PTR)hm);
	if (!spawn(args, TRUE, CREATE_SUSPENDED, NULL, &pi)) return 3;
	void *r = VirtualAllocEx(pi.hProcess, s, SHM_SIZE, MEM_RESERVE, PAGE_NOACCESS);
	printf("reserve same=%d\n", r == (void *)s);
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T q = VirtualQueryEx(pi.hProcess, s, &mbi, sizeof mbi);
	printf("query=%d reserved=%d\n", q == sizeof mbi, mbi.State != MEM_FREE && mbi.AllocationBase == (void *)s);

	char *page = (char *)VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	char buf[32] = {0};
	SIZE_T nw = 0, nr = 0;
	BOOL w = WriteProcessMemory(pi.hProcess, page, "written by parent", 18, &nw);
	BOOL rd = ReadProcessMemory(pi.hProcess, page, buf, 18, &nr);
	printf("wpm=%d/%zu rpm=%d/%zu %s\n", w, nw, rd, nr, buf);
	p->wpm = page;

	BOOL d = DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &p->event, 0, FALSE, DUPLICATE_SAME_ACCESS);
	printf("dup=%d\n", d);
	printf("resume=%lu\n", ResumeThread(pi.hThread));
	InterlockedIncrement(&s->ready);
	bump(s);
	DWORD we = WaitForSingleObject(ev, 30000);
	DWORD wp = WaitForSingleObject(pi.hProcess, 30000), code = 99;
	GetExitCodeProcess(pi.hProcess, &code);
	printf("event=%lu child=%lu code=%lu counter=%ld\n", we, wp, code, s->counter);
	return 0;
}

static int job_child(HANDLE hm) {
	params *p = (params *)MapViewOfFile(hm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!p) return 10;
	PROCESS_INFORMATION pi;
	if (!spawn("sleep", FALSE, 0, NULL, &pi)) return 11;
	BOOL in = FALSE;
	IsProcessInJob(pi.hProcess, NULL, &in);
	p->gcpid = pi.dwProcessId, p->gcinjob = in;
	PROCESS_INFORMATION bp;
	p->breakerr = spawn("exit 0", FALSE, CREATE_BREAKAWAY_FROM_JOB, NULL, &bp) ? 0 : GetLastError();
	SetEvent(p->ready);
	for (;;) Sleep(1000);
}

static int job_parent(void) {
	SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
	HANDLE hm;
	params *p = param_block(&hm);
	if (!p || !(p->ready = CreateEventA(&sa, TRUE, FALSE, NULL))) return 1;
	HANDLE job = CreateJobObjectA(NULL, NULL);
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION li = {0};
	li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	printf("setinfo=%d\n", SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li));

	char args[64];
	PROCESS_INFORMATION pi;
	snprintf(args, sizeof args, "jobchild %#llx", (unsigned long long)(ULONG_PTR)hm);
	if (!spawn(args, TRUE, CREATE_SUSPENDED, NULL, &pi)) return 2;
	BOOL in = TRUE;
	IsProcessInJob(pi.hProcess, job, &in);
	printf("before assign injob=%d\n", in);
	printf("assign=%d\n", AssignProcessToJobObject(job, pi.hProcess));
	IsProcessInJob(pi.hProcess, job, &in);
	printf("after assign injob=%d\n", in);
	ResumeThread(pi.hThread);
	printf("ready=%lu\n", WaitForSingleObject(p->ready, 30000));
	printf("grandchild injob=%lu breakaway err=%lu\n", p->gcinjob, p->breakerr);
	JOBOBJECT_BASIC_ACCOUNTING_INFORMATION ai;
	QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &ai, sizeof ai, NULL);
	printf("active=%lu total=%lu\n", ai.ActiveProcesses, ai.TotalProcesses);
	HANDLE gc = OpenProcess(SYNCHRONIZE, FALSE, p->gcpid);
	printf("child alive=%lu\n", WaitForSingleObject(pi.hProcess, 0));
	CloseHandle(job);
	DWORD wc = WaitForSingleObject(pi.hProcess, 10000), wg = gc ? WaitForSingleObject(gc, 10000) : 99;
	printf("after close child=%lu grandchild=%lu\n", wc, wg);
	return 0;
}

static int asuser(void) {
	HANDLE tok, rt;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok)) return 1;
	if (!CreateRestrictedToken(tok, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &rt)) return 2;
	char cmd[2 * MAX_PATH];
	snprintf(cmd, sizeof cmd, "\"%s\" exit 9", self);
	STARTUPINFOA si = {sizeof si};
	PROCESS_INFORMATION pi;
	BOOL ok = CreateProcessAsUserA(rt, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	DWORD code = 99;
	if (ok) {
		WaitForSingleObject(pi.hProcess, 30000);
		GetExitCodeProcess(pi.hProcess, &code);
	}
	printf("asuser=%d code=%lu\n", ok, code);
	HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL); // not a token
	ok = CreateProcessAsUserA(ev, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	printf("bad token=%d err=%lu\n", ok, GetLastError());
	return 0;
}

// spawn "setevents a b" inheriting either everything or only a
static void handlelist_case(const char *label, BOOL list) {
	SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
	HANDLE a = CreateEventA(&sa, TRUE, FALSE, NULL), b = CreateEventA(&sa, TRUE, FALSE, NULL);
	char args[64];
	snprintf(args, sizeof args, "setevents %#llx %#llx", (unsigned long long)(ULONG_PTR)a, (unsigned long long)(ULONG_PTR)b);
	STARTUPINFOEXA si = {{sizeof si}};
	DWORD flags = 0;
	if (list) {
		SIZE_T n = 0;
		BOOL probe = InitializeProcThreadAttributeList(NULL, 1, 0, &n);
		printf("probe=%d err=%lu size>0=%d\n", probe, GetLastError(), n > 0);
		si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(n);
		BOOL init = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &n);
		BOOL upd = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &a, sizeof a, NULL, NULL);
		printf("init=%d update=%d\n", init, upd);
		flags = EXTENDED_STARTUPINFO_PRESENT;
	}
	PROCESS_INFORMATION pi;
	if (!spawn(args, TRUE, flags, (STARTUPINFOA *)&si, &pi)) {
		printf("%s: CreateProcess failed %lu\n", label, GetLastError());
		return;
	}
	if (list) {
		DeleteProcThreadAttributeList(si.lpAttributeList);
		free(si.lpAttributeList);
	}
	DWORD code = 99;
	WaitForSingleObject(pi.hProcess, 30000);
	GetExitCodeProcess(pi.hProcess, &code);
	printf("%s: code=%lu a=%lu b=%lu\n", label, code, WaitForSingleObject(a, 0), WaitForSingleObject(b, 0));
}

int main(int argc, char **argv) {
	GetModuleFileNameA(NULL, self, sizeof self);
	if (argc < 2) return 100;
	const char *m = argv[1];
	if (!strcmp(m, "shmchild") && argc >= 3) return shm_child(h(argv[2]));
	if (!strcmp(m, "jobchild") && argc >= 3) return job_child(h(argv[2]));
	if (!strcmp(m, "exit") && argc >= 3) return atoi(argv[2]);
	if (!strcmp(m, "sleep"))
		for (;;) Sleep(1000);
	if (!strcmp(m, "setevents") && argc >= 4) // bit 0/1: SetEvent on a/b succeeded
		return (SetEvent(h(argv[2])) ? 1 : 0) | (SetEvent(h(argv[3])) ? 2 : 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!strcmp(m, "shm")) return shm_parent();
	if (!strcmp(m, "job")) return job_parent();
	if (!strcmp(m, "asuser")) return asuser();
	if (!strcmp(m, "handlelist")) {
		handlelist_case("all", FALSE);
		handlelist_case("list", TRUE);
		return 0;
	}
	return 100;
}
