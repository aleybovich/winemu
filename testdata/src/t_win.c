#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <shellapi.h>

static int fails = 0;
#define CHECK(c, name) do { if (c) printf("PASS %s\n", name); else { printf("FAIL %s (line %d, err %lu)\n", name, __LINE__, GetLastError()); fails++; } } while (0)

static volatile LONG counter = 0;
static CRITICAL_SECTION cs; static long cs_total = 0;
static SRWLOCK srw = SRWLOCK_INIT; static CONDITION_VARIABLE cv = CONDITION_VARIABLE_INIT; static int ready = 0;
static HANDLE ev;
static __thread int tls_var = 5;
static DWORD tls_idx;

static DWORD WINAPI worker(LPVOID p) {
    int id = (int)(INT_PTR)p;
    tls_var = id * 100; TlsSetValue(tls_idx, (LPVOID)(INT_PTR)(id + 1));
    for (int i = 0; i < 2000; i++) { InterlockedIncrement(&counter); EnterCriticalSection(&cs); cs_total += id; LeaveCriticalSection(&cs); if ((i & 255) == 0) Sleep(0); }
    if (tls_var != id * 100 || (INT_PTR)TlsGetValue(tls_idx) != id + 1) return 999;
    return id;
}
static DWORD WINAPI waiter(LPVOID p) {
    AcquireSRWLockExclusive(&srw); while (!ready) SleepConditionVariableSRW(&cv, &srw, INFINITE, 0); ReleaseSRWLockExclusive(&srw);
    WaitForSingleObject(ev, INFINITE); return 7;
}
static volatile int av_count = 0;
static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        av_count++;
        ep->ContextRecord->Rip += 3;      // skip "mov eax, [rax]" style 3-byte instruction? we use a known sequence
        ep->ContextRecord->Rax = 1234;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ep->ExceptionRecord->ExceptionCode == 0xE0001234) { av_count += 10; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    // ---- threads & sync ----
    InitializeCriticalSection(&cs); tls_idx = TlsAlloc(); ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE th[4]; DWORD tid;
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)i, 0, &tid);
    DWORD wr = WaitForMultipleObjects(4, th, TRUE, 10000);
    CHECK(wr == WAIT_OBJECT_0, "WaitForMultipleObjects all");
    DWORD codes = 0; for (int i = 0; i < 4; i++) { DWORD c; GetExitCodeThread(th[i], &c); codes += c; CloseHandle(th[i]); }
    CHECK(codes == 0 + 1 + 2 + 3, "thread exit codes + TLS isolation");
    CHECK(counter == 8000, "InterlockedIncrement");
    CHECK(cs_total == 2000 * 6, "CriticalSection");
    CHECK(tls_var == 5, "static __thread on main");
    HANDLE w = CreateThread(NULL, 0, waiter, NULL, 0, NULL);
    CHECK(WaitForSingleObject(w, 50) == WAIT_TIMEOUT, "wait timeout");
    AcquireSRWLockExclusive(&srw); ready = 1; ReleaseSRWLockExclusive(&srw); WakeAllConditionVariable(&cv);
    SetEvent(ev);
    CHECK(WaitForSingleObject(w, 5000) == WAIT_OBJECT_0, "condvar + event wakeup");
    DWORD wc; GetExitCodeThread(w, &wc); CHECK(wc == 7, "waiter exit code");
    HANDLE sem = CreateSemaphoreW(NULL, 2, 2, NULL);
    CHECK(WaitForSingleObject(sem, 0) == 0 && WaitForSingleObject(sem, 0) == 0 && WaitForSingleObject(sem, 0) == WAIT_TIMEOUT, "semaphore");
    HANDLE mtx = CreateMutexW(NULL, FALSE, L"winemu_test_mutex");
    CHECK(WaitForSingleObject(mtx, 0) == 0 && ReleaseMutex(mtx), "mutex");
    DWORD t0 = GetTickCount(); Sleep(30); DWORD el = GetTickCount() - t0;
    CHECK(el >= 25 && el < 2000, "Sleep/GetTickCount");
    LARGE_INTEGER f, q1, q2; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&q1); Sleep(5); QueryPerformanceCounter(&q2);
    CHECK(f.QuadPart > 0 && q2.QuadPart > q1.QuadPart, "QueryPerformanceCounter");

    // ---- exceptions ----
    PVOID h = AddVectoredExceptionHandler(1, veh);
    volatile int *bad = (int*)0x10;
    int v = 0;
    __asm__ volatile("mov (%1), %%eax\n\tnop\n\tmov %%eax, %0" : "=r"(v) : "r"(bad) : "rax");   // 2-byte mov + 1-byte nop
    CHECK(av_count == 1 && v == 1234, "vectored handler fixes access violation");
    RaiseException(0xE0001234, 0, 0, NULL);
    CHECK(av_count == 11, "RaiseException continuable");
    RemoveVectoredExceptionHandler(h);

    // ---- files & directories ----
    WCHAR dir[] = L"winemu_dir_test";
    RemoveDirectoryW(dir);
    CHECK(CreateDirectoryW(dir, NULL), "CreateDirectoryW");
    CHECK(!CreateDirectoryW(dir, NULL) && GetLastError() == ERROR_ALREADY_EXISTS, "CreateDirectory exists error");
    HANDLE fh = CreateFileW(L"winemu_dir_test\\data.bin", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(fh != INVALID_HANDLE_VALUE, "CreateFileW");
    char wbuf[100]; for (int i = 0; i < 100; i++) wbuf[i] = (char)i; DWORD n;
    CHECK(WriteFile(fh, wbuf, 100, &n, NULL) && n == 100, "WriteFile");
    LARGE_INTEGER pos = {.QuadPart = 10}, sz; SetFilePointerEx(fh, pos, NULL, FILE_BEGIN);
    char rbuf[10]; CHECK(ReadFile(fh, rbuf, 10, &n, NULL) && n == 10 && rbuf[0] == 10 && rbuf[9] == 19, "SetFilePointerEx + ReadFile");
    CHECK(GetFileSizeEx(fh, &sz) && sz.QuadPart == 100, "GetFileSizeEx");
    BY_HANDLE_FILE_INFORMATION bhi; CHECK(GetFileInformationByHandle(fh, &bhi) && bhi.nFileSizeLow == 100, "GetFileInformationByHandle");
    CloseHandle(fh);
    CHECK(CreateFileW(L"winemu_dir_test\\nope.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND, "missing file error");
    fh = CreateFileA("winemu_dir_test/second.txt", GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL); WriteFile(fh, "hi", 2, &n, NULL); CloseHandle(fh);
    WIN32_FIND_DATAW fd; HANDLE fnd = FindFirstFileW(L"winemu_dir_test\\*", &fd); int files = 0, dots = 0;
    if (fnd != INVALID_HANDLE_VALUE) { do { if (fd.cFileName[0] == '.') dots++; else files++; } while (FindNextFileW(fnd, &fd)); FindClose(fnd); }
    CHECK(files == 2 && dots == 2, "FindFirstFileW/FindNextFileW");
    CHECK(GetLastError() == ERROR_NO_MORE_FILES, "ERROR_NO_MORE_FILES");
    DWORD attrs = GetFileAttributesW(dir); CHECK(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY), "GetFileAttributesW dir");
    CHECK(MoveFileExW(L"winemu_dir_test\\second.txt", L"winemu_dir_test\\third.txt", 0), "MoveFileExW");
    CHECK(GetFileAttributesW(L"winemu_dir_test\\SECOND.TXT") == INVALID_FILE_ATTRIBUTES, "moved away");
    // memory mapped file
    fh = CreateFileW(L"winemu_dir_test\\data.bin", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE map = CreateFileMappingW(fh, NULL, PAGE_READWRITE, 0, 0, NULL);
    unsigned char *view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
    CHECK(view && view[42] == 42, "MapViewOfFile read");
    if (view) { view[0] = 0xAB; UnmapViewOfFile(view); }
    CloseHandle(map); SetFilePointer(fh, 0, NULL, FILE_BEGIN); ReadFile(fh, rbuf, 1, &n, NULL); CloseHandle(fh);
    CHECK((unsigned char)rbuf[0] == 0xAB, "mapped view write-back");
    CHECK(DeleteFileW(L"winemu_dir_test\\data.bin") && DeleteFileW(L"winemu_dir_test\\third.txt"), "DeleteFileW");
    CHECK(RemoveDirectoryW(dir), "RemoveDirectoryW");
    WCHAR full[MAX_PATH]; GetFullPathNameW(L"a\\..\\b\\c.txt", MAX_PATH, full, NULL);
    CHECK(wcslen(full) > 8 && wcscmp(full + wcslen(full) - 6, L"\\c.txt") == 0, "GetFullPathNameW");
    WCHAR tmp[MAX_PATH]; CHECK(GetTempPathW(MAX_PATH, tmp) > 0 && tmp[1] == L':', "GetTempPathW");

    // ---- memory ----
    char *va = VirtualAlloc(NULL, 1 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(va != NULL, "VirtualAlloc"); va[0] = 1; va[(1 << 20) - 1] = 2;
    DWORD oldp; CHECK(VirtualProtect(va, 4096, PAGE_READONLY, &oldp), "VirtualProtect");
    MEMORY_BASIC_INFORMATION mbi; CHECK(VirtualQuery(va + 5000, &mbi, sizeof mbi) == sizeof mbi && mbi.AllocationBase == va, "VirtualQuery");
    CHECK(VirtualFree(va, 0, MEM_RELEASE), "VirtualFree");
    HANDLE heap = HeapCreate(0, 0, 0); int *ha = HeapAlloc(heap, HEAP_ZERO_MEMORY, 4000);
    CHECK(ha && ha[999] == 0 && HeapSize(heap, 0, ha) == 4000, "HeapAlloc zero + size");
    ha = HeapReAlloc(heap, 0, ha, 8000); CHECK(ha != NULL, "HeapReAlloc"); HeapFree(heap, 0, ha); HeapDestroy(heap);

    // ---- strings, modules, environment ----
    const char *utf8 = "h\xc3\xa9llo \xe2\x82\xac \xf0\x9f\x98\x80";
    WCHAR wide[64]; int wn = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, 64);
    CHECK(wn == 11 && wide[1] == 0xE9 && wide[6] == 0x20AC && wide[8] == 0xD83D, "MultiByteToWideChar UTF-8");
    char back[64]; int bn = WideCharToMultiByte(CP_UTF8, 0, wide, -1, back, 64, NULL, NULL);
    CHECK(bn == (int)strlen(utf8) + 1 && strcmp(back, utf8) == 0, "WideCharToMultiByte round trip");
    WCHAR path[MAX_PATH]; DWORD pl = GetModuleFileNameW(NULL, path, MAX_PATH);
    CHECK(pl > 4 && _wcsicmp(path + pl - 4, L".exe") == 0, "GetModuleFileNameW");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    CHECK(k32 != NULL && GetProcAddress(k32, "GetTickCount64") != NULL, "GetProcAddress");
    CHECK(GetProcAddress(k32, "ThisFunctionDoesNotExist") == NULL && GetLastError() == ERROR_PROC_NOT_FOUND, "GetProcAddress missing");
    HMODULE adv = LoadLibraryW(L"advapi32.dll"); CHECK(adv != NULL, "LoadLibraryW system dll");
    CHECK(LoadLibraryW(L"no_such_dll_xyz.dll") == NULL && GetLastError() == ERROR_MOD_NOT_FOUND, "LoadLibrary missing");
    SetEnvironmentVariableW(L"WINEMU_TEST_VAR", L"value42"); WCHAR ev2[32];
    CHECK(GetEnvironmentVariableW(L"winemu_test_var", ev2, 32) == 7 && wcscmp(ev2, L"value42") == 0, "env case-insensitive");
    CHECK(GetEnvironmentVariableW(L"NOPE_NOT_SET", ev2, 32) == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND, "env missing");
    int argc; LPWSTR *argv = CommandLineToArgvW(L"prog.exe \"two words\" a\\\\\"b c", &argc);
    CHECK(argc == 3 && wcscmp(argv[1], L"two words") == 0 && wcscmp(argv[2], L"a\\b c") == 0, "CommandLineToArgvW");
    SYSTEM_INFO si; GetSystemInfo(&si); CHECK(si.dwPageSize == 4096 && si.dwNumberOfProcessors >= 1, "GetSystemInfo");
    OSVERSIONINFOW ov = {sizeof ov}; GetVersionExW(&ov); CHECK(ov.dwMajorVersion == 10, "GetVersionExW");
    SYSTEMTIME st; GetLocalTime(&st); CHECK(st.wYear >= 2024, "GetLocalTime");
    FILETIME ft; GetSystemTimeAsFileTime(&ft); SYSTEMTIME st2; FileTimeToSystemTime(&ft, &st2); CHECK(st2.wYear >= 2024, "FileTime conversion");
    DWORD mode; CHECK(!GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode), "GetConsoleMode fails on redirected stdout");
    printf("fails=%d\n", fails);
    return fails;
}
