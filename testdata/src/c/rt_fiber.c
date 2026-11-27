// Fibers: ping-pong between two fibers and the main fiber, fiber data,
// GetCurrentFiber/GetFiberData (inline TEB reads), FPU state and deep
// stacks inside a fiber, DeleteFiber, ConvertFiberToThread.
#include <windows.h>
#include <stdio.h>

static LPVOID mainFiber, fibers[2];
static int trace[16], n;
static volatile double acc[2];

static int deep(int d) {
	volatile char buf[4096];
	buf[0] = (char)d;
	return d == 0 ? buf[0] : deep(d - 1) + 1;
}

static void CALLBACK routine(LPVOID param) {
	int id = (int)(INT_PTR)param;
	for (int i = 0;; i++) {
		if (GetFiberData() != param || GetCurrentFiber() != fibers[id - 1]) {
			printf("fiber %d: wrong fiber data %p / current %p\n", id, GetFiberData(), GetCurrentFiber());
			ExitProcess(2);
		}
		acc[id - 1] += 0.5 * id;
		if (deep(64) != 64) {
			printf("fiber %d: deep recursion failed\n", id);
			ExitProcess(3);
		}
		trace[n++] = id * 10 + i;
		SwitchToFiber(id == 1 ? fibers[1] : mainFiber);
	}
}

int main(void) {
	if (IsThreadAFiber()) return 10;
	mainFiber = ConvertThreadToFiber((LPVOID)0x1234);
	if (!mainFiber || GetCurrentFiber() != mainFiber || GetFiberData() != (LPVOID)0x1234 || !IsThreadAFiber()) return 11;
	fibers[0] = CreateFiber(0, routine, (LPVOID)1);
	fibers[1] = CreateFiberEx(4096, 256 * 1024, FIBER_FLAG_FLOAT_SWITCH, routine, (LPVOID)2);
	if (!fibers[0] || !fibers[1]) return 12;
	double local = 1.25;
	for (int round = 0; round < 3; round++) {
		SwitchToFiber(fibers[0]);
		if (GetCurrentFiber() != mainFiber) return 13;
		local *= 2;
	}
	printf("trace:");
	for (int i = 0; i < n; i++) printf(" %d", trace[i]);
	printf("\nacc: %.1f %.1f local: %.2f\n", acc[0], acc[1], local);
	DeleteFiber(fibers[0]);
	DeleteFiber(fibers[1]);
	if (!ConvertFiberToThread() || IsThreadAFiber()) return 14;
	if (ConvertFiberToThread() || GetLastError() != ERROR_ALREADY_THREAD) return 15;
	printf("ok\n");
	return 0;
}
