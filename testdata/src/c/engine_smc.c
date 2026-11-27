// Guest test for the block engine: self-modifying code through every write
// path, and precise register state at a fault (docs/engine.md).
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef int (*fn_t)(void);

static unsigned char *code;

static void emit_ret_imm(unsigned char *p, int v) { // mov eax, imm32 ; ret
	p[0] = 0xB8;
	memcpy(p + 1, &v, 4);
	p[5] = 0xC3;
}

static volatile ULONG64 seen_rip, seen_rax, fault_at;

static LONG CALLBACK handler(EXCEPTION_POINTERS *ep) {
	if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;
	seen_rip = ep->ContextRecord->Rip;
	seen_rax = ep->ContextRecord->Rax;
	ep->ContextRecord->Rip += 3; // skip "mov rdx, [rcx]"
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void) {
	code = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!code)
		return 1;

	// 1. guest stores (memcpy) into code that already ran
	emit_ret_imm(code, 11);
	int a = ((fn_t)code)();
	emit_ret_imm(code, 12);
	int b = ((fn_t)code)();
	printf("store: %d %d\n", a, b);

	// 2. a store into the next instruction of the same block:
	//    mov byte [rip+1], 7 ; mov eax, 1 ; ret
	unsigned char same[] = {0xC6, 0x05, 0x01, 0, 0, 0, 7, 0xB8, 1, 0, 0, 0, 0xC3};
	memcpy(code + 0x100, same, sizeof same);
	printf("same block: %d\n", ((fn_t)(code + 0x100))());
	printf("same block again: %d\n", ((fn_t)(code + 0x100))());

	// 3. Go-side write: WriteProcessMemory on the current process
	unsigned char patch[6];
	emit_ret_imm(patch, 13);
	SIZE_T n = 0;
	WriteProcessMemory(GetCurrentProcess(), code, patch, sizeof patch, &n);
	FlushInstructionCache(GetCurrentProcess(), code, sizeof patch);
	printf("wpm: %d\n", ((fn_t)code)());

	// 4. free, then new code at the same address
	if (!VirtualFree(code, 0, MEM_RELEASE))
		return 2;
	unsigned char *again = VirtualAlloc(code, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (again != code)
		return 3;
	emit_ret_imm(code, 14);
	printf("realloc: %d\n", ((fn_t)code)());

	// 5. precise state at a fault in the middle of straight-line code
	AddVectoredExceptionHandler(1, handler);
	ULONG64 out;
	__asm__ volatile(
		"lea 1f(%%rip), %%r8\n\t"
		"mov %%r8, %1\n\t"
		"mov $0x1234, %%rax\n\t"
		"xor %%ecx, %%ecx\n\t"
		"1: mov (%%rcx), %%rdx\n\t"
		"add $1, %%rax\n\t"
		"mov %%rax, %0\n\t"
		: "=m"(out), "=m"(fault_at)
		:
		: "rax", "rcx", "rdx", "r8", "memory");
	printf("fault: rip ok %d rax %#llx after %#llx\n", seen_rip == fault_at, seen_rax, out);
	return 0;
}
