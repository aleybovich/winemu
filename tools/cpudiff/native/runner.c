// Native side of the CPU differential tester (x86-64 Linux only).
// Reads records from stdin: u32 codelen, code bytes, 17 x u64 state
// (16 GPRs + RFLAGS) + 16 x 16-byte XMM; executes the code natively (it must
// end in RET and must not touch RSP) and writes back the resulting state.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

uint64_t g_state[17 + 32];
void *g_code;
uint8_t g_mem[4096] __attribute__((aligned(64)));

void run(void);
__asm__(
    ".globl run\n"
    "run:\n"
    "push %rbx\n push %rbp\n push %r12\n push %r13\n push %r14\n push %r15\n"
    "lea g_state(%rip), %rdi\n"
    "movdqu 136(%rdi), %xmm0\n movdqu 152(%rdi), %xmm1\n movdqu 168(%rdi), %xmm2\n movdqu 184(%rdi), %xmm3\n"
    "movdqu 200(%rdi), %xmm4\n movdqu 216(%rdi), %xmm5\n movdqu 232(%rdi), %xmm6\n movdqu 248(%rdi), %xmm7\n"
    "mov 128(%rdi), %rax\n push %rax\n popfq\n"
    "mov 0(%rdi), %rax\n mov 8(%rdi), %rcx\n mov 16(%rdi), %rdx\n mov 24(%rdi), %rbx\n"
    "mov 40(%rdi), %rbp\n mov 48(%rdi), %rsi\n mov 64(%rdi), %r8\n mov 72(%rdi), %r9\n"
    "mov 80(%rdi), %r10\n mov 88(%rdi), %r11\n mov 96(%rdi), %r12\n mov 104(%rdi), %r13\n"
    "mov 112(%rdi), %r14\n mov 120(%rdi), %r15\n mov 56(%rdi), %rdi\n"
    "call *g_code(%rip)\n"
    "push %rdi\n lea g_state(%rip), %rdi\n"
    "mov %rax, 0(%rdi)\n mov %rcx, 8(%rdi)\n mov %rdx, 16(%rdi)\n mov %rbx, 24(%rdi)\n"
    "mov %rbp, 40(%rdi)\n mov %rsi, 48(%rdi)\n mov %r8, 64(%rdi)\n mov %r9, 72(%rdi)\n"
    "mov %r10, 80(%rdi)\n mov %r11, 88(%rdi)\n mov %r12, 96(%rdi)\n mov %r13, 104(%rdi)\n"
    "mov %r14, 112(%rdi)\n mov %r15, 120(%rdi)\n"
    "pop %rax\n mov %rax, 56(%rdi)\n"
    "pushfq\n pop %rax\n mov %rax, 128(%rdi)\n"
    "movdqu %xmm0, 136(%rdi)\n movdqu %xmm1, 152(%rdi)\n movdqu %xmm2, 168(%rdi)\n movdqu %xmm3, 184(%rdi)\n"
    "movdqu %xmm4, 200(%rdi)\n movdqu %xmm5, 216(%rdi)\n movdqu %xmm6, 232(%rdi)\n movdqu %xmm7, 248(%rdi)\n"
    "pop %r15\n pop %r14\n pop %r13\n pop %r12\n pop %rbp\n pop %rbx\n ret\n");

int main(void) {
  uint8_t *code = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  g_code = code;
  // first line of output: address of scratch memory buffer
  fwrite(&(uint64_t){(uint64_t)g_mem}, 8, 1, stdout);
  fflush(stdout);
  for (;;) {
    uint32_t n;
    if (fread(&n, 4, 1, stdin) != 1) break;
    if (fread(code, 1, n, stdin) != n) break;
    if (fread(g_state, 8, 17 + 32, stdin) != 17 + 32) break;
    if (fread(g_mem, 1, 256, stdin) != 256) break;
    run();
    fwrite(g_state, 8, 17 + 32, stdout);
    fwrite(g_mem, 1, 256, stdout);
    fflush(stdout);
  }
  return 0;
}
