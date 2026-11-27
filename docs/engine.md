# Execution engine (Perf-P2): predecoded basic blocks

`cpu.CPU.Run(n)` executes guest code with one of three engines, chosen by
`WINEMU_ENGINE` (read once at start-up, `cpu.DefaultEngine`):

| value | engine |
|---|---|
| unset / `block` | predecoded block engine (default) |
| `interp` | the original interpreter (`step` / `stepShared`), kept as the reference |
| `check` | block engine with every block re-executed by the reference and compared |

The interpreter is unchanged and remains the reference implementation and the
fallback for every instruction the block engine does not specialise.

## Blocks and IR

A *block* is decoded once, starting at a guest RIP, and ends after a control
transfer (jcc, jmp, call, ret, indirect jmp/call, hypercall `0F 04`), after an
instruction the engine does not specialise (*fallback op*), before an
instruction that starts on another 4 KiB page, or after 64 instructions.
Each instruction becomes one `op` (`internal/cpu/block.go`):

```
op { fn handler; ip, next uint64; disp, imm uint64; base, idx, scale, seg;
     r, rm (register numbers, byte registers pre-resolved to index+high flag);
     sz (operand size), sub (ALU op / condition code / shift op), name }
```

Handlers are specialised by form and operand size (`mov r64,[ea]`,
`alu32 r,r`, `jcc rel`, ...). The effective-address recipe is precomputed:
`ea = disp + R[base] + R[idx]<<scale + segbase(seg)`; RIP-relative operands are
folded into an absolute `disp` at decode time (using exactly the immediate
length the reference passes to `decodeModRM`); FS/GS bases are read at
execution time because blocks are shared by all threads of a process.
Anything else (x87, SSE, string ops, `0x67`, LOCK/XCHG-mem in shared mode,
rare opcodes, odd prefix orders) is a fallback op: `RIP = ip; step()` (or
`stepShared()` when the slice runs in shared mode), which ends the block.

Blocks are cached per address space (`mem.Memory.Code`, so all threads of a
process share them; each process has its own) in a map plus a direct-mapped
lookup table. Code in shared-section chunks is never cached: it runs through
the fallback, one instruction at a time.

## Exactness rules

- Every handler performs the reference's side effects in the reference's order
  (same flag helpers: `add`, `sub`, `logic`, `shift`, `cond`, ...), so faults
  leave the same register/flag/memory state. `IP0` is set before each op, so a
  fault reports the instruction's address and `runSlice` resets `RIP` to it as
  before. RIP is stored only when the block is left (branches write their
  target; other exits write `next`).
- `Run(n)` executes exactly `n` instructions unless `Stop` is set: the block
  loop is cut at the remaining budget. `ICount` is updated exactly as before
  (at the end of the slice, or `+done` when `Stop` ends it; nothing on a panic).
  `Stop` can only be set inside API code, i.e. by a hypercall, which is always
  the last op of a block; it is checked after hypercall and fallback ops.
- Shared mode is chosen per slice as before (`Mem.HasShared()`); LOCK-prefixed
  instructions and `XCHG r,m` are fallback ops, so in shared mode they go
  through `stepShared`/`execLocked` (host atomics unchanged).
- Nested `Run` (API callbacks into the guest from a hypercall) keeps all
  per-run state in locals.

## Self-modifying code and invalidation

`mem` keeps a second chunk table for **stores** (`w1`), identical to the read
table except that chunks containing decoded code are absent. The store fast
path (`W8`..`W64`) is therefore unchanged in cost; a store into a code chunk
falls to the slow path, which checks a per-chunk 16-bit mask of watched 4 KiB
pages. Every write path (`writeSlow`, `Write`, `Fill`, `Zero`, unmap/decommit
via `dropChunks`) calls `noteWrite(a, n)`; when it hits a watched page, the
page is unwatched, `Memory.OnCodeWrite(page)` drops every block on that page
and `Memory.CodeWritten` is set. This covers guest stores, Go-side API writes
(`WriteProcessMemory` into another process writes through the target's
`Memory`), `VirtualFree`, unmap, decommit and heap free. Shared-section chunks
are not cached, so stores from another process into them need no tracking.
`FlushInstructionCache` needs no extra work.

Rule inside a block: after every op that stores to memory the handler checks
`CodeWritten`; if set, the block is left after that instruction and the next
instruction is fetched from a freshly decoded block. This is stricter than x86
(which only guarantees SMC after a serialising jump for cross-modification)
and identical to the reference interpreter, which re-fetches every instruction.

## Differential checker (`WINEMU_ENGINE=check`)

Before a block runs, the checker snapshots the architectural state (GPRs, RIP,
RFLAGS, XMM, MXCSR, x87, FS/GS base) and turns on the `mem` write journal
(old bytes of every store; in check mode all stores take the slow path). It
runs the block engine, restores state and memory, runs the reference for the
same number of instructions, and compares registers, flags, the set of
written bytes and their values, and the fault (type, code, address). On a
divergence it replays instruction by instruction to find the first diverging
instruction and panics with its address, bytes, decoded op and the
differences. Hypercall and fallback ops are executed once (they are the
reference). Instructions that touched shared memory are not compared (another
process may change it in between). Fuzz tests (`internal/cpu/block_fuzz_test.go`)
generate random instruction sequences over the specialised forms and compare
both engines on random state (`-blockfuzz.mult=N` scales the iteration counts,
`-blockfuzz.seed=S` offsets the seeds; cases that may contain RDTSC/RDTSCP/
RDRAND/RDSEED are skipped because the reference returns host-time values).

## JIT readiness (Perf-P3)

An `op` is a fully decoded, size-specialised instruction with explicit operand
descriptors, so a JIT translates a block op by op: register operands map to
loads/stores of `CPU.R[i]` (or host registers allocated per block), the EA
recipe to an add/shift sequence, memory accesses to an inline chunk-table
lookup with a slow-path exit, flags to host NZCV/flag words, branch ops to
block exits carrying the target RIP. Fallback and hypercall ops are exits to
Go. Each op carries `ip`, giving the PC map needed for precise faults. The
store-path invalidation (`OnCodeWrite`) is shared: a JIT registers its code
per page the same way.
