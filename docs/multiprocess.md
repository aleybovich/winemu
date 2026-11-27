# Multi-process model (WS-D)

All Windows guest processes of one session run inside **one host winemu
process**. Each guest process is one `*win.Emu` (own address space, handle
table, threads, CRT, console state) running on **its own goroutine**; the
processes share a `*win.Kernel` (`internal/win/kernel.go`).

## Kernel object model

```
Kernel (one per session, thread-safe)
  mu            kernel lock: object state of every waitable, namespace, process table
  procs         pid -> *Process (live processes)
  names         "event:<name>" / "mutex:<name>" / "sem:<name>" -> object
  nextID        shared PID/TID allocator (multiples of 4, like Windows)
  gen, wake     change generation + broadcast channel for cross-goroutine wake-ups
Process (kernel side of one Emu)
  pid, parent, exe, exit code, exited, kill request, *Emu (hook for WS-E1)
Emu (= the process, owned by its goroutine)
  Mem, handles (per-process table: value -> shared object), threads, scheduler,
  CRT, console, cvWaiters, addrWaiters, views, deadlock bookkeeping
```

Kernel objects are ordinary Go values (`*eventObj`, `*mutexObj`, `*semObj`,
`*timerObj`, `*processObj`, `*threadObj`, `*fileObj` + `*pipeBuf`, ...). A handle
table entry holds a pointer to the object, so two processes holding handles to
the same object (inheritance, named open, later `DuplicateHandle`) see the same
state. The `waitable` interface (`signaled(t)`, `acquire(t)`) is unchanged; it
is always called **with the kernel lock held**, and implementations must not
take it themselves. Anything that changes the state a waiter could be waiting
for calls `k.notify()` afterwards (after releasing the lock).

Named objects are refcounted by handle: the name disappears when the last
handle is closed. Process exit closes every handle of the process.

**Per-process state** stays on the `Emu`: memory, handle table, threads, TLS/FLS,
CRT, console, critical sections / SRW / condition variables / `WaitOnAddress`
(these live in process memory and are process-local on Windows too), file views.
**Cross-process state** is on the kernel. There are no mutable package globals
left in `internal/win` other than the API registry (written only by `init`).

## Scheduling and wake-ups

Threads of one process are still scheduled cooperatively on that process's
goroutine (deterministic within a process, unchanged code). Processes run in
parallel. When every thread of a process is waiting, the scheduler sleeps
until the earliest deadline, a kernel notification, or a short poll interval
(1 ms growing to 10 ms; the poll catches conditions on shared memory, which do
not notify). Lost wake-ups are avoided with the generation counter: the
scheduler reads `gen` before scanning its threads, registers as a sleeper, and
skips the sleep if `gen` moved; `notify` bumps `gen` and closes the broadcast
channel only when somebody sleeps (cheap when nobody does).

## Deadlock detection

A process is *blocked forever* when all its live threads wait without a deadline
(waits on waitable timers count as having the timer's due time as deadline;
host I/O such as OS pipes and consoles uses short retry deadlines and is never
"forever"). Waits on host-completed work (sockets, name lookups) use
`e.blockHost(ready, timeout)`: the thread is marked `waitHost`, `idle` keeps
polling it with the 1->10 ms backoff and never counts the process as blocked
forever; host goroutines that complete work (DNS lookups) call `k.notify()`.
A process with an active `WSAEventSelect` is likewise never blocked forever,
so `pollNet` keeps running while it idles; it sets the event under the kernel
lock and notifies. The kernel counts blocked-forever processes. A deadlock is declared
only when **every** live process of the session is blocked forever and no
kernel notification happened for ~2 s; then only the **youngest** live process
exits with `STATUS_POSSIBLE_DEADLOCK` (0xC0000194). Its exit signals its process
object, so a parent waiting for it wakes up and the detector re-evaluates. A
parent in `WaitForSingleObject(child, INFINITE)` is therefore never reported
while the child runs.

## Shared memory and atomics

`mem.Section` is shareable backing store (lazily materialised 64 KiB chunks,
`atomic.Pointer` per chunk). `Memory.MapSection` maps a section range into an
address space; several `Memory` instances (processes) can map the same section,
at the same or different addresses. Shared chunks are **not** entered into the
private chunk table, so every access to them falls to the slow path, where
`mem` uses host atomics (`sync/atomic`, sequentially consistent on amd64 and
arm64): aligned scalars use 32/64-bit atomic loads/stores, sub-word stores use a
CAS loop on the containing word, bulk copies go word by word. The private fast
path is untouched (same instructions as before), so processes without shared
memory pay nothing.

`LOCK`-prefixed instructions: `CPU.Run` picks, per slice, the normal step
loop (no shared mapping: unchanged hot path) or `stepShared`, in which a
`LOCK`-prefixed instruction or `XCHG` with memory runs in *locked mode*: the CPU
snapshots registers and flags, `mem` records the first shared read
(address, size, value) and turns the matching write into a CAS. If the CAS fails
the instruction is rolled back (registers, flags, RIP) and re-executed - a
classic LL/SC-style retry that gives exact x86 RMW atomicity for every lockable
instruction (ALU ops, INC/DEC/NOT/NEG, BTS/BTR/BTC, XADD, CMPXCHG, CMPXCHG8B)
without per-instruction code. `XCHG reg, mem` is implicitly locked the same way.
Fences are no-ops: all shared accesses are already SC atomics. Limits: an
access that straddles an 8-byte boundary, and `CMPXCHG16B`, cannot be one host
atomic; they serialise on a host-wide bus lock (`mem.busLock`), which is atomic
against other locked operations but not against a concurrent plain store to
the same bytes. Code fetched from a shared chunk is read without atomics. Because the loop
is chosen per slice, code that maps the first section (WS-E1) should end the
current slice (`e.yield()`) so locked instructions after it are atomic.

## Process creation, handles, stdio

`CreateProcess` of a PE image creates a child `Emu` on the same kernel, copies
the handles to inherit **with identical values** into the child table before
anything else is allocated (handle allocation skips occupied values), points
the child's std handle slots at the objects given in `STARTUPINFO`
(`STARTF_USESTDHANDLES`) or at the parent's std objects, loads the image on the
parent's goroutine (so "file not found"/"bad format" fail synchronously) and
starts the child goroutine. Without `bInheritHandles` nothing but stdio is
shared. Anonymous pipes (`CreatePipe`, `_popen`) are kernel pipes
(`pipeBuf` with its own lock + kernel notify). `ReadFile`, `NtReadFile` and
CRT `_read` on an empty pipe block only the calling thread (`blockOnEmptyPipe`:
the call is re-executed when data or EOF arrives); CRT stream reads
(`fgets`/`fread`/`getc`/`scanf`) still block the whole process (`hostWait`),
because those calls cannot be re-executed safely. `system`/`_popen` run
`%COMSPEC% /c <command>` through the builtin `cmd.exe` (`cmd.go`), in-process
too; `system`/`_pclose` block only the calling thread (the child is kept in
`Thread.xop` across the re-execution).

Exit: `ExitProcess`/return from `main`/`TerminateProcess` (asynchronous request
checked by the target's scheduler between slices and in host waits) flush the
CRT, close all handles (so pipe readers see EOF), mark threads exited, record
the exit code and signal the process object. `GetExitCodeProcess`,
`WaitForSingleObject(process)`, `GetProcessId`, `OpenProcess(pid)` work across
processes. The root process has the host pid as its pid; others get kernel ids.
The host winemu exits when the **root** process exits, with its exit code;
every other guest process still running is terminated then (asked to exit,
given up to 2 s to close its handles).

Nothing launches a guest `.exe` as a separate host process any more; non-PE
targets keep failing with `ERROR_BAD_EXE_FORMAT` as before.

## Hooks for WS-E1

`e.processOf(h)` resolves a process handle to its `*Process`; `Process.Emu()`
gives the target's `Emu`/`Mem`. A process can be prepared without being
started (`newChildProcess`, then `(*Emu).startProcess`), which is the support
point for `CREATE_SUSPENDED` (today the flag is ignored and the child starts). Touching another process's **private** memory or thread
state from a different goroutine is only safe while the target is not running
(not yet started, or suspended at a scheduler boundary) - E1 must add that
synchronisation; shared sections are safe at any time. `Handles` is locked,
so inserting into another process's table (DuplicateHandle) is safe. New
cross-process object kinds (e.g. tokens, sockets) just go into handle tables
as pointers; embed `kname` for named/refcounted objects, keep their state
under `Kernel.mu` and call `notify` when a waiter could become ready.
