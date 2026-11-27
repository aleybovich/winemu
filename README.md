# winemu

Run **64-bit Windows console programs on macOS** (Apple Silicon and Intel) — and Linux —
with a single self-contained Go binary. No Wine, no Rosetta, no VM, no cgo.

```
$ winemu hello.exe
Hello from Windows!
$ echo '{"a":1}' | winemu tool.exe --flag file.txt
```

winemu is a user-mode emulator: it interprets x86-64 machine code in software,
loads PE executables and DLLs itself, and implements the Windows system DLLs
(kernel32, ntdll, the C runtime, ...) in Go on top of macOS.

## Quick start

```sh
# prebuilt (macOS universal binary, from the release zip)
chmod +x winemu
xattr -d com.apple.quarantine winemu 2>/dev/null   # only if macOS blocks it
./winemu path/to/program.exe arg1 arg2

# or build from source (Go 1.22+)
make            # builds ./winemu for this machine
make test       # runs the end-to-end test suite
make mac        # builds dist/winemu (universal), dist/winemu-arm64, dist/winemu-amd64
```

Usage:

```
winemu [options] program.exe [arguments...]

  -prefix dir   virtual Windows environment (default ~/.winemu, or $WINEMU_PREFIX)
  -lenient      unimplemented APIs return 0 instead of stopping the program
  -trace        log every Windows API call to stderr
  -v            verbose diagnostics (register dump + stack trace on crashes)
  -version
```

The program's exit code becomes winemu's exit code (low 8 bits, as on any Unix).

## The virtual environment

On first run winemu creates a prefix (default `~/.winemu`):

| Windows path   | Mac path                              |
|----------------|---------------------------------------|
| `C:\`          | `~/.winemu/drive_c`                   |
| `Z:\`          | `/` (your whole Mac file system)      |
| current dir    | your shell's current directory, seen as `Z:\Users\you\...` |

So relative paths and Mac-style paths (`/Users/you/file.txt`) passed as
arguments just work. `C:\Users\<you>`, `AppData`, `Temp`, `ProgramData`,
`C:\windows\system32` exist inside the prefix. Paths are matched
case-insensitively, like on Windows.

Environment variables: the program gets a Windows-style environment
(`USERPROFILE`, `APPDATA`, `TEMP`, `PATH=C:\windows\system32;...`).
`TERM`, `LANG`, `TZ`, `COLUMNS`, `LINES`, `NO_COLOR` are passed through, and any
`WINEMU_ENV_NAME=value` on the Mac side becomes `NAME=value` inside.

### DLLs

DLLs are searched in the program's directory, then
`~/.winemu/drive_c/windows/system32`. Native DLLs are loaded and run for real
(DllMain, TLS, exports, forwarders). System DLLs are always the emulated ones.

**Programs built with Visual C++ and `/MD`** (dynamic CRT) may need
`msvcp140.dll` (C++ standard library) and, for C++ exceptions,
`vcruntime140.dll` + `vcruntime140_1.dll`. These are Microsoft code and can't be
emulated; copy them from any Windows PC (`C:\Windows\System32`) or from the
Visual C++ Redistributable into `~/.winemu/drive_c/windows/system32`.
Programs built with MinGW/GCC/Clang, Rust, Go, or MSVC `/MT` (static CRT) need
nothing extra. The UCRT (`api-ms-win-crt-*`, `ucrtbase.dll`) and `msvcrt.dll`
are built in.

## What works

Tested with C, C++ (exceptions, RTTI, STL, iostreams, `std::thread`), Go and
Win32 API programs (see `testdata/src`):

- **CPU**: x86-64 integer instructions, x87, SSE, SSE2, SSE3, SSSE3, SSE4.1,
  SSE4.2 (incl. `pcmpistri` & co.), POPCNT/LZCNT/TZCNT, CRC32, CMPXCHG16B.
  Verified against real hardware with 80,000 randomized instruction tests
  (`tools/cpudiff`).
- **Executables**: PE32+ exe and DLL loading, relocations, imports by name and
  ordinal, forwarded exports, API sets, delay-loading, static TLS + callbacks,
  `LoadLibrary`/`GetProcAddress`.
- **Exceptions**: real x64 SEH — unwind-info interpreter, `RtlDispatchException`
  semantics, vectored handlers, `RtlUnwindEx` with collided unwinds,
  `__C_specific_handler`, C++ exceptions (GCC/Clang and native vcruntime),
  setjmp/longjmp, unhandled-exception reports.
- **Threads**: `CreateThread`, `_beginthreadex`, critical sections, SRW locks,
  condition variables, events, mutexes, semaphores, waitable timers,
  `WaitOnAddress`, `InitOnce`, TLS/FLS, thread pools, IOCP — scheduled
  cooperatively on one host thread (deterministic, atomics are trivially atomic).
- **C runtime**: UCRT and msvcrt — stdio (buffered streams, text/binary modes),
  full printf/scanf families with MSVC formatting, strings, wide chars,
  UTF-8 multibyte, math, time, locale stubs, low-level I/O, `_findfirst`,
  `_stat`, conio (`_getch`, `_kbhit` with raw terminal mode).
- **Files**: CreateFile/ReadFile/WriteFile & friends, directories,
  FindFirstFile, attributes, times, memory-mapped files, temp files.
- **Console**: colors (`SetConsoleTextAttribute` → ANSI), VT sequences pass
  through, cursor positioning, clear screen, `ReadConsole`/`ReadConsoleInput`,
  window size from the terminal, legacy code page 437 output converted to UTF-8.
- **Processes**: `CreateProcess` (child `.exe` files run in a new winemu with
  redirected handles/pipes), `system()` (with `cls`, `pause`, `echo`, ...),
  `_popen`.
- ~1,500 distinct Windows/CRT functions in total.

## Limitations

- Console programs only — no GUI (windows, GDI, DirectX), no COM servers.
- 64-bit (x64) executables only — no 32-bit, ARM64 or .NET executables.
- No networking yet (winsock calls fail with `WSAENETDOWN`).
- No registry contents (keys can be "created" but nothing is stored), no services.
- Speed: it's an interpreter, roughly 30-40 million instructions per second,
  i.e. typically 20-50x slower than native for CPU-heavy work. Fine for most
  tools; heavy number crunching will be slow.
- AVX/AVX2/BMI are not emulated; CPUID doesn't advertise them, so programs pick
  their SSE code paths.
- When a program calls an API that isn't implemented, winemu stops and names
  it (e.g. `unimplemented API called: kernel32!Foo`). Try `-lenient`, and
  please report it.
- `cmd.exe`, batch files and PowerShell are not available.

## Troubleshooting

- `-trace` shows every API call with arguments, return values and call sites.
- `-v` prints registers and a stack trace on crashes.
- `WINEMU_STATS=1` prints instruction counts and speed.
- `WINEMU_DEBUG_SEH=1` logs exception dispatch.

## How it works

```
cmd/winemu         CLI
internal/cpu       x86-64 interpreter: decoder, ALU/flags, SSE*, x87
internal/mem       sparse 47-bit guest address space (64 KiB chunks, lazy)
internal/pe        PE32+ parser
internal/win       the Windows personality:
  loader.go        PE loader, builtin-DLL image synthesis, imports/exports, TLS
  process.go       process start-up, PEB/TEB, loader lists, KUSER_SHARED_DATA
  emu.go           threads, scheduler, API dispatch, guest callbacks
  seh.go           structured exception handling and unwinding
  kernel32*.go     kernel32/ntdll: memory, files, console, sync, time, ...
  crt*.go          ucrtbase/msvcrt; printf.go & scanf.go formatters
  child.go         CreateProcess / system / _popen
tools/cpudiff      differential CPU tester (needs an x86-64 Linux host)
tools/mkfat        builds macOS universal binaries without lipo
tests/             end-to-end tests over testdata/bin/*.exe
```

Emulated DLLs are real in-memory PE images whose exports point at tiny
trampolines (`0F 04 imm32; ret`) — `0F 04` is an undefined x86 opcode that the
interpreter treats as a "hypercall" into the Go implementation. Callbacks from
API implementations back into guest code (qsort comparators, DllMain, exception
handlers, thread pools) run nested scheduler loops; blocking APIs park the
thread and are re-executed when it is resumed.

Rebuilding the test programs requires Zig (`pip install ziglang`): `make testbins`.
