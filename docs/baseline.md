# WS0 baseline (before Wave 1)

Environment: macOS arm64 (Darwin 25.6), Go 1.26.6 (module declares go 1.24.7),
Zig 0.17.1 via `python3 -m ziglang`.

`make testbins`: originally failed only because `testdata/bin/` did not exist
(`error: unable to open output directory "../bin": FileNotFound`). With the
directory created, every program compiled with Zig 0.17.1 unchanged (two harmless
clang warnings in `t_cpp.cpp`). The Makefile now runs `mkdir -p testdata/bin`.

`make test` (`go vet ./...` + `go test ./tests/ -count=1`): **all pass**.

| e2e case | exe | result | time |
|----------|-----|--------|------|
| hello   | hello.exe   | PASS | 0.34s |
| crt     | t_crt.exe   | PASS | 0.58s |
| cpp     | t_cpp.exe   | PASS | 0.07s |
| win32   | t_win.exe   | PASS | 0.14s |
| dll     | usedll.exe  | PASS | 0.04s |
| input   | t_input.exe | PASS | 0.04s |
| process | parent.exe  | PASS | 0.16s |
| go      | gohello.exe | PASS | 0.24s |
| bench   | t_bench.exe | PASS | 1.09s |

`go test ./... -count=1`: only `winemu/tests` had tests before WS0 (pass). After WS0
there are also `internal/win` harness self-tests (`TestHarness*`) and
`tests/TestExampleGoGuest`, all passing. `go test -race ./internal/win/` is clean.
No emulator failures were found by the baseline.
