# winemu build targets
GO      ?= go
LDFLAGS := -s -w
ZIGCC   ?= python3 -m ziglang cc -target x86_64-windows-gnu
ZIGCXX  ?= python3 -m ziglang c++ -target x86_64-windows-gnu
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

.PHONY: all build test mac clean testbins gotestbins ctestbins cpudiff

all: build

build:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o winemu ./cmd/winemu

test:
	$(GO) vet ./...
	$(GO) test ./tests/ -count=1

mac:
	mkdir -p dist
	GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/winemu-arm64 ./cmd/winemu
	GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/winemu-amd64 ./cmd/winemu
	$(GO) run ./tools/mkfat -o dist/winemu dist/winemu-arm64 dist/winemu-amd64

# Rebuild the Windows test programs (needs Zig: pip install ziglang)
testbins: gotestbins ctestbins
	mkdir -p testdata/bin
	cd testdata/src && $(ZIGCC) -O2 hello.c -o ../bin/hello.exe
	cd testdata/src && $(ZIGCC) -O2 t_crt.c -o ../bin/t_crt.exe
	cd testdata/src && $(ZIGCXX) -O2 t_cpp.cpp -o ../bin/t_cpp.exe
	cd testdata/src && $(ZIGCC) -O1 t_win.c -o ../bin/t_win.exe -lshell32
	cd testdata/src && $(ZIGCC) -O2 t_input.c -o ../bin/t_input.exe
	cd testdata/src && $(ZIGCC) -O2 t_bench.c -o ../bin/t_bench.exe
	cd testdata/src && $(ZIGCC) -O2 -shared mylib.c -o ../bin/mylib.dll -Wl,--out-implib,/tmp/libmylib.a
	cd testdata/src && $(ZIGCC) -O2 usedll.c -o ../bin/usedll.exe -L/tmp -lmylib
	cd testdata/src && $(ZIGCC) -O2 t_console.c -o ../bin/t_console.exe
	cd testdata/src && $(ZIGCC) -O2 child.c -o ../bin/child.exe
	cd testdata/src && $(ZIGCC) -O2 parent.c -o ../bin/parent.exe
	cd testdata/src/gohello && GOOS=windows GOARCH=amd64 $(GO) build -o ../../bin/gohello.exe .
	rm -f testdata/bin/*.pdb

# Guest test programs, picked up by convention (no Makefile edit needed):
#   testdata/src/go/<name>/*.go     -> testdata/bin/<name>.exe  (package main, part of this module)
#   testdata/src/c/<name>.c / .cpp  -> testdata/bin/<name>.exe  (Zig, MinGW target)
# Extra C/C++ link flags go in a source line of the form:  // LDFLAGS: -lws2_32
C_TESTBINS := $(patsubst testdata/src/c/%.c,testdata/bin/%.exe,$(wildcard testdata/src/c/*.c)) \
              $(patsubst testdata/src/c/%.cpp,testdata/bin/%.exe,$(wildcard testdata/src/c/*.cpp))

gotestbins:
	mkdir -p testdata/bin
	@for d in $(patsubst %/,%,$(wildcard testdata/src/go/*/)); do \
		echo "go build $$d"; \
		GOOS=windows GOARCH=amd64 $(GO) build -o testdata/bin/$$(basename $$d).exe ./$$d || exit 1; \
	done

ctestbins: $(C_TESTBINS)

testdata/bin/%.exe: testdata/src/c/%.c
	@mkdir -p testdata/bin
	$(ZIGCC) -O2 $< -o $@ $$(sed -n 's,^// LDFLAGS:,,p' $<)
	@rm -f $(@:.exe=.pdb)

testdata/bin/%.exe: testdata/src/c/%.cpp
	@mkdir -p testdata/bin
	$(ZIGCXX) -O2 $< -o $@ $$(sed -n 's,^// LDFLAGS:,,p' $<)
	@rm -f $(@:.exe=.pdb)

# Differential CPU test against the host CPU (x86-64 Linux only)
cpudiff:
	gcc -O1 -o /tmp/winemu-cpudiff-runner tools/cpudiff/native/runner.c
	$(GO) run ./tools/cpudiff /tmp/winemu-cpudiff-runner

clean:
	rm -rf winemu dist

install: build
	@if [ -d "$(BINDIR)" ] && [ -w "$(BINDIR)" ] || { [ ! -e "$(BINDIR)" ] && mkdir -p "$(BINDIR)" 2>/dev/null; }; then \
		install -m 755 winemu "$(BINDIR)/winemu"; \
	else \
		echo "$(BINDIR) needs admin rights, using sudo"; \
		sudo mkdir -p "$(BINDIR)" && sudo install -m 755 winemu "$(BINDIR)/winemu"; \
	fi
	@echo "installed $(BINDIR)/winemu"

uninstall:
	@if [ -w "$(BINDIR)" ]; then rm -f "$(BINDIR)/winemu"; else sudo rm -f "$(BINDIR)/winemu"; fi