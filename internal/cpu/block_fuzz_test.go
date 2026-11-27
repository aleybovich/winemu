package cpu

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"testing"

	"winemu/internal/mem"
)

// Random instruction sequences over the forms the block engine specialises
// (plus neighbours that fall back), run on the reference and on the block
// engine from identical random state (generator ideas from tools/cpudiff).

// -blockfuzz.mult scales the iteration counts; -blockfuzz.seed offsets the
// fixed seeds (longer or different runs: go test ./internal/cpu -run Fuzz
// -blockfuzz.mult=10 -blockfuzz.seed=$RANDOM).
var (
	fuzzMult = flag.Int("blockfuzz.mult", 1, "multiplier for the block fuzz iteration counts")
	fuzzSeed = flag.Int64("blockfuzz.seed", 0, "offset added to the block fuzz seeds")
)

var fuzzOps1 = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x50, 0x53, 0x55, 0x57, 0x58, 0x5B, 0x5D, 0x5F, 0x63, 0x68, 0x69, 0x6A, 0x6B,
	0x70, 0x72, 0x74, 0x75, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0x7A, 0x78,
	0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8D, 0x90, 0x91, 0x93, 0x97, 0x98, 0x99,
	0xA8, 0xA9, 0xB0, 0xB4, 0xB7, 0xB8, 0xBC, 0xBF, 0xC0, 0xC1, 0xC6, 0xC7, 0xC9, 0xD0, 0xD1, 0xD2, 0xD3,
	0xEB, 0xF6, 0xF7, 0xFE, 0xFF, 0x9C, 0x9D, 0x9E, 0x9F, 0xF5, 0xF8, 0xF9, 0xFC, 0xA4, 0xAA, 0xAB, 0xC3, 0xE8,
}

var fuzzOps0F = []byte{
	0x40, 0x42, 0x44, 0x45, 0x47, 0x4C, 0x4F, 0x4A, 0x80, 0x84, 0x85, 0x8C, 0x8F, 0x90, 0x92, 0x94, 0x95, 0x9C, 0x9F, 0x9A,
	0xAF, 0xB6, 0xB7, 0xBE, 0xBF, 0x1F, 0x18, 0xA3, 0xBA, 0xBC, 0xC8, 0xB1,
}

func fuzzVal(r *rand.Rand) uint64 {
	switch r.Intn(8) {
	case 0:
		return 0
	case 1:
		return uint64(r.Intn(5))
	case 2:
		return ^uint64(0) - uint64(r.Intn(3))
	case 3:
		return 1 << uint(r.Intn(64))
	case 4:
		return uint64(r.Int63n(0x100)) << (8 * uint(r.Intn(8)))
	case 5, 6:
		return tData + uint64(r.Intn(0x2000)) // a pointer into the data region
	}
	return r.Uint64()
}

// fuzzInstr emits one random instruction.
func fuzzInstr(r *rand.Rand) []byte {
	var b []byte
	for range r.Intn(3) {
		b = append(b, []byte{0x66, 0x66, 0xF3, 0xF2, 0x64, 0x65, 0x2E, 0x67, 0xF0}[r.Intn(9)])
	}
	if r.Intn(3) > 0 {
		b = append(b, 0x40|byte(r.Intn(16)))
	}
	if r.Intn(5) == 0 {
		b = append(b, 0x0F, fuzzOps0F[r.Intn(len(fuzzOps0F))])
	} else {
		b = append(b, fuzzOps1[r.Intn(len(fuzzOps1))])
	}
	// ModRM: favour register forms and small displacements off pointer registers
	modrm := byte(r.Intn(256))
	if r.Intn(2) == 0 {
		modrm |= 0xC0
	}
	b = append(b, modrm)
	if modrm>>6 != 3 && modrm&7 == 4 {
		b = append(b, byte(r.Intn(256))&^0xC0|byte(r.Intn(2))<<6)
	}
	if modrm>>6 == 0 && modrm&7 == 5 { // RIP-relative: stay near the code
		b = append(b, byte(r.Intn(64)), 0, 0, 0)
	}
	// trailing bytes for displacement/immediates
	for range r.Intn(9) {
		b = append(b, byte(r.Intn(256)))
	}
	return b
}

// timeDependent reports byte sequences that may decode as RDTSC, RDTSCP or
// RDRAND/RDSEED (0F C7 /6, /7): the reference returns host-time-derived
// values, so two runs differ. Over-approximate: such cases are skipped.
func timeDependent(code []byte) bool {
	return bytes.Contains(code, []byte{0x0F, 0x31}) || bytes.Contains(code, []byte{0x0F, 0x01, 0xF9}) ||
		bytes.Contains(code, []byte{0x0F, 0xC7})
}

func fuzzCode(r *rand.Rand) []byte {
	var code []byte
	for range 1 + r.Intn(12) {
		code = append(code, fuzzInstr(r)...)
	}
	return append(code, stop()...)
}

func fuzzSetup(seed int64) func(c *CPU) {
	return func(c *CPU) {
		r := rand.New(rand.NewSource(seed))
		for i := range c.R {
			c.R[i] = fuzzVal(r)
		}
		c.R[RSP] = tData + 0x8000 - uint64(r.Intn(0x100))&^7
		c.Flags = 0x202 | uint64(r.Intn(1<<12))&arithFlags
		c.GSBase = tData + 0x100
		c.FSBase = tData + 0x200
		for i := range c.X {
			for j := range c.X[i] {
				c.X[i][j] = byte(r.Intn(256))
			}
		}
		for a := uint64(tData); a < tData+0x3000; a += 8 {
			c.Mem.W64(a, fuzzVal(r))
		}
	}
}

func TestBlockFuzz(t *testing.T) {
	n := 20000
	if testing.Short() {
		n = 3000
	}
	n *= *fuzzMult
	r := rand.New(rand.NewSource(1 + *fuzzSeed))
	fails := 0
	for i := range n {
		code := fuzzCode(r)
		seed := r.Int63()
		budget := 1 + r.Intn(64)
		if timeDependent(code) {
			continue
		}
		before := t.Failed()
		both(t, fmt.Sprintf("case %d code % x", i, code), code, fuzzSetup(seed), budget)
		if !before && t.Failed() {
			fails++
		}
		if t.Failed() && fails > 5 {
			t.Fatal("too many failures")
		}
	}
}

// TestBlockFuzzPageBoundary places random code across a page and a chunk
// boundary.
func TestBlockFuzzPageBoundary(t *testing.T) {
	r := rand.New(rand.NewSource(2 + *fuzzSeed))
	for i := range 3000 * *fuzzMult {
		code := fuzzCode(r)
		at := uint64(mem.ChunkSize - 1 - r.Intn(24))
		if i%2 == 0 {
			at = mem.PageSize - 1 - uint64(r.Intn(24))
		}
		seed := r.Int63()
		budget := 1 + r.Intn(64)
		if timeDependent(code) {
			continue
		}
		setup := func(c *CPU) {
			if _, err := c.Mem.Map(tCode+mem.ChunkSize, mem.ChunkSize, mem.PageExecuteReadWrite, mem.MemPrivate, "code2"); err != nil {
				t.Fatal(err)
			}
			c.Mem.Write(tCode+at, code)
			c.RIP = tCode + at
			fuzzSetup(seed)(c)
		}
		both(t, fmt.Sprintf("boundary case %d at %#x code % x", i, at, code), nil, setup, budget)
		if t.Failed() {
			return
		}
	}
}
