package cpu

// Predecoded basic-block engine (docs/engine.md).

import (
	"os"

	"winemu/internal/mem"
)

// Engine selects how Run executes guest code.
type Engine uint8

const (
	EngineBlock  Engine = iota // predecoded blocks (default)
	EngineInterp               // reference interpreter
	EngineCheck                // blocks, each verified against the reference
)

func (e Engine) String() string {
	switch e {
	case EngineInterp:
		return "interp"
	case EngineCheck:
		return "check"
	}
	return "block"
}

// DefaultEngine is the engine of new CPUs, from WINEMU_ENGINE.
var DefaultEngine = parseEngine(os.Getenv("WINEMU_ENGINE"))

func parseEngine(s string) Engine {
	switch s {
	case "interp":
		return EngineInterp
	case "check":
		return EngineCheck
	}
	return EngineBlock
}

// opFn executes one predecoded instruction. It returns true when the block
// must be left; it has then set RIP.
type opFn func(c *CPU, o *op) bool

const noReg = 0xFF

// op is one predecoded instruction.
type op struct {
	fn    opFn
	ip    uint64 // address of the instruction
	next  uint64 // address of the following instruction
	disp  uint64 // EA displacement (absolute address for RIP-relative); branch target
	imm   uint64 // immediate, already extended the way the reference extends it
	sz    uint8  // operand size
	r     uint8  // ModRM.reg / opcode register (byte registers: resolved index)
	rm    uint8  // ModRM.rm register when not memory
	rSh   uint8  // 8 when r names AH/CH/DH/BH
	rmSh  uint8  // 8 when rm names AH/CH/DH/BH
	base  uint8  // EA base register or noReg
	idx   uint8  // EA index register or noReg
	scale uint8
	seg   uint8 // 0 none, 1 FS, 2 GS
	sub   uint8 // ALU op, condition code, shift op
	mem   bool  // ModRM operand is memory
	ext   bool  // hypercall or fallback: has effects outside the CPU, never re-executed by the checker
	id    uint8 // fusion class (block_fuse.go)
	extra uint8 // further instructions this op executes (fused jcc)
	cnt   uint8 // instructions of the block up to and including this op
	pre   uint8 // no-op instructions folded in before this op (jmp, nop)
}

type block struct {
	ip   uint64
	ops  []op
	n    int       // instructions in the block
	succ [2]*block // recently taken successors (chaining); checked against RIP and dead
	dead bool      // invalidated: must not be entered through succ links
}

// next returns the block at rip, following b's successor links first.
func (bc *blockCache) next(c *CPU, b *block, rip uint64) *block {
	if b != nil {
		if s := b.succ[0]; s != nil && s.ip == rip && !s.dead {
			return s
		}
		if s := b.succ[1]; s != nil && s.ip == rip && !s.dead {
			b.succ[0], b.succ[1] = s, b.succ[0]
			return s
		}
	}
	s := bc.get(rip)
	if s == nil {
		if s = c.decodeBlock(rip); s == nil {
			return nil
		}
		bc.add(c.Mem, s)
	}
	if b != nil {
		b.succ[1], b.succ[0] = b.succ[0], s
	}
	return s
}

const fastBits = 12

type blockCache struct {
	fast  [1 << fastBits]*block
	all   map[uint64]*block
	pages map[uint64][]*block
}

func cacheOf(m *mem.Memory) *blockCache {
	if bc, ok := m.Code.(*blockCache); ok {
		return bc
	}
	bc := &blockCache{all: map[uint64]*block{}, pages: map[uint64][]*block{}}
	m.Code = bc
	m.OnCodeWrite = bc.invalidatePage
	return bc
}

func fastSlot(ip uint64) uint64 { return (ip ^ ip>>fastBits) & (1<<fastBits - 1) }

func (bc *blockCache) get(ip uint64) *block {
	h := fastSlot(ip)
	if b := bc.fast[h]; b != nil && b.ip == ip {
		return b
	}
	b := bc.all[ip]
	if b != nil {
		bc.fast[h] = b
	}
	return b
}

func (bc *blockCache) add(m *mem.Memory, b *block) {
	bc.all[b.ip] = b
	bc.fast[fastSlot(b.ip)] = b
	first := b.ip &^ (mem.PageSize - 1)
	last := (b.ops[len(b.ops)-1].next - 1) &^ (mem.PageSize - 1)
	for p := first; ; p += mem.PageSize {
		bc.pages[p] = append(bc.pages[p], b)
		m.WatchCode(p)
		if p >= last {
			break
		}
	}
}

// invalidatePage drops every block with code on page (mem.OnCodeWrite).
func (bc *blockCache) invalidatePage(page uint64) {
	for _, b := range bc.pages[page] {
		b.dead = true
		if bc.all[b.ip] == b {
			delete(bc.all, b.ip)
		}
		if h := fastSlot(b.ip); bc.fast[h] == b {
			bc.fast[h] = nil
		}
	}
	delete(bc.pages, page)
}

// refStep executes one instruction with the reference interpreter.
func (c *CPU) refStep() {
	if c.sharedSlice {
		c.stepShared()
	} else {
		c.step()
	}
}

// runBlocks is Run for the block engine.
func (c *CPU) runBlocks(n int) {
	defer c.flags() // RFLAGS is architectural again when Run returns or panics
	shared := c.Mem.HasShared()
	bc := cacheOf(c.Mem)
	check := c.Engine == EngineCheck
	if check {
		c.Mem.DisableFastWrite()
	}
	c.sharedSlice = shared
	done := 0
	var b *block
	for done < n {
		b = bc.next(c, b, c.RIP)
		switch {
		case b == nil: // code in a shared chunk, or not decodable here
			c.flags()
			c.refStep()
			done++
		case check:
			done += c.checkBlock(b, n-done)
		case b.n > n-done:
			done += c.refSteps(n - done)
		default:
			ops := b.ops
			i := 0
			for ; i < len(ops); i++ {
				o := &ops[i] // handlers that can fault set IP0 themselves
				if o.fn(c, o) {
					done += int(o.cnt)
					goto left
				}
			}
			c.RIP = ops[len(ops)-1].next
			done += b.n
		left:
		}
		if c.Stop {
			c.ICount += uint64(done)
			return
		}
	}
	c.ICount += uint64(n)
}

// refSteps runs n instructions on the reference: used when the slice ends
// inside a block (once per slice), so fused ops are never split.
func (c *CPU) refSteps(n int) int {
	c.flags()
	for range n {
		c.refStep()
	}
	return n
}

// execOps runs a run of a block's ops; it returns the instructions executed
// and whether an op left the block.
func (c *CPU) execOps(ops []op) (int, bool) {
	base := int(ops[0].cnt) - 1 - int(ops[0].extra) - int(ops[0].pre)
	for i := range ops {
		o := &ops[i]
		if o.fn(c, o) {
			return int(o.cnt) - base, true
		}
	}
	c.RIP = ops[len(ops)-1].next
	return int(ops[len(ops)-1].cnt) - base, false
}
