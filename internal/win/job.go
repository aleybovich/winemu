package win

// Job objects: a named, refcounted kernel object grouping processes.
// Children of a member process join its job unless they break away
// (CREATE_BREAKAWAY_FROM_JOB with JOB_OBJECT_LIMIT_BREAKAWAY_OK, or
// JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK). Closing the last handle of a job
// with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE terminates its processes. Limits
// are stored and reported; none but the kill/breakaway flags are enforced.
// State is guarded by Kernel.mu.

const (
	jobLimitBreakawayOK       = 0x800
	jobLimitSilentBreakawayOK = 0x1000
	jobLimitKillOnJobClose    = 0x2000
	jobBasicValidFlags        = 0xFF
	jobExtendedValidFlags     = 0x7FFF

	createBreakawayFromJob = 0x01000000

	jobBasicAccounting = 1
	jobBasicLimit      = 2
	jobProcessIDList   = 3
	jobUIRestrictions  = 4
	jobSecurityLimit   = 5
	jobEndOfJobTime    = 6
	jobCompletionPort  = 7
	jobExtendedLimit   = 9
)

type jobObj struct {
	kname
	limits  [144]byte // JOBOBJECT_EXTENDED_LIMIT_INFORMATION (basic limits = first 64 bytes)
	ui      uint32    // JOBOBJECT_BASIC_UI_RESTRICTIONS
	procs   []*Process
	ended   int // members terminated by TerminateJobObject / kill-on-close
	closing bool
}

func (j *jobObj) flags() uint32 { return le32(j.limits[16:]) }

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// unref releases a handle; the last one kills the members of a
// kill-on-close job.
func (j *jobObj) unref() {
	k := j.k
	if k == nil {
		return
	}
	k.mu.Lock()
	j.refs--
	last := j.refs == 0
	if last && j.key != "" {
		delete(k.names, j.key)
		j.key = ""
	}
	var kill []*Process
	if last && j.flags()&jobLimitKillOnJobClose != 0 {
		kill = j.liveLocked()
		j.ended += len(kill)
	}
	k.mu.Unlock()
	for _, p := range kill {
		p.terminate(0)
	}
}

func (j *jobObj) liveLocked() []*Process {
	var out []*Process
	for _, p := range j.procs {
		if !p.exited {
			out = append(out, p)
		}
	}
	return out
}

// addLocked makes p a member (Kernel.mu held).
func (j *jobObj) addLocked(p *Process) {
	p.xp.job = j
	j.procs = append(j.procs, p)
}

// childJob returns the job a new child of e joins (nil: none), or a Win32
// error if the creation flags ask for a breakaway the job does not allow.
func (e *Emu) childJob(flags uint32) (*jobObj, uint32) {
	e.k.mu.Lock()
	defer e.k.mu.Unlock()
	j := e.proc.xp.job
	if j == nil {
		return nil, 0
	}
	f := j.flags()
	if f&jobLimitSilentBreakawayOK != 0 {
		return nil, 0
	}
	if flags&createBreakawayFromJob != 0 {
		if f&jobLimitBreakawayOK == 0 {
			return nil, errAccessDenied
		}
		return nil, 0
	}
	return j, 0
}

func (e *Emu) joinJob(j *jobObj, p *Process) {
	if j == nil {
		return
	}
	e.k.mu.Lock()
	j.addLocked(p)
	e.k.mu.Unlock()
}

// inheritJob puts a child created without CreateProcess flags (builtin cmd,
// system, _popen) into e's job, as CreateProcess would.
func (e *Emu) inheritJob(p *Process) {
	j, _ := e.childJob(0) // no breakaway requested: cannot fail
	e.joinJob(j, p)
}

// jobArg resolves a job handle; h == 0 means the caller's job if allowZero.
func (e *Emu) jobArg(h uint64, allowZero bool) *jobObj {
	if h == 0 && allowZero {
		e.k.mu.Lock()
		defer e.k.mu.Unlock()
		return e.proc.xp.job
	}
	j, _ := e.handles.get(h).(*jobObj)
	return j
}

func init() {
	k := dK32
	regAW(k, "CreateJobObject", func(e *Emu, w bool) uint64 {
		name, key := e.strArg(1, w), ""
		if name != "" {
			key = "job:" + objName(name)
		}
		o, existed := e.createNamed(key, &jobObj{})
		if existed {
			e.SetLastError(errAlreadyExists)
		} else {
			e.SetLastError(0)
		}
		return e.handleFor(o, e.saInherit(e.Arg(0)))
	})
	regAW(k, "OpenJobObject", func(e *Emu, w bool) uint64 {
		name := e.strArg(2, w)
		if name == "" {
			return e.fail(errInvalidParameter)
		}
		o := e.openNamed("job:" + objName(name))
		if o == nil {
			return e.fail(errFileNotFound)
		}
		return e.handleFor(o, e.Arg32(1) != 0)
	})
	reg(k, "AssignProcessToJobObject", func(e *Emu) uint64 {
		j := e.jobArg(e.Arg(0), false)
		p := e.procArg(1)
		if j == nil || p == nil {
			return e.fail(errInvalidHandle)
		}
		e.k.mu.Lock()
		defer e.k.mu.Unlock()
		switch {
		case p.xp.job == j:
		case p.exited || p.xp.job != nil: // nested jobs are not supported
			return e.fail(errAccessDenied)
		default:
			j.addLocked(p)
		}
		return 1
	})
	reg(k, "IsProcessInJob", func(e *Emu) uint64 {
		p := e.procArg(0)
		if p == nil {
			return e.fail(errInvalidHandle)
		}
		var j *jobObj
		if h := e.Arg(1); h != 0 {
			if j = e.jobArg(h, false); j == nil {
				return e.fail(errInvalidHandle)
			}
		}
		e.k.mu.Lock()
		in := p.xp.job != nil && (j == nil || p.xp.job == j)
		e.k.mu.Unlock()
		e.Mem.W32(e.Arg(2), uint32(b2u(in)))
		return 1
	})
	reg(k, "TerminateJobObject", func(e *Emu) uint64 {
		j := e.jobArg(e.Arg(0), false)
		if j == nil {
			return e.fail(errInvalidHandle)
		}
		code := e.Arg32(1)
		e.k.mu.Lock()
		live := j.liveLocked()
		j.ended += len(live)
		e.k.mu.Unlock()
		self := false
		for _, p := range live {
			if p == e.proc {
				self = true
				continue
			}
			p.terminate(code)
		}
		if self {
			e.crt.flushAll()
			e.exitProcess(code)
		}
		return 1
	})
	reg(k, "SetInformationJobObject", func(e *Emu) uint64 {
		j := e.jobArg(e.Arg(0), false)
		if j == nil {
			return e.fail(errInvalidHandle)
		}
		class, buf, n := e.Arg32(1), e.Arg(2), e.Arg32(3)
		need := map[uint32]uint32{jobBasicLimit: 64, jobExtendedLimit: 144, jobUIRestrictions: 4,
			jobEndOfJobTime: 4, jobCompletionPort: 16}
		want, known := need[class]
		switch {
		case class == jobSecurityLimit:
			return 1 // deprecated; accepted
		case !known:
			return e.fail(errInvalidParameter)
		case n != want:
			return e.fail(errBadLength)
		}
		b := e.Mem.ReadBytes(buf, int(n))
		e.k.mu.Lock()
		defer e.k.mu.Unlock()
		switch class {
		case jobBasicLimit, jobExtendedLimit:
			valid := uint32(jobBasicValidFlags)
			if class == jobExtendedLimit {
				valid = jobExtendedValidFlags
			}
			if le32(b[16:])&^valid != 0 {
				return e.fail(errInvalidParameter)
			}
			if class == jobBasicLimit { // the extended-only flags are kept
				put32(b[16:], le32(b[16:])|j.flags()&^jobBasicValidFlags)
			}
			io := j.limits[64:112]
			saved := [48]byte(io)
			copy(j.limits[:], b)
			copy(j.limits[64:112], saved[:]) // IO counters are not settable
		case jobUIRestrictions:
			j.ui = le32(b)
		}
		return 1
	})
	reg(k, "QueryInformationJobObject", func(e *Emu) uint64 {
		j := e.jobArg(e.Arg(0), true)
		if j == nil {
			return e.fail(errInvalidHandle)
		}
		class, buf, n, ret := e.Arg32(1), e.Arg(2), e.Arg32(3), e.Arg(4)
		e.k.mu.Lock()
		var out []byte
		switch class {
		case jobBasicAccounting:
			out = make([]byte, 48)
			live := len(j.liveLocked())
			put32(out[36:], uint32(len(j.procs))) // TotalProcesses
			put32(out[40:], uint32(live))         // ActiveProcesses
			put32(out[44:], uint32(j.ended))      // TotalTerminatedProcesses
		case jobBasicLimit:
			out = append([]byte(nil), j.limits[:64]...)
		case jobExtendedLimit:
			out = append([]byte(nil), j.limits[:]...)
		case jobUIRestrictions:
			out = make([]byte, 4)
			put32(out, j.ui)
		case jobProcessIDList:
			live := j.liveLocked()
			out = make([]byte, 8+8*len(live))
			put32(out, uint32(len(live)))
			put32(out[4:], uint32(len(live)))
			for i, p := range live {
				put32(out[8+8*i:], p.pid)
			}
		}
		e.k.mu.Unlock()
		if out == nil {
			return e.fail(errInvalidParameter)
		}
		if class == jobProcessIDList {
			if n < 8 {
				return e.fail(errBadLength)
			}
			if uint32(len(out)) > n { // as many ids as fit
				fit := (n - 8) / 8
				put32(out[4:], fit)
				out = out[:8+8*fit]
				e.Mem.Write(buf, out)
				if ret != 0 {
					e.Mem.W32(ret, uint32(len(out)))
				}
				return e.fail(errMoreData)
			}
		} else if n != uint32(len(out)) {
			return e.fail(errBadLength)
		}
		e.Mem.Write(buf, out)
		if ret != 0 {
			e.Mem.W32(ret, uint32(len(out)))
		}
		return 1
	})
}

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
