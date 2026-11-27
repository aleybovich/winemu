package win

import "testing"

func TestJobCreateOpenAssign(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	j := h.call(dK32, "CreateJobObjectW", 0, h.wstr("xp-job"))
	if j == 0 || h.lastError() != 0 {
		t.Fatalf("create: err %d", h.lastError())
	}
	if j2 := h.call(dK32, "CreateJobObjectW", 0, h.wstr("xp-job")); j2 == 0 || h.lastError() != errAlreadyExists {
		t.Fatal("existing name")
	}
	if h.call(dK32, "OpenJobObjectW", 0x1F001F, 0, h.wstr("xp-nojob")) != 0 || h.lastError() != errFileNotFound {
		t.Fatal("open missing")
	}
	in := h.alloc(4)
	if h.call(dK32, "IsProcessInJob", hb, 0, in) != 1 || h.r32(in) != 0 {
		t.Fatal("not in a job yet")
	}
	if h.call(dK32, "AssignProcessToJobObject", j, hb) != 1 {
		t.Fatalf("assign: err %d", h.lastError())
	}
	if h.call(dK32, "IsProcessInJob", hb, j, in) != 1 || h.r32(in) != 1 || h.call(dK32, "IsProcessInJob", pseudoProcess, j, in) != 1 || h.r32(in) != 0 {
		t.Fatal("IsProcessInJob")
	}
	other := h.call(dK32, "CreateJobObjectW", 0, 0)
	if h.call(dK32, "AssignProcessToJobObject", other, hb) != 0 || h.lastError() != errAccessDenied {
		t.Fatal("second job")
	}
	if h.call(dK32, "AssignProcessToJobObject", hb, hb) != 0 || h.lastError() != errInvalidHandle {
		t.Fatal("not a job handle")
	}
	ids := h.alloc(64)
	if h.call(dK32, "QueryInformationJobObject", j, jobProcessIDList, ids, 64, 0) != 1 || h.r32(ids) != 1 || h.r64(ids+8) != uint64(b.E.proc.pid) {
		t.Fatal("process id list")
	}
	acc := h.alloc(48)
	if h.call(dK32, "QueryInformationJobObject", j, jobBasicAccounting, acc, 48, 0) != 1 || h.r32(acc+36) != 1 || h.r32(acc+40) != 1 {
		t.Fatal("accounting")
	}
}

func TestJobLimits(t *testing.T) {
	h := newTestEmu(t)
	j := h.call(dK32, "CreateJobObjectA", 0, 0)
	ext := h.alloc(144)
	h.w32(ext+16, jobLimitKillOnJobClose|jobLimitBreakawayOK)
	if h.call(dK32, "SetInformationJobObject", j, jobBasicLimit, ext, 64) != 0 || h.lastError() != errInvalidParameter {
		t.Fatal("extended flag through basic limits")
	}
	if h.call(dK32, "SetInformationJobObject", j, jobExtendedLimit, ext, 100) != 0 || h.lastError() != errBadLength {
		t.Fatal("bad length")
	}
	if h.call(dK32, "SetInformationJobObject", j, jobExtendedLimit, ext, 144) != 1 {
		t.Fatalf("extended: err %d", h.lastError())
	}
	basic := h.alloc(64)
	h.w32(basic+16, 0x100>>4) // JOB_OBJECT_LIMIT_PRIORITY_CLASS (0x20)
	h.w32(basic+56, 0x20)
	if h.call(dK32, "SetInformationJobObject", j, jobBasicLimit, basic, 64) != 1 {
		t.Fatal("basic")
	}
	ui := h.alloc(4)
	h.w32(ui, 0xFF)
	if h.call(dK32, "SetInformationJobObject", j, jobUIRestrictions, ui, 4) != 1 {
		t.Fatal("ui restrictions")
	}
	got, ret := h.alloc(144), h.alloc(4)
	if h.call(dK32, "QueryInformationJobObject", j, jobExtendedLimit, got, 144, ret) != 1 || h.r32(ret) != 144 ||
		h.r32(got+16) != jobLimitKillOnJobClose|jobLimitBreakawayOK|0x10 || h.r32(got+56) != 0x20 {
		t.Fatalf("flags %#x", h.r32(got+16))
	}
	if h.call(dK32, "QueryInformationJobObject", j, jobUIRestrictions, got, 4, 0) != 1 || h.r32(got) != 0xFF {
		t.Fatal("ui query")
	}
	if h.call(dK32, "QueryInformationJobObject", j, jobBasicLimit, got, 8, 0) != 0 || h.lastError() != errBadLength {
		t.Fatal("query bad length")
	}
	if h.call(dK32, "SetInformationJobObject", j, 99, got, 4) != 0 || h.lastError() != errInvalidParameter {
		t.Fatal("unknown class")
	}
}

func TestJobKillOnClose(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	j := h.call(dK32, "CreateJobObjectW", 0, 0)
	j2 := h.alloc(8)
	h.call(dK32, "DuplicateHandle", pseudoProcess, j, pseudoProcess, j2, 0, 0, 2)
	ext := h.alloc(144)
	h.w32(ext+16, jobLimitKillOnJobClose)
	h.call(dK32, "SetInformationJobObject", j, jobExtendedLimit, ext, 144)
	h.call(dK32, "AssignProcessToJobObject", j, hb)
	h.call(dK32, "CloseHandle", j)
	if _, done := b.E.proc.exitStatus(); done {
		t.Fatal("killed while a handle remains")
	}
	h.call(dK32, "CloseHandle", h.r64(j2))
	if code, done := b.E.proc.exitStatus(); !done || code != 0 {
		t.Fatalf("member not killed on close: done %v code %d", done, code)
	}
}

func TestJobTerminate(t *testing.T) {
	h := newTestEmu(t)
	b := sibling(t, h)
	hb := procHandle(h, b)
	j := h.call(dK32, "CreateJobObjectW", 0, 0)
	h.call(dK32, "AssignProcessToJobObject", j, hb)
	if h.call(dK32, "TerminateJobObject", j, 7) != 1 {
		t.Fatal("TerminateJobObject")
	}
	if code, done := b.E.proc.exitStatus(); !done || code != 7 {
		t.Fatalf("done %v code %d", done, code)
	}
	acc := h.alloc(48)
	h.call(dK32, "QueryInformationJobObject", j, jobBasicAccounting, acc, 48, 0)
	if h.r32(acc+40) != 0 || h.r32(acc+44) != 1 {
		t.Fatalf("active %d terminated %d", h.r32(acc+40), h.r32(acc+44))
	}
	if h.call(dK32, "TerminateJobObject", hb, 7) != 0 || h.lastError() != errInvalidHandle {
		t.Fatal("not a job")
	}
	in := h.alloc(4)
	if h.call(dK32, "QueryInformationJobObject", 0, jobBasicLimit, in, 64, 0) != 0 || h.lastError() != errInvalidHandle {
		t.Fatal("caller in no job")
	}
}

// childJob decides which job a new child joins (CREATE_BREAKAWAY_FROM_JOB
// against JOB_OBJECT_LIMIT_BREAKAWAY_OK / SILENT_BREAKAWAY_OK).
func TestJobChildJoins(t *testing.T) {
	h := newTestEmu(t)
	if j, err := h.E.childJob(0); j != nil || err != 0 {
		t.Fatalf("no job: %v %d", j, err)
	}
	jh := h.call(dK32, "CreateJobObjectW", 0, 0)
	if h.call(dK32, "AssignProcessToJobObject", jh, pseudoProcess) != 1 {
		t.Fatalf("assign self: err %d", h.lastError())
	}
	job := h.E.handles.get(jh).(*jobObj)
	ext := h.alloc(144)
	for _, c := range []struct {
		limit, flags uint32
		want         *jobObj
		err          uint32
	}{
		{0, 0, job, 0},
		{0, createBreakawayFromJob, nil, errAccessDenied},
		{jobLimitBreakawayOK, 0, job, 0},
		{jobLimitBreakawayOK, createBreakawayFromJob, nil, 0},
		{jobLimitSilentBreakawayOK, 0, nil, 0},
		{jobLimitSilentBreakawayOK, createBreakawayFromJob, nil, 0},
	} {
		h.w32(ext+16, c.limit)
		if h.call(dK32, "SetInformationJobObject", jh, jobExtendedLimit, ext, 144) != 1 {
			t.Fatalf("limit %#x: err %d", c.limit, h.lastError())
		}
		if j, err := h.E.childJob(c.flags); j != c.want || err != c.err {
			t.Errorf("limit %#x flags %#x: job %v err %d, want %v %d", c.limit, c.flags, j != nil, err, c.want != nil, c.err)
		}
	}
}
