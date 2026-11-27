package win

// ntdll status helpers used by CRT-level code (last NTSTATUS, NtFlushBuffersFileEx).

func init() {
	// TEB.LastStatusValue (x64 offset 0x1250)
	reg(dNt, "RtlGetLastNtStatus", func(e *Emu) uint64 { return uint64(e.Mem.R32(e.Cur.TEB + 0x1250)) })
	// NtFlushBuffersFileEx(FileHandle, Flags, Parameters, ParametersSize, IoStatusBlock)
	reg(dNt, "NtFlushBuffersFileEx", func(e *Emu) uint64 {
		h := e.Arg(0)
		if fo := e.fileObj(h); fo != nil {
			if fo.f != nil && fo.console == 0 {
				fo.f.Sync()
			}
		} else if e.npEndOf(h) == nil {
			return 0xC0000008 // STATUS_INVALID_HANDLE
		}
		if iosb := e.Arg(4); iosb != 0 {
			e.Mem.W64(iosb, 0)
			e.Mem.W64(iosb+8, 0)
		}
		return 0
	})
}
