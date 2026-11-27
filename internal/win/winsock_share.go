//go:build darwin || linux

package win

// Socket sharing between processes: WSADuplicateSocketA/W and
// WSASocket(FROM_PROTOCOL_INFO).
//
// WSADuplicateSocket registers the socket object in the kernel namespace
// under "sockdup:<id>" for the target process and writes <id> into
// WSAPROTOCOL_INFO.dwProviderReserved; the registration holds a reference,
// so the source may close its descriptor right away. The target's WSASocket
// consumes the registration (once) and gets a handle to the same object -
// the same thing handle inheritance and DuplicateHandle produce. The object
// is safe for concurrent use (sockObj.mu); WSAEventSelect events are
// recorded by one polling owner (sockObj.evOwner).
//
// Limitation: a registration the target never consumes keeps the socket
// open until the session ends.

import "fmt"

const wsaFlagNoHandleInherit = 0x80

type sockDup struct {
	s   *sockObj
	pid uint32
}

func sockDupKey(id uint32) string { return fmt.Sprintf("sockdup:%d", id) }

// WSADuplicateSocketA/W(s, dwProcessId, lpProtocolInfo)
func (e *Emu) duplicateSocket(wide bool) uint64 {
	s := e.sockArg(0)
	if s == nil {
		return sockErr
	}
	pid, info := e.Arg32(1), e.Arg(2)
	if info == 0 {
		return e.wsaFail(wsaEFAULT)
	}
	if e.k.process(pid) == nil {
		return e.wsaFail(wsaEINVAL)
	}
	p := protoFor(s.af, s.typ, s.proto)
	if p == nil {
		return e.wsaFail(wsaEINVAL)
	}
	s.refs++ // held by the registration (s is locked)
	id := e.k.allocID()
	e.k.mu.Lock()
	e.k.names[sockDupKey(id)] = &sockDup{s: s, pid: pid}
	e.k.mu.Unlock()
	e.writeProtoInfo(info, p, wide, id)
	return 0
}

// socketFromInfo creates the target's descriptor for a duplicated socket;
// ok=false when the info does not describe one (a catalog entry).
func (e *Emu) socketFromInfo(pi uint64) (h uint64, ok bool) {
	id := e.Mem.R32(pi + protoInfoReserved)
	if id == 0 {
		return 0, false
	}
	key := sockDupKey(id)
	e.k.mu.Lock()
	d, _ := e.k.names[key].(*sockDup)
	if d != nil && d.pid == e.proc.pid {
		delete(e.k.names, key)
	} else {
		d = nil
	}
	e.k.mu.Unlock()
	if d == nil {
		return e.wsaFail(wsaEINVAL), true
	}
	h = e.handles.add(d.s) // refs: +1 for the handle
	d.s.unref()            // -1 for the consumed registration
	e.netSt().socks[d.s] = true
	return h, true
}

func init() {
	w := "ws2_32.dll"
	regWS(w, "WSADuplicateSocketW", func(e *Emu) uint64 { return e.duplicateSocket(true) })
	regWS(w, "WSADuplicateSocketA", func(e *Emu) uint64 { return e.duplicateSocket(false) })
}
