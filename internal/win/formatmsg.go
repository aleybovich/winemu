package win

// FormatMessageA/W: system message table lookup, insert and escape
// processing (%1..%99 with optional !printf-spec!, %0 %n %r %t %space %. %!
// %%), FORMAT_MESSAGE_IGNORE_INSERTS, ALLOCATE_BUFFER (LocalFree-able) and
// line widths (regular line breaks become CRLF with width 0, spaces with any
// other width; widths other than MAX_WIDTH_MASK do no wrapping). Message
// tables in modules (FROM_HMODULE) are not supported: a module-only lookup
// fails with ERROR_MR_MID_NOT_FOUND.

import (
	"unicode/utf16"
	"unicode/utf8"
)

const (
	fmtAllocateBuffer = 0x100
	fmtIgnoreInserts  = 0x200
	fmtFromString     = 0x400
	fmtFromHModule    = 0x800
	fmtFromSystem     = 0x1000
	fmtArgumentArray  = 0x2000
	fmtMaxWidthMask   = 0xFF

	errMrMidNotFound = 317
)

// expandMessage applies FormatMessage's escape and insert processing to
// text; ok is false when an insert has no argument source.
func (e *Emu) expandMessage(text string, flags uint32, args uint64, wide bool) (string, bool) {
	src := []rune(text)
	var out []rune
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\r' || c == '\n' { // one line break: CR, LF or CRLF
			if c == '\r' && i+1 < len(src) && src[i+1] == '\n' {
				i++
			}
			if flags&fmtMaxWidthMask != 0 {
				out = append(out, ' ') // regular line breaks are ignored
			} else {
				out = append(out, '\r', '\n')
			}
			continue
		}
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i++; i >= len(src) {
			break
		}
		switch c = src[i]; c {
		case '0':
			return string(out), true
		case 'n':
			out = append(out, '\r', '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			n, j := int(c-'0'), i+1
			if j < len(src) && src[j] >= '0' && src[j] <= '9' {
				n, j = n*10+int(src[j]-'0'), j+1
			}
			if flags&fmtIgnoreInserts != 0 {
				out = append(out, src[i-1:j]...)
				i = j - 1
				continue
			}
			spec := []rune("s")
			if j < len(src) && src[j] == '!' {
				end := j + 1
				for end < len(src) && src[end] != '!' {
					end++
				}
				if end >= len(src) {
					return "", false
				}
				spec, j = src[j+1:end], end+1
			}
			if args == 0 {
				return "", false
			}
			base := args
			if flags&fmtArgumentArray == 0 {
				base = e.Mem.R64(args) // va_list *
			}
			o := e.sprintf(append([]rune{'%'}, spec...), &vaList{e: e, p: base + 8*uint64(n-1)}, fmtOpts{wide: wide, legacyWide: true})
			if wide {
				out = append(out, utf16.Decode(o.u)...)
			} else {
				for b := o.b; len(b) > 0; {
					r, sz := utf8.DecodeRune(b)
					out, b = append(out, r), b[sz:]
				}
			}
			i = j - 1
		default: // %% %. %! %space and unknown escapes: the character itself
			if flags&fmtIgnoreInserts != 0 {
				out = append(out, '%') // only %0 %n %r %t are processed
			}
			out = append(out, c)
		}
	}
	return string(out), true
}

func init() {
	regAW(dK32, "FormatMessage", func(e *Emu, w bool) uint64 {
		flags, id := e.Arg32(0), e.Arg32(2)
		buf, size, args := e.Arg(4), e.Arg32(5), e.Arg(6)
		alloc := flags&fmtAllocateBuffer != 0
		if buf == 0 {
			return e.fail(errInvalidParameter)
		}
		if alloc {
			e.Mem.W64(buf, 0)
		}
		var text string
		switch {
		case flags&fmtFromString != 0:
			if e.Arg(1) == 0 {
				return e.fail(errInvalidParameter)
			}
			text = e.strArg(1, w)
		case flags&(fmtFromSystem|fmtFromHModule) != 0:
			s, ok := winMessages[id]
			if !ok || flags&fmtFromSystem == 0 {
				return e.fail(errMrMidNotFound)
			}
			text = s + "\r\n"
		default:
			return e.fail(errInvalidParameter)
		}
		msg, ok := e.expandMessage(text, flags, args, w)
		if !ok {
			return e.fail(errInvalidParameter)
		}
		n, unit := uint32(len(msg)), uint64(1)
		var u []uint16
		if w {
			u = utf16.Encode([]rune(msg))
			n, unit = uint32(len(u)), 2
		}
		if alloc {
			a := e.heapAllocRaw(uint64(max(n+1, size)) * unit)
			e.Mem.W64(buf, a)
			buf = a
		} else if n >= size {
			return e.fail(errInsufficientBuf)
		}
		if w {
			e.Mem.WriteUnits(buf, append(u, 0))
		} else {
			e.Mem.WriteCStr(buf, msg)
		}
		return uint64(n)
	})
}

// System message texts not provided elsewhere: the rest of the Winsock range
// (10004-11031) and codes reported by winemu's APIs.
func init() {
	for code, msg := range map[uint32]string{
		7:     "The storage control blocks were destroyed.",
		9:     "The storage control block address is invalid.",
		13:    "The data is invalid.",
		14:    "Not enough memory resources are available to complete this operation.",
		15:    "The system cannot find the drive specified.",
		16:    "The directory cannot be removed.",
		17:    "The system cannot move the file to a different disk drive.",
		21:    "The device is not ready.",
		24:    "The program issued a command but the command length is incorrect.",
		33:    "The process cannot access the file because another process has locked a portion of the file.",
		53:    "The network path was not found.",
		67:    "The network name cannot be found.",
		111:   "The file name is too long.",
		124:   "The system call level is not correct.",
		131:   "An attempt was made to move the file pointer before the beginning of the file.",
		193:   "%1 is not a valid Win32 application.",
		206:   "The filename or extension is too long.",
		231:   "All pipe instances are busy.",
		232:   "The pipe is being closed.",
		233:   "No process is on the other end of the pipe.",
		258:   "The wait operation timed out.",
		267:   "The directory name is invalid.",
		288:   "Attempt to release mutex not owned by caller.",
		298:   "Too many posts were made to a semaphore.",
		317:   "The system cannot find message text for message number 0x%1 in the message file for %2.",
		487:   "Attempt to access invalid address.",
		524:   "The user account restriction prevents this operation.",
		535:   "There is a process on other end of the pipe.",
		536:   "Waiting for a process to open the other end of the pipe.",
		995:   "The I/O operation has been aborted because of either a thread exit or an application request.",
		996:   "Overlapped I/O event is not in a signaled state.",
		997:   "Overlapped I/O operation is in progress.",
		998:   "Invalid access to memory location.",
		1004:  "Invalid flags.",
		1008:  "An attempt was made to reference a token that does not exist.",
		1060:  "The specified service does not exist as an installed service.",
		1062:  "The service has not been started.",
		1063:  "The service process could not connect to the service controller.",
		1065:  "The database specified does not exist.",
		1072:  "The specified service has been marked for deletion.",
		1073:  "The specified service already exists.",
		1083:  "The executable program that this service is configured to run in does not implement the service.",
		1113:  "No mapping for the Unicode character exists in the target multi-byte code page.",
		1114:  "A dynamic link library (DLL) initialization routine failed.",
		1168:  "Element not found.",
		1184:  "The specified port is unknown.",
		1223:  "The operation was canceled by the user.",
		1225:  "The remote computer refused the network connection.",
		1236:  "The network connection was aborted by the local system.",
		1280:  "The current thread has already been converted to a fiber.",
		1281:  "The current thread has already been converted from a fiber.",
		1300:  "Not all privileges or groups referenced are assigned to the caller.",
		1305:  "The revision level is unknown.",
		1307:  "This security ID may not be assigned as the owner of this object.",
		1308:  "This security ID may not be assigned as the primary group of an object.",
		1309:  "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.",
		1312:  "A specified logon session does not exist. It may already have been terminated.",
		1313:  "A specified privilege does not exist.",
		1314:  "A required privilege is not held by the client.",
		1332:  "No mapping between account names and security IDs was done.",
		1336:  "The access control list (ACL) structure is invalid.",
		1337:  "The security ID structure is invalid.",
		1338:  "The security descriptor structure is invalid.",
		1344:  "No more memory is available for security information updates.",
		1346:  "Either a required impersonation level was not provided, or the provided impersonation level is invalid.",
		1349:  "The type of the token is inappropriate for its attempted use.",
		1450:  "Insufficient system resources exist to complete the requested service.",
		1722:  "The RPC server is unavailable.",
		1812:  "The specified image file did not contain a resource section.",
		1813:  "The specified resource type cannot be found in the image file.",
		1814:  "The specified resource name cannot be found in the image file.",
		2221:  "The user name could not be found.",
		15106: "The user stopped resource enumeration.",

		10046: "The protocol family has not been configured into the system or no implementation for it exists.",
		10052: "The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress.",
		10059: "Too many references to some kernel object.",
		10062: "Cannot translate name.",
		10063: "Name component or name was too long.",
		10064: "A socket operation failed because the destination host was down.",
		10066: "Cannot remove a directory that is not empty.",
		10067: "A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously.",
		10068: "Ran out of quota.",
		10069: "Ran out of disk quota.",
		10070: "File handle reference is no longer available.",
		10071: "Item is not available locally.",
		10091: "WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable.",
		10101: "Returned by WSARecv or WSARecvFrom to indicate the remote party has initiated a graceful shutdown sequence.",
		10102: "No more results can be returned by WSALookupServiceNext.",
		10103: "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.",
		10104: "The procedure call table is invalid.",
		10105: "The requested service provider is invalid.",
		10106: "The requested service provider could not be loaded or initialized.",
		10107: "A system call that should never fail has failed.",
		10108: "No such service is known. The service cannot be found in the specified name space.",
		10110: "No more results can be returned by WSALookupServiceNext.",
		10111: "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.",
		10112: "A database query failed because it was actively refused.",
		11005: "At least one reserve has arrived.",
		11006: "At least one path has arrived.",
		11007: "There are no senders.",
		11008: "There are no receivers.",
		11009: "Reserve has been confirmed.",
		11010: "Error due to lack of resources.",
		11011: "Rejected for administrative reasons - bad credentials.",
		11012: "Unknown or conflicting style.",
		11013: "Problem with some part of the filterspec or providerspecific buffer in general.",
		11014: "Problem with some part of the flowspec.",
		11015: "General QOS error.",
		11016: "An invalid or unrecognized service type was found in the flowspec.",
		11017: "An invalid or inconsistent flowspec was found in the QOS structure.",
		11018: "Invalid QOS provider-specific buffer.",
		11019: "An invalid QOS filter style was used.",
		11020: "An invalid QOS filter type was used.",
		11021: "An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR.",
		11022: "An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer.",
		11023: "An incorrect number of flow descriptors was specified in the QOS structure.",
		11024: "An unrecognized object was found in the QOS provider-specific buffer.",
		11025: "An invalid policy object was found in the QOS provider-specific buffer.",
		11026: "An invalid QOS flow descriptor was found in the flow descriptor list.",
		11027: "An invalid or inconsistent flowspec was found in the QOS provider specific buffer.",
		11028: "An invalid FILTERSPEC was found in the QOS provider-specific buffer.",
		11029: "An invalid shape discard mode object was found in the QOS provider specific buffer.",
		11030: "An invalid shaping rate object was found in the QOS provider-specific buffer.",
		11031: "A reserved policy element was found in the QOS provider-specific buffer.",
	} {
		if _, ok := winMessages[code]; !ok {
			winMessages[code] = msg
		}
	}
}
