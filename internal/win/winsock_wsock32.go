//go:build darwin || linux

package win

// Winsock export ordinals and wsock32.dll (Winsock 1.1), whose exports
// forward to the ws2_32 implementations. Both tables follow the classic
// Winsock numbering; note that ws2_32 and wsock32 differ at 10..12.

var ws2Ordinals = map[uint32]string{
	1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname",
	7: "getsockopt", 8: "htonl", 9: "htons", 10: "ioctlsocket", 11: "inet_addr", 12: "inet_ntoa",
	13: "listen", 14: "ntohl", 15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send",
	20: "sendto", 21: "setsockopt", 22: "shutdown", 23: "socket",
	51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname", 54: "getprotobynumber",
	55: "getservbyname", 56: "getservbyport", 57: "gethostname",
	101: "WSAAsyncSelect", 102: "WSAAsyncGetHostByAddr", 103: "WSAAsyncGetHostByName",
	104: "WSAAsyncGetProtoByNumber", 105: "WSAAsyncGetProtoByName", 106: "WSAAsyncGetServByPort",
	107: "WSAAsyncGetServByName", 108: "WSACancelAsyncRequest", 109: "WSASetBlockingHook",
	110: "WSAUnhookBlockingHook", 111: "WSAGetLastError", 112: "WSASetLastError",
	113: "WSACancelBlockingCall", 114: "WSAIsBlocking", 115: "WSAStartup", 116: "WSACleanup",
	151: "__WSAFDIsSet", 500: "WEP",
}

var wsock32Ordinals = map[uint32]string{
	1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname",
	7: "getsockopt", 8: "htonl", 9: "htons", 10: "inet_addr", 11: "inet_ntoa", 12: "ioctlsocket",
	13: "listen", 14: "ntohl", 15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send",
	20: "sendto", 21: "setsockopt", 22: "shutdown", 23: "socket", 24: "MigrateWinsockConfiguration",
	51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname", 54: "getprotobynumber",
	55: "getservbyname", 56: "getservbyport", 57: "gethostname",
	101: "WSAAsyncSelect", 102: "WSAAsyncGetHostByAddr", 103: "WSAAsyncGetHostByName",
	104: "WSAAsyncGetProtoByNumber", 105: "WSAAsyncGetProtoByName", 106: "WSAAsyncGetServByPort",
	107: "WSAAsyncGetServByName", 108: "WSACancelAsyncRequest", 109: "WSASetBlockingHook",
	110: "WSAUnhookBlockingHook", 111: "WSAGetLastError", 112: "WSASetLastError",
	113: "WSACancelBlockingCall", 114: "WSAIsBlocking", 115: "WSAStartup", 116: "WSACleanup",
	151: "__WSAFDIsSet", 500: "WEP", 1000: "WSApSetPostRoutine",
	1100: "inet_network", 1101: "getnetbyname", 1102: "rcmd", 1103: "rexec", 1104: "rresvport",
	1105: "sethostname", 1106: "dn_expand", 1107: "WSARecvEx", 1108: "s_perror",
	1109: "GetAddressByNameA", 1110: "GetAddressByNameW", 1111: "EnumProtocolsA", 1112: "EnumProtocolsW",
	1113: "GetTypeByNameA", 1114: "GetTypeByNameW", 1115: "GetNameByTypeA", 1116: "GetNameByTypeW",
	1117: "SetServiceA", 1118: "SetServiceW", 1119: "GetServiceA", 1120: "GetServiceW",
	1130: "NPLoadNameSpaces", 1140: "TransmitFile", 1141: "AcceptEx", 1142: "GetAcceptExSockaddrs",
}

// wsock32Forwarded lists the wsock32 exports forwarded to ws2_32 (those
// ws2_32 implements; TestWsock32Forwarders checks the list).
var wsock32Forwarded = []string{
	"accept", "bind", "closesocket", "connect", "getpeername", "getsockname", "getsockopt", "htonl",
	"htons", "inet_addr", "inet_ntoa", "ioctlsocket", "listen", "ntohl", "ntohs", "recv", "recvfrom",
	"select", "send", "sendto", "setsockopt", "shutdown", "socket", "gethostbyaddr", "gethostbyname",
	"getprotobyname", "getprotobynumber", "getservbyname", "getservbyport", "gethostname",
	"WSAGetLastError", "WSASetLastError", "WSAStartup", "WSACleanup", "__WSAFDIsSet",
}

func init() {
	for o, n := range ws2Ordinals {
		regOrd("ws2_32.dll", o, n)
	}
	for o, n := range wsock32Ordinals {
		regOrd("wsock32.dll", o, n)
	}
	for _, n := range wsock32Forwarded {
		// resolved at call time, independent of init order
		reg("wsock32.dll", n, func(e *Emu) uint64 { return registry["ws2_32.dll"].funcs[n].fn(e) })
	}
}
