package win

// System message texts for Winsock error codes (FormatMessage).
func init() {
	for code, msg := range map[uint32]string{
		10004: "A blocking operation was interrupted by a call to WSACancelBlockingCall.",
		10009: "The file handle supplied is not valid.",
		10013: "An attempt was made to access a socket in a way forbidden by its access permissions.",
		10014: "The system detected an invalid pointer address in attempting to use a pointer argument in a call.",
		10022: "An invalid argument was supplied.",
		10024: "Too many open sockets.",
		10035: "A non-blocking socket operation could not be completed immediately.",
		10036: "A blocking operation is currently executing.",
		10037: "An operation was attempted on a non-blocking socket that already had an operation in progress.",
		10038: "An operation was attempted on something that is not a socket.",
		10039: "A required address was omitted from an operation on a socket.",
		10040: "A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself.",
		10041: "A protocol was specified in the socket function call that does not support the semantics of the socket type requested.",
		10042: "An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call.",
		10043: "The requested protocol has not been configured into the system, or no implementation for it exists.",
		10044: "The support for the specified socket type does not exist in this address family.",
		10045: "The attempted operation is not supported for the type of object referenced.",
		10047: "An address incompatible with the requested protocol was used.",
		10048: "Only one usage of each socket address (protocol/network address/port) is normally permitted.",
		10049: "The requested address is not valid in its context.",
		10050: "A socket operation encountered a dead network.",
		10051: "A socket operation was attempted to an unreachable network.",
		10053: "An established connection was aborted by the software in your host machine.",
		10054: "An existing connection was forcibly closed by the remote host.",
		10055: "An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.",
		10056: "A connect request was made on an already connected socket.",
		10057: "A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied.",
		10058: "A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.",
		10060: "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.",
		10061: "No connection could be made because the target machine actively refused it.",
		10065: "A socket operation was attempted to an unreachable host.",
		10092: "The Windows Sockets version requested is not supported.",
		10093: "Either the application has not called WSAStartup, or WSAStartup failed.",
		10109: "The specified class was not found.",
		11001: "No such host is known.",
		11002: "This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server.",
		11003: "A non-recoverable error occurred during a database lookup.",
		11004: "The requested name is valid, but no data of the requested type was found.",
	} {
		if _, ok := winMessages[code]; !ok {
			winMessages[code] = msg
		}
	}
}
