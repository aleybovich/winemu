package tests

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// WS-B1: Winsock (synchronous + event model) guest tests.

func runWinsockGuest(t *testing.T, exe string) {
	t.Helper()
	r := runGuest(t, exe, guestOpts{Timeout: 60 * time.Second})
	if r.Code != 0 || !strings.Contains(r.Stdout, "ALL OK") {
		t.Fatalf("%s: exit %d\nstdout:\n%s\nstderr:\n%s", exe, r.Code, r.Stdout, r.Stderr)
	}
}

// blocking echo server/client threads, IPv4 + IPv6 loopback, MSG_WAITALL,
// getaddrinfo("localhost"), WSAECONNREFUSED, WSAEADDRINUSE
func TestWinsockBlockingEcho(t *testing.T) { runWinsockGuest(t, "ws_echo_blocking.exe") }

// non-blocking sockets driven by select()
func TestWinsockNonblockSelect(t *testing.T) { runWinsockGuest(t, "ws_nonblock_select.exe") }

// WSAEventSelect + WaitForMultipleObjects + WSAEnumNetworkEvents server loop
func TestWinsockEventSelect(t *testing.T) { runWinsockGuest(t, "ws_eventselect.exe") }

// A host client (net.Dial) talks to a guest listening socket.
func TestWinsockHostClient(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	done := make(chan guestResult, 1)
	go func() {
		done <- runGuest(t, "ws_host_server.exe", guestOpts{Args: []string{strconv.Itoa(port)}, Timeout: 60 * time.Second})
	}()
	var conn net.Conn
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err == nil || time.Now().After(deadline) {
			break
		}
		select {
		case r := <-done:
			t.Fatalf("guest exited before accepting: code %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("dial guest: %v", err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, "ping from host\n"); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "echo: ping from host\n" {
		t.Fatalf("reply %q, err %v", reply, err)
	}
	conn.Close()
	r := <-done
	if r.Code != 0 || !strings.Contains(r.Stdout, "served ping from host from 127.0.0.1") {
		t.Fatalf("guest: exit %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
}
