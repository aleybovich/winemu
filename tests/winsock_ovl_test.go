package tests

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// WS-B2: overlapped sockets, IOCP and socket sharing (guest tests).

// Go guest: net.Listen + net/http server and http.Get/Post clients in one
// process, a read deadline (CancelIoEx) and UDP.
func TestGoNetHTTPSelf(t *testing.T) {
	r := runGuest(t, "ws_gonet.exe", guestOpts{Args: []string{"self"}, Timeout: 60 * time.Second})
	if r.Code != 0 || !strings.Contains(r.Stdout, "ALL OK") {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// A host net/http client reaches a Go HTTP server running in the guest.
func TestGoNetHostHTTPClient(t *testing.T) {
	port := strconv.Itoa(freePort(t))
	const requests = 4
	done := make(chan guestResult, 1)
	go func() {
		done <- runGuest(t, "ws_gonet.exe", guestOpts{Args: []string{"serve", port, strconv.Itoa(requests)}, Timeout: 60 * time.Second})
	}()
	base := "http://127.0.0.1:" + port
	client := &http.Client{Timeout: 10 * time.Second}
	get := func(path string) (string, error) {
		resp, err := client.Get(base + path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	deadline := time.Now().Add(30 * time.Second)
	body, err := get("/hello?n=1")
	for err != nil && time.Now().Before(deadline) {
		select {
		case r := <-done:
			t.Fatalf("guest exited early: %d\n%s%s", r.Code, r.Stdout, r.Stderr)
		case <-time.After(50 * time.Millisecond):
		}
		body, err = get("/hello?n=1")
	}
	if err != nil || body != "hello 1" {
		t.Fatalf("GET: %q %v", body, err)
	}
	for i := 2; i < requests; i++ {
		if body, err := get("/hello?n=" + strconv.Itoa(i)); err != nil || body != "hello "+strconv.Itoa(i) {
			t.Fatalf("GET %d: %q %v", i, body, err)
		}
	}
	big := strings.Repeat("x", 3<<20)
	resp, err := client.Post(base+"/echo", "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != big {
		t.Fatalf("POST echo: %d bytes", len(b))
	}
	r := <-done
	if r.Code != 0 || !strings.Contains(r.Stdout, "served 4") {
		t.Fatalf("guest: exit %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
}

// Go guest net.Dial to a host TCP server.
func TestGoNetDialHost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, "host echo: "+line)
	}()
	r := runGuest(t, "ws_gonet.exe", guestOpts{Args: []string{"dial", l.Addr().String()}, Timeout: 60 * time.Second})
	if r.Code != 0 || !strings.Contains(r.Stdout, "reply: host echo: hello from guest") {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
	}
}

// C guest: AcceptEx/ConnectEx echo over an IOCP worker, completion routines,
// CancelIoEx of a pending AcceptEx.
func TestWinsockIOCPEcho(t *testing.T) { runWinsockGuest(t, "ws_iocp_echo.exe") }

// C guest: WSADuplicateSocket parent -> child serving the connection, and a
// child serving an inherited listening socket.
func TestWinsockDuplicateSocket(t *testing.T) { runWinsockGuest(t, "ws_dupsock.exe") }
