// ws_gonet exercises Go's Windows network stack (overlapped sockets, IOCP,
// AcceptEx/ConnectEx, CancelIoEx) under winemu.
//
//	ws_gonet self          HTTP server + client in one process, UDP, deadlines
//	ws_gonet serve PORT N  HTTP server on 127.0.0.1:PORT, exits after N requests
//	ws_gonet dial ADDR     TCP client: sends a line, prints the reply
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func fail(format string, a ...any) {
	fmt.Printf("FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func handler(count func()) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", r.URL.Query().Get("n"))
		count()
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
		count()
	})
	return mux
}

func self() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
	}
	go http.Serve(l, handler(func() {}))
	base := "http://" + l.Addr().String()
	// sequential requests over a keep-alive connection
	for i := range 20 {
		resp, err := http.Get(fmt.Sprintf("%s/hello?n=%d", base, i))
		if err != nil {
			fail("get %d: %v", i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != fmt.Sprintf("hello %d", i) {
			fail("get %d: body %q", i, b)
		}
	}
	// concurrent requests with a large body
	big := strings.Repeat("0123456789", 200_000)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(base+"/echo", "text/plain", strings.NewReader(big))
			if err != nil {
				errs <- fmt.Errorf("post %d: %v", i, err)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != big {
				errs <- fmt.Errorf("post %d: %d bytes back", i, len(b))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		fail("%v", err)
	}
	fmt.Println("http ok")

	// read deadline: the pending overlapped read is cancelled (CancelIoEx)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		fail("dial: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var ne net.Error
	if _, err := c.Read(make([]byte, 1)); !errors.As(err, &ne) || !ne.Timeout() {
		fail("read with deadline: %v", err)
	}
	c.Close()
	fmt.Println("deadline ok")

	// UDP (WSARecvFrom/WSASendTo overlapped, SIO_UDP_CONNRESET)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fail("listen udp: %v", err)
	}
	uc, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		fail("dial udp: %v", err)
	}
	uc.Write([]byte("datagram"))
	buf := make([]byte, 64)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "datagram" || from.String() != uc.LocalAddr().String() {
		fail("udp read: %q from %v err %v", buf[:n], from, err)
	}
	fmt.Println("udp ok")
	fmt.Println("ALL OK")
}

func serve(port string, n int) {
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		fail("listen: %v", err)
	}
	done := make(chan struct{})
	var mu sync.Mutex
	served := 0
	srv := &http.Server{Handler: handler(func() {
		mu.Lock()
		defer mu.Unlock()
		if served++; served == n {
			close(done)
		}
	})}
	go srv.Serve(l)
	fmt.Println("listening")
	<-done
	time.Sleep(100 * time.Millisecond) // let the last response go out
	fmt.Printf("served %d\n", n)
}

func dial(addr string) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fail("dial: %v", err)
	}
	defer c.Close()
	fmt.Fprintf(c, "hello from guest\n")
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		fail("read: %v", err)
	}
	fmt.Printf("reply: %s", reply)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage")
	}
	switch os.Args[1] {
	case "self":
		self()
	case "serve":
		n, _ := strconv.Atoi(os.Args[3])
		serve(os.Args[2], n)
	case "dial":
		dial(os.Args[2])
	default:
		fail("unknown mode %q", os.Args[1])
	}
}
