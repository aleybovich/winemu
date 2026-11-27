// pg_e2e drives a PostgreSQL server lifecycle from one guest process:
// initdb, pg_ctl start -w, a client session over the PostgreSQL wire
// protocol (v3, trust auth, simple queries), pg_ctl stop -w.
//
// Environment: PG_BUNDLE (directory holding bin\initdb.exe), PG_WORK
// (scratch directory), PG_PORT (TCP port).
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	bundle, work, port := os.Getenv("PG_BUNDLE"), os.Getenv("PG_WORK"), os.Getenv("PG_PORT")
	if bundle == "" || work == "" || port == "" {
		fail("PG_BUNDLE, PG_WORK and PG_PORT must be set")
	}
	bin := filepath.Join(bundle, "bin")
	data := filepath.Join(work, "data")
	pwfile := filepath.Join(work, "pwfile")
	if err := os.WriteFile(pwfile, []byte("postgres\n"), 0o600); err != nil {
		fail("pwfile: %v", err)
	}

	step(work, "initdb", filepath.Join(bin, "initdb"), "-A", "trust", "-U", "postgres", "-D", data,
		"--pwfile="+pwfile, "--locale=C", "--encoding=UTF8")
	step(work, "pg_ctl start", filepath.Join(bin, "pg_ctl"), "start", "-w", "-D", data,
		"-o", "-p "+port, "-l", filepath.Join(work, "server.log"))

	t0 := time.Now()
	err := query("127.0.0.1:"+port, "SELECT version()", "SELECT 1+1")
	fmt.Printf("client: %v (%.1fs)\n", status(err), time.Since(t0).Seconds())

	step(work, "pg_ctl stop", filepath.Join(bin, "pg_ctl"), "stop", "-w", "-D", data)
	if err != nil {
		os.Exit(1)
	}
}

// step runs exe with stdout+stderr in a file, not a pipe: pg_ctl start
// leaves the postmaster running with the inherited handles, so a pipe would
// never reach EOF.
func step(work, name, exe string, args ...string) {
	logPath := filepath.Join(work, strings.ReplaceAll(name, " ", "_")+".out")
	f, err := os.Create(logPath)
	if err != nil {
		fail("%s: %v", name, err)
	}
	t0 := time.Now()
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = f, f
	err = cmd.Run()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	out, rerr := os.ReadFile(logPath)
	if err == nil {
		err = rerr
	}
	fmt.Printf("%s: %v (%.1fs)\n", name, status(err), time.Since(t0).Seconds())
	if err != nil {
		fmt.Printf("--- %s output:\n%s---\n", name, out)
		os.Exit(1)
	}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Success.") || l == "server started" || l == "server stopped" ||
			strings.Contains(l, "restricted token") {
			fmt.Printf("  %s\n", l)
		}
	}
}

func status(err error) string {
	if err != nil {
		return "FAIL " + err.Error()
	}
	return "ok"
}

func fail(f string, a ...any) {
	fmt.Printf(f+"\n", a...)
	os.Exit(2)
}

// query runs each simple query in one session and prints its rows.
func query(addr string, sqls ...string) error {
	c, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return err
	}
	r := bufio.NewReader(c)

	// StartupMessage: length, protocol 3.0, name/value pairs, terminator.
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 196608)
	for _, s := range []string{"user", "postgres", "database", "postgres"} {
		b = append(append(b, s...), 0)
	}
	b = append(b, 0)
	if _, err := c.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(b)+4)), b...)); err != nil {
		return err
	}
	if err := untilReady(r, nil); err != nil {
		return fmt.Errorf("startup: %w", err)
	}
	for _, sql := range sqls {
		m := append([]byte(sql), 0)
		if _, err := c.Write(append(append([]byte{'Q'}, binary.BigEndian.AppendUint32(nil, uint32(len(m)+4))...), m...)); err != nil {
			return err
		}
		var rows [][]string
		if err := untilReady(r, &rows); err != nil {
			return fmt.Errorf("%s: %w", sql, err)
		}
		fmt.Printf("query %q -> %q\n", sql, rows)
	}
	_, err = c.Write([]byte{'X', 0, 0, 0, 4})
	return err
}

// untilReady reads backend messages up to ReadyForQuery, collecting DataRow
// fields into rows (if non-nil).
func untilReady(r *bufio.Reader, rows *[][]string) error {
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(hdr[1:])
		if n < 4 {
			return fmt.Errorf("bad message length %d", n)
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return err
		}
		switch hdr[0] {
		case 'R': // Authentication
			if len(body) < 4 || binary.BigEndian.Uint32(body) != 0 {
				return fmt.Errorf("authentication method %v not supported (need trust)", body)
			}
		case 'E':
			return errors.New("server error: " + strings.ReplaceAll(string(body), "\x00", " "))
		case 'D':
			if rows == nil || len(body) < 2 {
				continue
			}
			cols, p := int(binary.BigEndian.Uint16(body)), 2
			row := make([]string, 0, cols)
			for range cols {
				if p+4 > len(body) {
					return errors.New("short DataRow")
				}
				l := int32(binary.BigEndian.Uint32(body[p:]))
				p += 4
				if l < 0 {
					row = append(row, "NULL")
					continue
				}
				if p+int(l) > len(body) {
					return errors.New("short DataRow")
				}
				row = append(row, string(body[p:p+int(l)]))
				p += int(l)
			}
			*rows = append(*rows, row)
		case 'Z':
			return nil
		}
	}
}
