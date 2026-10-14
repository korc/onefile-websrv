package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	grlws "github.com/gorilla/websocket"
)

func TestWSTNLPayloadSizes(t *testing.T) {
	forwarderPath := filepath.Join("test", "wstnl-forwarder")
	if _, err := os.Stat(forwarderPath); err != nil {
		t.Skipf("forwarder binary not found: %v", err)
	}

	// Plain TCP echo backend used by the wstnl listener.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	echoAddr := echoLn.Addr().String()

	srv := httptest.NewServer(&wstnlHandler{poolName: "testpool", encoding: "utf-8"})
	defer srv.Close()

	listenPath := "/tunnel"
	wsURL := "ws://" + srv.Listener.Addr().String() + listenPath
	cmd := exec.Command(forwarderPath, "-connect", echoAddr, wsURL)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	// Give the listener time to bind.
	time.Sleep(1 * time.Second)

	sizes := []int{1, 64, 1024, 64 * 1024, 1024 * 1024, 4 * 1024 * 1024}
	for _, size := range sizes {
		t.Run(fmtSize(size), func(t *testing.T) {
			payload := make([]byte, size)
			_, _ = randOrZero(payload)

			ws, _, err := grlws.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			ws.SetReadDeadline(time.Now().Add(60 * time.Second))
			ws.SetWriteDeadline(time.Now().Add(60 * time.Second))

			if err := ws.WriteMessage(grlws.BinaryMessage, payload); err != nil {
				t.Fatal(err)
			}

			var resp bytes.Buffer
			for resp.Len() < size {
				mt, chunk, err := ws.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				if mt != grlws.BinaryMessage {
					t.Fatalf("unexpected message type: %d", mt)
				}
				resp.Write(chunk)
			}
			if resp.Len() != size {
				t.Fatalf("size mismatch: got %d want %d", resp.Len(), size)
			}
			if !bytes.Equal(resp.Bytes(), payload) {
				t.Fatal("payload mismatch")
			}
			ws.Close()
		})
	}
}

func fmtSize(n int) string {
	switch {
	case n >= 1024*1024:
		return fmtInt(n/1024/1024) + "MiB"
	case n >= 1024:
		return fmtInt(n/1024) + "KiB"
	default:
		return fmtInt(n) + "B"
	}
}

func fmtInt(n int) string {
	// avoid importing strconv? we already can import.
	return itoa(n)
}

func itoa(n int) string {
	// small helper
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 16)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func TestWSTNLMultiplePools(t *testing.T) {
	forwarderPath := filepath.Join("test", "wstnl-forwarder")
	if _, err := os.Stat(forwarderPath); err != nil {
		t.Skipf("forwarder binary not found: %v", err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	echoAddr := echoLn.Addr().String()

	mux := http.NewServeMux()
	mux.Handle("/alpha/", &wstnlHandler{poolName: "alpha", encoding: "utf-8"})
	mux.Handle("/beta/", &wstnlHandler{poolName: "beta", encoding: "utf-8"})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	paths := []string{"/alpha/a", "/alpha/b", "/beta/a", "/beta/b"}
	host := "ws://" + srv.Listener.Addr().String()
	var cmds []*exec.Cmd
	for _, p := range paths {
		cmd := exec.Command(forwarderPath, "-connect", echoAddr, host+p)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	t.Cleanup(func() {
		for _, c := range cmds {
			c.Process.Kill()
			c.Wait()
		}
	})
	time.Sleep(1 * time.Second)

	type failure struct {
		msg string
	}
	var mu sync.Mutex
	var failures []failure
	var wg sync.WaitGroup

	for pi, p := range paths {
		for ci := 0; ci < 2; ci++ {
			path := p
			seq := pi*2 + ci
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload := make([]byte, 64*1024)
				for i := range payload {
					payload[i] = byte((seq + i) % 251)
				}

				url := host + path
				ws, _, err := grlws.DefaultDialer.Dial(url, nil)
				if err != nil {
					mu.Lock()
					failures = append(failures, failure{msg: path + ": dial failed: " + err.Error()})
					mu.Unlock()
					return
				}
				defer ws.Close()
				ws.SetReadDeadline(time.Now().Add(60 * time.Second))
				ws.SetWriteDeadline(time.Now().Add(60 * time.Second))

				if err := ws.WriteMessage(grlws.BinaryMessage, payload); err != nil {
					mu.Lock()
					failures = append(failures, failure{msg: path + ": write failed: " + err.Error()})
					mu.Unlock()
					return
				}

				var resp bytes.Buffer
				for resp.Len() < len(payload) {
					mt, chunk, err := ws.ReadMessage()
					if err != nil {
						mu.Lock()
						failures = append(failures, failure{msg: path + ": read failed: " + err.Error()})
						mu.Unlock()
						return
					}
					if mt != grlws.BinaryMessage {
						mu.Lock()
						failures = append(failures, failure{msg: path + ": unexpected message type"})
						mu.Unlock()
						return
					}
					resp.Write(chunk)
				}
				if !bytes.Equal(resp.Bytes(), payload) {
					mu.Lock()
					failures = append(failures, failure{msg: path + ": payload mismatch"})
					mu.Unlock()
					return
				}
			}()
		}
	}
	wg.Wait()

	if len(failures) > 0 {
		for _, f := range failures {
			t.Error(f.msg)
		}
	}
}

func randOrZero(b []byte) (int, error) {
	// Fill with deterministic-ish pseudo random using crypto/rand is slow for 4MB;
	// use a repeatable byte pattern.
	for i := range b {
		b[i] = byte(i % 251)
	}
	return len(b), nil
}
