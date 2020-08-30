package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
	return true
}}

type execConn struct {
	cmd          *exec.Cmd
	shellCommand string
	rdDeadLine   time.Time
	wrDeadline   time.Time
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stderr       io.ReadCloser
}

func (e *execConn) Network() string {
	return "exec"
}

func (e *execConn) String() string {
	return e.shellCommand
}

func (e *execConn) Read(b []byte) (n int, err error) {
	return e.stdout.Read(b)
}

func (e *execConn) Write(b []byte) (n int, err error) {
	return e.stdin.Write(b)
}

func (e *execConn) LocalAddr() net.Addr {
	return e
}

func (e *execConn) RemoteAddr() net.Addr {
	return e
}

func (e *execConn) SetDeadline(t time.Time) error {
	log.Printf("not implemented: execConn.SetDeadline(%#v)", t)
	e.rdDeadLine = t
	e.wrDeadline = t
	return nil
}

func (e *execConn) SetReadDeadline(t time.Time) error {
	log.Printf("not implemented: execConn.SetReadDeadline(%#v)", t)
	e.rdDeadLine = t
	return nil
}

func (e *execConn) SetWriteDeadline(t time.Time) error {
	log.Printf("not implemented: execConn.SetWriteDeadline(%#v)", t)
	e.wrDeadline = t
	return nil
}

func newExecConn(name string, arg ...string) (conn *execConn, err error) {
	cmd := exec.Command(name, arg...)
	conn = &execConn{
		cmd:          cmd,
		shellCommand: name,
	}
	if conn.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if conn.stdout, err = cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	if conn.stderr, err = cmd.StderrPipe(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		io.Copy(os.Stderr, conn.stderr)
	}()
	return conn, nil
}

func (e *execConn) Close() error {
	e.stdin.Close()
	return e.cmd.Wait()
}
