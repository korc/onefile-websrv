package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

var wsMuxMap = make(map[string]*wsMux)

type wsMux struct {
	addr        string
	readBuffers map[uint64]chan []byte
	bufMux      *sync.Mutex
}

type wsMuxClient struct {
	mux    *wsMux
	reqNum uint64
}

type wsMuxClientAddr struct{ addr string }

func (wsMuxClientAddr) Network() string   { return "ws-mux" }
func (a *wsMuxClientAddr) String() string { return a.addr }

func getWSMux(addr string) *wsMux {
	if ret, have := wsMuxMap[addr]; have {
		return ret
	} else {
		wsMuxMap[addr] = &wsMux{
			addr:        addr,
			readBuffers: make(map[uint64]chan []byte),
			bufMux:      &sync.Mutex{},
		}
		return wsMuxMap[addr]
	}
}

func (m *wsMux) NewClient(r *http.Request) *wsMuxClient {
	m.bufMux.Lock()
	defer m.bufMux.Unlock()
	ret := &wsMuxClient{mux: m, reqNum: r.Context().Value(requestNumberContext).(uint64)}
	m.readBuffers[ret.reqNum] = make(chan []byte, 1)
	return ret
}

func (m *wsMuxClient) Close() error {
	m.mux.bufMux.Lock()
	defer m.mux.bufMux.Unlock()
	close(m.mux.readBuffers[m.reqNum])
	delete(m.mux.readBuffers, m.reqNum)
	return nil
}

func (m *wsMuxClient) LocalAddr() net.Addr {
	return &wsMuxClientAddr{m.mux.addr}
}

func (m *wsMuxClient) RemoteAddr() net.Addr {
	return &wsMuxClientAddr{fmt.Sprintf("%s[%d]", m.mux.addr, m.reqNum)}
}

func (m *wsMuxClient) ReadNext() (buf []byte, err error) {
	d := <-m.mux.readBuffers[m.reqNum]
	if d == nil {
		return nil, io.EOF
	}
	return d, nil
}

func (m *wsMuxClient) Read(b []byte) (n int, err error) {
	d := <-m.mux.readBuffers[m.reqNum]
	if d == nil {
		return 0, io.EOF
	}
	m.mux.bufMux.Lock()
	defer m.mux.bufMux.Unlock()
	n = copy(b, d)
	if n < len(d) {
		m.mux.readBuffers[m.reqNum] <- d[n:]
	}
	return n, err
}

func (m *wsMuxClient) Write(b []byte) (n int, err error) {
	m.mux.bufMux.Lock()
	defer m.mux.bufMux.Unlock()
	for reqNum := range m.mux.readBuffers {
		if reqNum == m.reqNum {
			continue
		}
		m.mux.readBuffers[reqNum] <- b
	}
	return len(b), nil
}

func (m *wsMuxClient) SetDeadline(time.Time) error      { return ErrNotImplemented }
func (m *wsMuxClient) SetReadDeadline(time.Time) error  { return ErrNotImplemented }
func (m *wsMuxClient) SetWriteDeadline(time.Time) error { return ErrNotImplemented }
