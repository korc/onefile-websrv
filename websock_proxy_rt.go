package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
)

type WSProxyRoundTripper struct{}

func (svc *wsProxyService) DialTo(clientId uint32) (net.Conn, error) {
	if svc.listener == nil {
		return nil, net.ErrClosed
	}
	reqConn, conn := net.Pipe()
	svc.lock.Lock()
	client := newWSSink(nil, 0)
	svc.clients[clientId] = client
	svc.lock.Unlock()
	svc.listener.buf <- map[string]interface{}{"connected": clientId}
	go func(s *wsSink) {
		defer s.Close()
		defer conn.Close()
		defer reqConn.Close()
		defer svc.closeClient(clientId)
		for {
			data := make([]byte, 16*1024)
			n, err := conn.Read(data)
			if err != nil {
				if err != io.EOF {
					log.Printf("Could not read[%d] from http request pipe: %s", n, err)
				}
				break
			}
			if n == 0 {
				break
			}
			msg := make([]byte, 4+n)
			binary.LittleEndian.PutUint32(msg, clientId)
			copy(msg[4:], data[:n])
			svc.listener.buf <- msg
		}
	}(client)
	go func(s *wsSink) {
		defer s.Close()
		defer conn.Close()
		defer reqConn.Close()
		defer svc.closeClient(clientId)
		for {
			var data interface{}
			select {
			case <-s.done:
			case data = <-s.buf:
			}
			if data == nil {
				break
			}
			dataOut, ok := data.([]byte)
			if !ok {
				var err error
				dataOut, err = json.Marshal(data)
				if err != nil {
					log.Printf("ERROR: could not marshal %#v: %s", data, err)
					continue
				}
			}
			if n, err := io.Copy(conn, bytes.NewReader(dataOut)); err != nil {
				if err.Error() != "io: read/write on closed pipe" {
					log.Printf("could not send %d/%d bytes to http req: %s", n, len(dataOut), err)
				}
				break
			}
		}
	}(client)
	return reqConn, nil
}

func (*WSProxyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request.URL.Scheme = "http"

	wsprxSvc := getWsPrxSvc(request.URL.Host)

	return (&http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			reqNum := ctx.Value(requestNumberContext).(int)
			return wsprxSvc.DialTo(uint32(reqNum))
		},
	}).RoundTrip(request)
}

func init() {
	customHttpSchemas["wsprx"] = func() http.RoundTripper { return &WSProxyRoundTripper{} }
}
