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

func (svc *wsProxyService) DialTo() (net.Conn, error) {
	if svc.listener == nil {
		return nil, net.ErrClosed
	}
	reqConn, conn := net.Pipe()
	svc.lock.Lock()
	svc.seq += 1
	clientId := svc.seq
	svc.clients[clientId] = &wsSink{buf: make(chan interface{}, 4)}
	svc.lock.Unlock()
	svc.listener.buf <- map[string]interface{}{"connected": clientId}
	go func() {
		defer conn.Close()
		defer svc.closeClient(clientId)
		for {
			data := make([]byte, 16*1024)
			n, err := conn.Read(data)
			if err != nil {
				log.Printf("Could not read[%d] from http request pipe: %s", n, err)
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
	}()
	go func(s *wsSink) {
		defer conn.Close()
		defer svc.closeClient(clientId)
		for {
			data := <-s.buf
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
				log.Printf("could not send %d/%d bytes to http req: %s", n, len(dataOut), err)
				break
			}
		}
	}(svc.clients[clientId])
	return reqConn, nil
}

func (*WSProxyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request.URL.Scheme = "http"

	wsprxSvc := getWsPrxSvc(request.URL.Host)

	return (&http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return wsprxSvc.DialTo()
		},
	}).RoundTrip(request)
}

func init() {
	customHttpSchemas["wsprx"] = func() http.RoundTripper { return &WSProxyRoundTripper{} }
}
