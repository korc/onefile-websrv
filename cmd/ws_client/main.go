package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

var exitOnBadStatus = false
var connCount atomic.Uint64
var writeDataType = websocket.BinaryMessage

const bufSize = 32 * 1024

//goland:noinspection GoUnhandledErrorResult
func connectAndLoop(location string, headers http.Header, dst io.WriteCloser, src io.ReadCloser) error {
	defer dst.Close()
	defer src.Close()
	connNum := connCount.Add(1)
	log.Printf("[%d] Dialing to %s", connNum, location)
	ws, resp, err := websocket.DefaultDialer.Dial(location, headers)
	if err != nil {
		log.Printf("[%d] Could not connect: %s (resp=%#v)", connNum, err, resp)
		if exitOnBadStatus && (resp == nil || resp.StatusCode == http.StatusBadRequest) {
			os.Exit(100)
		}
		return err
	}
	defer ws.Close()

	log.Printf("[%d] Connected, transferring data", connNum)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer ws.Close()
		defer src.Close()
		defer dst.Close()
		defer log.Printf("[%d] local closed the socket", connNum)
		for {
			buf := make([]byte, bufSize)
			nRead, err := src.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[%d] Error reading socket: %s", connNum, err)
				}
				break
			}
			if err := ws.WriteMessage(writeDataType, buf[:nRead]); err != nil {
				log.Printf("[%d] Error writing WS: %s", connNum, err)
				break
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer ws.Close()
		defer dst.Close()
		defer src.Close()
		defer log.Printf("[%d] remote closed the socket", connNum)
		for {
			msgType, buf, err := ws.ReadMessage()
			if err != nil {
				if err != io.EOF {
					log.Printf("[%d] Error reading WS (%d): %s", connNum, msgType, err)
				}
				break
			}
			toWrite := len(buf)
			for toWrite > 0 {
				nWritten, err := dst.Write(buf)
				if err != nil {
					log.Printf("[%d] Error writing socket: %s", connNum, err)
					break
				}
				buf = buf[nWritten:]
				toWrite = len(buf)
			}
		}
	}()
	wg.Wait()
	log.Printf("[%d] finished", connNum)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	certFlag := flag.String("cert", "", "Certificate for SSL connection")
	certKeyFlag := flag.String("key", "", "Key for SSL certificate")
	listenAddr := flag.String("listen", "", "Listen on address instead of stdin/out")
	connectAddr := flag.String("connect", "", "Connect to address instead of stdin/out")
	flag.IntVar(&writeDataType, "type", writeDataType, "WS write data type")
	exitOnBadStatusFlag := flag.Bool("exit-on-bad-status", false, "exit with 100 on bad status from WS")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalf("Usage: %v [<options>] <wss_url> [<header1=xxx>...]\n", filepath.Base(os.Args[0]))
	}

	url := args[0]

	exitOnBadStatus = *exitOnBadStatusFlag

	if *certFlag != "" {
		if *certKeyFlag == "" {
			*certKeyFlag = *certFlag
		}
		websocket.DefaultDialer.TLSClientConfig = &tls.Config{
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				log.Printf("Client certificate requested: %#v", info)
				cert, err := tls.LoadX509KeyPair(*certFlag, *certKeyFlag)
				if err != nil {
					log.Printf("Could not load certificate: %s", err)
				}
				return &cert, err
			},
		}
	}

	headers := make(http.Header)

	if len(args) > 1 {
		for i := 1; i < len(args); i++ {
			kv := strings.SplitN(args[i], "=", 2)
			headers.Set(kv[0], kv[1])
		}
	}
	if *listenAddr == "" && *connectAddr == "" {
		connectAndLoop(url, headers, os.Stdout, os.Stdin)
	} else if *connectAddr == "" {
		proto := "tcp"
		if idx := strings.Index(*listenAddr, "://"); idx >= 0 {
			proto = (*listenAddr)[:idx]
			*listenAddr = (*listenAddr)[idx+3:]
		}
		log.Printf("Listening on %s address %#v", proto, *listenAddr)
		ls, err := net.Listen(proto, *listenAddr)
		if err != nil {
			log.Fatalf("Could not listen on %#v: %s", *listenAddr, err)
		}
		for {
			conn, err := ls.Accept()
			if err != nil {
				log.Fatal("Error accepting client: ", err)
			}
			go connectAndLoop(url, headers, conn, conn)
		}
	} else {
		proto := "tcp"
		if idx := strings.Index(*connectAddr, "://"); idx >= 0 {
			proto = (*connectAddr)[:idx]
			*connectAddr = (*connectAddr)[idx+3:]
		}
		log.Printf("Connecting to %s address %#v", proto, *connectAddr)
		conn, err := net.Dial(proto, *connectAddr)
		if err != nil {
			log.Fatalf("Could not connect to %#v: %s", *connectAddr, err)
		} else {
			log.Print("Connected")
		}
		connectAndLoop(url, headers, conn, conn)
	}
}
