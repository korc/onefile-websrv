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

	"golang.org/x/net/websocket"
)

//goland:noinspection GoUnhandledErrorResult
func connectAndLoop(wsConfig *websocket.Config, dst io.WriteCloser, src io.ReadCloser) error {
	defer dst.Close()
	defer src.Close()
	log.Printf("Dialing to %s", wsConfig.Location)
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		log.Print("Could not connect: ", err)
		return err
	}
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame

	log.Printf("Connected, transferring data")

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer ws.Close()
		defer src.Close()
		defer dst.Close()
		defer log.Printf("local closed the socket")
		io.Copy(ws, src)
	}()
	go func() {
		defer wg.Done()
		defer ws.Close()
		defer dst.Close()
		defer src.Close()
		defer log.Printf("remote closed the socket")
		io.Copy(dst, ws)
	}()
	wg.Wait()
	log.Printf("finished")
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	originFlag := flag.String("origin", "http://localhost", "websocket origin")
	certFlag := flag.String("cert", "", "Certificate for SSL connection")
	certKeyFlag := flag.String("key", "", "Key for SSL certificate")
	listenAddr := flag.String("listen", "", "Listen on address instead of stdin/out")
	connectAddr := flag.String("connect", "", "Connect to address instead of stdin/out")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalf("Usage: %v [<options>] <wss_url> [<header1=xxx>...]\n", filepath.Base(os.Args[0]))
	}

	url := args[0]

	wsConfig, err := websocket.NewConfig(url, *originFlag)
	if err != nil {
		panic(err)
	}

	if *certFlag != "" {
		if *certKeyFlag == "" {
			*certKeyFlag = *certFlag
		}
		wsConfig.TlsConfig = &tls.Config{
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

	if len(args) > 1 {
		wsConfig.Header = http.Header{}
		for i := 1; i < len(args); i++ {
			kv := strings.SplitN(args[i], "=", 2)
			wsConfig.Header.Add(kv[0], kv[1])
		}
	}
	if *listenAddr == "" && *connectAddr == "" {
		connectAndLoop(wsConfig, os.Stdout, os.Stdin)
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
			go connectAndLoop(wsConfig, conn, conn)
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
		connectAndLoop(wsConfig, conn, conn)
	}
}
