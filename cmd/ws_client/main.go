package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/net/websocket"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	originFlag := flag.String("origin", "http://localhost", "websocket origin")
	certFlag := flag.String("cert", "", "Certificate for SSL connection")
	certKeyFlag := flag.String("key", "", "Key for SSL certificate")
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

	if len(args) > 2 {
		wsConfig.Header = http.Header{}
		for i := 1; i < len(args); i++ {
			kv := strings.SplitN(args[i], "=", 2)
			wsConfig.Header.Add(kv[0], kv[1])
		}
	}

	log.Printf("Dialing to %s, origin = %s", url, *originFlag)
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		panic(err)
	}
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame

	log.Printf("Connected, transferring data")

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer ws.Close()
		defer os.Stdin.Close()
		defer os.Stdout.Close()
		defer log.Printf("local closed the socket")
		io.Copy(ws, os.Stdin)
	}()
	go func() {
		defer wg.Done()
		defer ws.Close()
		defer os.Stdout.Close()
		defer os.Stdin.Close()
		defer log.Printf("remote closed the socket")
		io.Copy(os.Stdout, ws)
	}()
	wg.Wait()
	log.Printf("finished")
}
