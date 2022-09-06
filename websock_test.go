package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	grlws "github.com/gorilla/websocket"
	glnws "golang.org/x/net/websocket"
)

const (
	testHello          = "Enter data> "
	testReply          = "got: "
	testReadBufLen     = 8192
	testCloseWaitDelay = 300 * time.Millisecond
)

func handleTestSocket(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed") {
				log.Printf("Could not accept: %s", err)
			}
			break
		}
		go func(conn net.Conn) {
			defer conn.Close()
			if n, err := conn.Write([]byte(testHello)); err != nil {
				log.Fatalf("Could not write hello %#v[%d]: %s", testHello, n, err)
			}
			buf := make([]byte, testReadBufLen)
			if n, err := conn.Read(buf); err != nil && err != io.EOF {
				log.Fatalf("Couldn't receive data: %s", err)
			} else {
				newBuf := []byte(testReply)
				newBuf = append(newBuf, buf[:n]...)
				if _, err := conn.Write(newBuf); err != nil {
					log.Fatalf("Could not write new buf %#v[%d] %s", string(newBuf), len(newBuf), err)
				}
				//log.Printf("Sent reply: %#v[%d]", string(newBuf), len(newBuf))
			}
		}(conn)
	}
}

func readWriteGlnWS(t *testing.T, srv *httptest.Server, testString []byte) (ret []byte) {
	ws, err := glnws.Dial("ws"+srv.URL[4:], "", "http://localhost")
	if err != nil {
		t.Errorf("Cannot dial: %s", err)
		return
	}
	defer ws.Close()
	var plt byte

	if rdr, err := ws.NewFrameReader(); err != nil {
		t.Errorf("Could not create frame reader: %s", err)
		return
	} else {
		buf := make([]byte, testReadBufLen)
		if n, err := rdr.Read(buf); err != nil {
			t.Errorf("Could not read message: %s", err)
			return
		} else {
			if !bytes.Equal(buf[:n], []byte(testHello)) {
				t.Errorf("Could not receive test %#v!=%#v[%d]: %s", testHello, string(buf[:n]), n, err)
				return
			}
			plt = rdr.PayloadType()
			t.Logf("Got greeting %#v[%d] (plt=%d)", string(buf[:n]), n, plt)
		}
	}
	if wrt, err := ws.NewFrameWriter(plt); err != nil {
		t.Errorf("Could not create frame writer: %s", err)
		return
	} else {
		if n, err := wrt.Write(testString); err != nil {
			t.Errorf("Could not write %#v[%d]: %s", testString, n, err)
			return
		}
		if rdr, err := ws.NewFrameReader(); err != nil {
			t.Errorf("Could not create second frame reader: %s", err)
			return
		} else {
			buf := make([]byte, testReadBufLen)
			if n, err := rdr.Read(buf); err != nil {
				t.Errorf("Could not read message[%d]: %s", n, err)
				return
			} else {
				if !bytes.Equal(buf[:len(testReply)], []byte(testReply)) {
					t.Errorf("reply does not start with %#v", testReply)
				}
				t.Logf("Got reply: %#v[%d] (err=%#v, plt=%d)", string(buf[:n]), n, err, rdr.PayloadType())
				ret = buf[len(testReply):n]
			}
		}
	}

	return
}

func readWriteGrlWS(t *testing.T, srv *httptest.Server, testString []byte) (ret []byte) {
	ws, _, err := grlws.DefaultDialer.Dial("ws"+srv.URL[4:], nil)
	if err != nil {
		t.Errorf("Cannot dial: %s", err)
		return
	}
	defer ws.Close()
	var plt int

	if msgType, buf, err := ws.ReadMessage(); err != nil {
		t.Errorf("Could not read message: %s", err)
		return
	} else {
		if !bytes.Equal(buf, []byte(testHello)) {
			t.Errorf("Could not receive test %#v!=%#v[%d]: %s", testHello, string(buf), len(buf), err)
			return
		}
		plt = msgType
		t.Logf("Got greeting %#v[%d] (plt=%d)", string(buf), len(buf), plt)
	}
	if err := ws.WriteMessage(plt, testString); err != nil {
		t.Errorf("Could not write %#v[%d]: %s", testString, len(testString), err)
		return
	}
	if msgType, buf, err := ws.ReadMessage(); err != nil {
		t.Errorf("Could not read message: %s", err)
		return
	} else {
		if !bytes.Equal(buf[:len(testReply)], []byte(testReply)) {
			t.Errorf("reply does not start with %#v", testReply)
		}
		t.Logf("Got reply: %#v[%d] (err=%#v, plt=%d)", string(buf), len(buf), err, msgType)
		ret = buf[len(testReply):]
	}
	return
}

func genSelfSigned(t *testing.T) tls.Certificate {
	template := &x509.Certificate{
		NotAfter:    time.Now().Add(time.Hour),
		NotBefore:   time.Now().Add(-time.Minute),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	template.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(math.MaxInt64))

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Cannot generate private key: ", err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal("Cannot create certificate: ", err)
	}
	return tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: privateKey}
}

func TestWebSocket(t *testing.T) {
	currentLogLevel = logLevelError
	testString1, _ := hex.DecodeString("516934b05d9bf61fd01c5a8bbb87c112f929734620094f180ef87fc7133082a05580b0929f167c576c92deb9eff8b48dc717d524d4d6cb91d706b5baa91cd6075ed0cdf2280cedcee7ca7132a5c2420e989638dfd03464b9ac090d175ddea66ae365513838fd943fd723705660eea2fb9a0c2acda51b9fa93eb0a7ff24279ae00a25117e511459ff62a62328454e35721ae3e83cb82022254760f9ba9fa87a5000f51c7494a343c527ab84dd54c2b60cb97c792c36ff0a5a4d0ec0ee4bbccbdc39092e4c65a9552cc7a2fb1cfe13af83b2034994b575e5167e5744d7875b5e9d2daba171303a1647d46cf213e9fb3ea7386e9523f146b812a94ddb19f1e68f23dcf68d53715588fbf753d1f2b37ce6a496fd8ef0068968aa31f4aad27b33d0d2e81e000226da1a9e2916ab22b978466ed77fc722e7eaca8921d04f9aea9cc59bd29eb6308555667a1a5ddffba7f3112d995169fb591856121fd5f5cde31c04afa2e28378bf7e42b967a547971fbae3186e297be4c37da03e00420d5c2130bc98b5160bf092c493644eeaf4fcfa23c8dbb94da1757fecb819b96c3dd4e19b598179c87f4a4ea6749a33d50ccd2969c2047e017109b825070d7bb9b757074f70a969265223e79bb30f1f7eff991aa0047eaf02d432e9ce7a43d1522539d65adc20c2429a60f14602bdf48306a094a3add082d0deaa39c848e59be62685d13d34137f582da334e8a371f1074dd24aada7ac0d3dc22ae3d9bae2328dd9a3168ea1fab0d5acc1d30f62cc710d84915d1ca471af6692a6ec5d25ec9f2fc7b891e31def656bc9a35937d5ec65433db3e7c890ca7a421877ba732bc0c389e50264ca07cae1065222bc1a4612c7073739fcabdbc1e5ee8e626887266431cabef7c9307ac6b5daf8db6727e0ca9c0c0c1fe1eebd983854223ce5fbaa8f4584ba8ad58ad38679cd0c5884b536a180c2c6ffa51bce1df5658722fe92fb44503f1dfd872fccd59421850b188c5173772ffae5d3a4a89cc0136cedf443f0d9db8161c86477535e19cfa183ae19dfa330eae5c741d153cfcf67928b273813efd55571d42ef64a7b83f933860d54325ef591bb1ac0c394cf9d7a1c858255326f3c291576cabd01c943933903b56d7c5b4eb9481159c31617dd61055d2d5585346aa930bd85d680ef54090e63c325d3f85f22efb2f48a35c32661c778233c5c629c0586228267683aec77b4bb68d232a96baab1c93a0db1cdf6313eaeabb36a4fb26c23b96b7ddcaae7652b429735965b0a8dd60d1d383596894ab97a97ab413e7ef045e6c18a09889d6eacd4e9ea16229e0959f754838f05f2756e866e1b2a5af7d95f417a57befd9c5e04740c9a7166a938f07759edc75b303ff5ffa6acbe3bfe6af92f6cf543793d5050600115097731a7086398c20751a55de0abed6d0820b5d2cae35d")

	t.Run("tcp", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("Cannot start TCP listener: ", err)
		}
		defer l.Close()
		go handleTestSocket(l)
		t.Run("binary", func(t *testing.T) {
			srv := httptest.NewServer(newWebSocketHandler(l.Addr().String()))
			defer srv.Close()
			reply := readWriteGrlWS(t, srv, testString1)
			if !bytes.Equal(reply, testString1) {
				t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(testString1),
					hex.EncodeToString(reply), hex.EncodeToString(testString1))
			}
		})
		t.Run("text", func(t *testing.T) {
			srv := httptest.NewServer(newWebSocketHandler("{type=text}" + l.Addr().String()))
			defer srv.Close()
			buf := testString1
			reply := readWriteGlnWS(t, srv, buf)
			if bytes.Equal(reply, buf) {
				t.Logf("Reply matches test")
			} else {
				t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(buf),
					hex.EncodeToString(reply), hex.EncodeToString(buf))
			}
		})

	})

	t.Run("tls", func(t *testing.T) {
		l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{genSelfSigned(t)},
		})
		if err != nil {
			t.Fatal("Cannot start TLS listener: ", err)
		}
		defer l.Close()
		go handleTestSocket(l)

		srv := httptest.NewServer(newWebSocketHandler("{tlsVerify=0}tls:" + l.Addr().String()))
		defer srv.Close()
		reply := readWriteGrlWS(t, srv, testString1)
		if !bytes.Equal(reply, testString1) {
			t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(testString1),
				hex.EncodeToString(reply), hex.EncodeToString(testString1))
		}
	})

	t.Run("unix", func(t *testing.T) {
		l, err := net.Listen("unix", "/tmp/test-ws-listen")
		if err != nil {
			t.Fatal("Cannot start UNIX listener: ", err)
		}
		defer l.Close()
		go handleTestSocket(l)
		t.Run("no-prefix", func(t *testing.T) {
			srv := httptest.NewServer(newWebSocketHandler("/tmp/test-ws-listen"))
			defer srv.Close()
			reply := readWriteGrlWS(t, srv, testString1)
			if !bytes.Equal(reply, testString1) {
				t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(testString1),
					hex.EncodeToString(reply), hex.EncodeToString(testString1))
			}
		})
		t.Run("unix-prefix", func(t *testing.T) {
			srv := httptest.NewServer(newWebSocketHandler("unix:/tmp/test-ws-listen"))
			defer srv.Close()
			reply := readWriteGrlWS(t, srv, testString1)
			if !bytes.Equal(reply, testString1) {
				t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(testString1),
					hex.EncodeToString(reply), hex.EncodeToString(testString1))
			}
		})
		t.Run("abstract", func(t *testing.T) {
			l, err := net.Listen("unix", "@/test/abstract/ws")
			if err != nil {
				t.Fatal("Cannot start UNIX listener: ", err)
			}
			defer l.Close()
			go handleTestSocket(l)

			srv := httptest.NewServer(newWebSocketHandler("@/test/abstract/ws"))
			defer srv.Close()
			reply := readWriteGrlWS(t, srv, testString1)
			if !bytes.Equal(reply, testString1) {
				t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(testString1),
					hex.EncodeToString(reply), hex.EncodeToString(testString1))
			}
		})
	})

	t.Run("exec", func(t *testing.T) {
		t.Run("sh-c", func(t *testing.T) {
			srv := httptest.NewServer(newWebSocketHandler("{type=text}exec:echo -n \"" + testHello + "\";read x; echo \"" + testReply + "$x\";sleep 1"))
			defer srv.Close()
			testString := []byte("Just some random data\n")
			reply := readWriteGrlWS(t, srv, testString)
			if !bytes.Equal(reply, testString) {
				t.Errorf("Reply[%d] does not match test[%d] %#v != %#v", len(reply), len(testString),
					hex.EncodeToString(reply), hex.EncodeToString(testString))
			}
		})
		t.Run("sep", func(t *testing.T) {
			srv := httptest.NewServer(newWebSocketHandler("{sh=/bin/echo,no-c=1,sep=;}exec:1;2;3"))
			defer srv.Close()
			conn, _, err := grlws.DefaultDialer.Dial("ws"+srv.URL[4:], nil)
			if err != nil {
				t.Errorf("Cannot connect to %s: %s", srv.URL, err)
				return
			}
			_, msg, err := conn.ReadMessage()
			if err != nil {
				t.Errorf("Could not read message: %s", err)
				return
			}
			if string(msg) != "1 2 3\n" {
				t.Errorf("Messages is not \"1 2 3\": %#v", string(msg))
				return
			}
		})
	})

	t.Run("inject-req-nr", func(t *testing.T) {
		beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf("request headers are %#v", r.Header)))
		}))
		defer beSrv.Close()
		srv := httptest.NewServer(newWebSocketHandler("{injReqNrHdr=X-Req-Nr}" + beSrv.Listener.Addr().String()))
		defer srv.Close()
		conn, _, err := grlws.DefaultDialer.Dial("ws"+srv.URL[4:], nil)
		if err != nil {
			t.Errorf("Could not dial to %#v: %s", srv.URL, err)
			return
		}
		conn.WriteMessage(grlws.BinaryMessage, []byte("GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		_, reply, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("Failed to read reply: %s", err)
			return
		}
		t.Logf("X-Req-Nr reply: %#v", string(reply))
		if !bytes.Contains(reply, []byte("X-Req-Nr")) {
			t.Errorf("X-Req-Nr not found in reply: %#v", string(reply))
		}
	})

	t.Run("mux", func(t *testing.T) {
		srv := httptest.NewServer(&HTTPLogger{DefaultHandler: newWebSocketHandler("{re=/(.*)}mux:$1")})
		defer srv.Close()

		urlA := "ws" + srv.URL[4:] + "/a"
		urlB := "ws" + srv.URL[4:] + "/b"

		connA1, _, err := grlws.DefaultDialer.Dial(urlA, nil)
		if err != nil {
			t.Errorf("Cannot dial client1 to %s: %s", urlA, err)
			return
		}
		defer connA1.Close()
		connA2, _, err := grlws.DefaultDialer.Dial(urlA, nil)
		if err != nil {
			t.Errorf("Cannot dial client2 to %s: %s", urlA, err)
			return
		}
		defer connA2.Close()
		connA3, _, err := grlws.DefaultDialer.Dial(urlA, nil)
		if err != nil {
			t.Errorf("Cannot dial client2 to %s: %s", urlA, err)
			return
		}
		defer connA3.Close()

		connB1, _, err := grlws.DefaultDialer.Dial(urlB, nil)
		if err != nil {
			t.Errorf("Cannot dial client1 to %s: %s", urlB, err)
			return
		}
		defer connB1.Close()
		connB2, _, err := grlws.DefaultDialer.Dial(urlB, nil)
		if err != nil {
			t.Errorf("Cannot dial client2 to %s: %s", urlB, err)
			return
		}
		defer connB2.Close()

		testA := []byte("This is a test")
		testB := []byte("This is another test")
		testA2 := []byte("Some more tests")
		t.Run("write", func(t *testing.T) {
			t.Run("A", func(t *testing.T) {
				if err := connA1.WriteMessage(grlws.BinaryMessage, testA); err != nil {
					t.Errorf("Cannot write testA: %s", err)
					return
				}
			})
			t.Run("B", func(t *testing.T) {
				if err := connB1.WriteMessage(grlws.BinaryMessage, testB); err != nil {
					t.Errorf("Cannot write testB: %s", err)
					return
				}
			})
			t.Run("A2", func(t *testing.T) {
				if err := connA2.WriteMessage(grlws.BinaryMessage, testA2); err != nil {
					t.Errorf("Cannot write testA2: %s", err)
					return
				}
			})
		})
		t.Run("read A", func(t *testing.T) {
			t.Run("C2", func(t *testing.T) {
				_, connAbuf2, err := connA2.ReadMessage()
				if err != nil {
					t.Errorf("Error reading message A2: %s", err)
					return
				}
				if !bytes.Equal(connAbuf2, testA) {
					t.Errorf("Answer A2 (%#v) is not testA (%#v)", string(connAbuf2), string(testA))
					return
				}
			})
			t.Run("C3", func(t *testing.T) {
				_, connAbuf3, err := connA3.ReadMessage()
				if err != nil {
					t.Errorf("Error reading message A3: %s", err)
					return
				}
				if !bytes.Equal(connAbuf3, testA) {
					t.Errorf("Answer A3 (%#v) is not testA (%#v)", string(connAbuf3), string(testA))
					return
				}
				t.Run("A2", func(t *testing.T) {
					_, connAbuf3_2, err := connA3.ReadMessage()
					if err != nil {
						t.Errorf("Error reading message A3(2): %s", err)
						return
					}
					if !bytes.Equal(connAbuf3_2, testA2) {
						t.Errorf("Answer A3(2) (%#v) is not testA2 (%#v)", string(connAbuf3_2), string(testA2))
						return
					}
				})
			})
		})
		t.Run("read B", func(t *testing.T) {
			_, connBbuf2, err := connB2.ReadMessage()
			if err != nil {
				t.Errorf("Error reading message B2: %s", err)
				return
			}
			if !bytes.Equal(connBbuf2, testB) {
				t.Errorf("Answer B2 (%#v) is not testB (%#v)", string(connBbuf2), string(testB))
				return
			}
		})
		t.Run("read A2C1", func(t *testing.T) {
			_, connAbuf1, err := connA1.ReadMessage()
			if err != nil {
				t.Errorf("Error reading message A1: %s", err)
				return
			}
			if !bytes.Equal(connAbuf1, testA2) {
				t.Errorf("Answer A1 (%#v) is not testA2 (%#v)", string(connAbuf1), string(testA2))
				return
			}
		})
		t.Run("large-binary", func(t *testing.T) {
			maxSize := 1024 * 1024
			for curSize := 1; curSize < maxSize; curSize = curSize * 2 {
				randBuf := make([]byte, curSize)
				nBytes, err := rand.Read(randBuf)
				if err != nil || nBytes != curSize {
					t.Errorf("Cannot fill randBuf: want=%d got=%d, err=%s", curSize, nBytes, err)
					return
				}
				if err := connA1.WriteMessage(grlws.BinaryMessage, randBuf); err != nil {
					t.Errorf("Error writing rndbuf[%d]: %s", curSize, err)
					return
				}
				msgType, recvBuf, err := connA2.ReadMessage()
				if err != nil {
					t.Errorf("Could not read msg[%d]: %s", curSize, err)
					return
				}
				if len(recvBuf) != curSize {
					t.Errorf("recvBuf length %d does not match randBuf %d", len(recvBuf), curSize)
					return
				}
				for i := 0; i < curSize; i++ {
					if randBuf[i] != recvBuf[i] {
						t.Errorf("Receive buf doesn't match randBuf[%d] at %d", curSize, i)
						return
					}
				}
				t.Logf("Received correct msg type=%d len=%d", msgType, curSize)
			}
		})
	})
}
