package main

import (
	"log"
	"net/http"
	"strings"
)

type contextKey int

const (
	authRoleContext contextKey = iota
	remoteLoggerContext
	requestNumberContext
)

func parseCurlyParams(handlerParams string) (map[string]string, string) {
	connectParams := make(map[string]string)
	if strings.HasPrefix(handlerParams, "{") {
		ebIndex := strings.Index(handlerParams, "}")
		if ebIndex < 0 {
			log.Fatal("Invalid parameter syntax, missing '}'")
		}
		for _, s := range strings.Split(handlerParams[1:ebIndex], ",") {
			kv := strings.SplitN(s, "=", 2)
			connectParams[kv[0]] = kv[1]
		}
		handlerParams = handlerParams[ebIndex+1:]
	}
	return connectParams, handlerParams
}

type serverConfig struct {
	logger   serverLogger
	certFile string
}

type protocoHandlerCreator func(urlPath, params string, cfg *serverConfig) (http.Handler, error)

var protocolHandlers = map[string]protocoHandlerCreator{}
var customHttpSchemas = make(map[string]func() http.RoundTripper)

func addProtocolHandler(proto string, createFunc protocoHandlerCreator) error {
	protocolHandlers[proto] = createFunc
	return nil
}
