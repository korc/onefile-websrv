package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"
)

type contextKey int

const (
	authRoleContext contextKey = iota
	remoteLoggerContext
	requestNumberContext
)

type options map[string]string

func parseOptString(params string) options {
	ret := map[string]string{}
	for _, s := range strings.Split(params, ",") {
		if eqIdx := strings.Index(s, "="); eqIdx == -1 {
			if strings.HasPrefix(s, "no-") {
				ret[s[3:]] = "false"
			} else {
				ret[s] = "true"
			}

		} else {
			ret[s[:eqIdx]] = s[eqIdx+1:]
		}
	}
	return ret
}

func (opts options) IsTrue(option string, defaultValue bool) bool {
	if vStr, have := opts[option]; have {
		if v, err := strconv.ParseBool(vStr); err == nil {
			return v
		} else {
			logf(nil, logLevelWarning, "cannot parse boolean from %#v: %s", vStr, err)
		}
	}
	return defaultValue
}

func (opts options) IsSet(option string) bool {
	if _, have := opts[option]; have {
		return true
	}
	return false
}

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
