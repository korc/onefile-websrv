package main

import (
	"net/http"
	"path/filepath"
	"strings"

	"golang.org/x/net/webdav"
)

// DownloadOnlyHandler is like static file handler, but adds Content-Disposition: attachment and optionally a fixed Content-Type
type DownloadOnlyHandler struct {
	ContentType string
	http.Handler
}

func (dh DownloadOnlyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET", "POST", "HEAD":
		wdHandler := dh.Handler.(*webdav.Handler)
		if fs, ok := wdHandler.FileSystem.(webdav.Dir); ok {
			name := strings.TrimPrefix(r.URL.Path, wdHandler.Prefix)
			if fi, err := fs.Stat(r.Context(), name); err == nil && fi.IsDir() {
				http.ServeFile(w, r, filepath.Join(string(fs), name))
				return
			}
		}
		w.Header().Set("Content-Disposition", "attachment")
		if dh.ContentType != "" {
			w.Header().Set("Content-Type", dh.ContentType)
		}
	}
	dh.Handler.ServeHTTP(w, r)
}
