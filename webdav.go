package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

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

type wdFSType string

func (wd wdFSType) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return webdav.Dir(wd).Mkdir(ctx, name, perm)
}

func (wd wdFSType) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	testPath := string(wd)
	for _, n := range strings.Split(name, "/") {
		fullPath, err := filepath.EvalSymlinks(path.Join(testPath, n))
		if err != nil {
			if err1, ok := err.(*fs.PathError); ok && err1.Err == syscall.ENOENT && flag&os.O_CREATE == os.O_CREATE {
				parent, err2 := filepath.EvalSymlinks(testPath)
				if err2 != nil {
					log.Printf("Could not evaluate parent full path for: %#q: %s", testPath, err)
					return nil, err
				}
				fullPath = path.Join(parent, n)
			} else {
				log.Printf("Could not evaluate full path for: %#q + %q: %s", testPath, n, err)
				return nil, err
			}
		}

		target, err := filepath.Rel(testPath, fullPath)
		if err != nil {
			log.Printf("Error finding relative path of %#q+%#q: %s", testPath, fullPath, err)
			return nil, err
		}

		if strings.HasPrefix(target, "../") {
			log.Printf("ERROR: use {unsafe=1} to allow accessing symlinks outside WebDAV root %#q + %#q -> %#q", testPath, n, target)
			return nil, filepath.ErrBadPattern
		}
	}
	return webdav.Dir(wd).OpenFile(ctx, name, flag, perm)
}

func (wd wdFSType) RemoveAll(ctx context.Context, name string) error {
	return webdav.Dir(wd).RemoveAll(ctx, name)
}

func (wd wdFSType) Rename(ctx context.Context, oldName, newName string) error {
	return webdav.Dir(wd).Rename(ctx, oldName, newName)
}

func (wd wdFSType) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return webdav.Dir(wd).Stat(ctx, name)
}

func NewDavHandler(urlPath, p string, cfg *serverConfig) (http.Handler, error) {
	if !strings.HasSuffix(urlPath, "/") {
		urlPath += "/"
	}
	var wdFS webdav.FileSystem
	opts, params := parseCurlyParams(p)
	if params == "" {
		wdFS = webdav.NewMemFS()
	} else if opts["unsafe"] != "" {
		wdFS = webdav.Dir(params)
	} else {
		wdFS = wdFSType(params)
	}
	wdHandler := webdav.Handler{
		FileSystem: wdFS,
		LockSystem: webdav.NewMemLS(),
		Prefix:     urlPath[strings.Index(urlPath, "/"):],
	}
	return DownloadOnlyHandler{ContentType: opts["ctype"], Handler: &wdHandler}, nil
}

func init() {
	addProtocolHandler("webdav", NewDavHandler)
}
