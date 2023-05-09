package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
)

func TestWebDavPut(t *testing.T) {
	handlers := map[string]http.Handler{}
	tmpDirs := map[string]string{}
	f := map[string][]byte{"a": []byte("ThisIsFileA"), "b": []byte("ThisIsFileB"), "c": []byte("ThisIsFileC")}
	for n, opts := range map[string]string{"safe": "", "unsafe": "{unsafe=1}"} {
		var err error
		tmpDirs[n] = t.TempDir()
		handlers[n], err = NewDavHandler("/tmp/"+n+"/", opts+tmpDirs[n], nil)
		if err != nil {
			t.Fatalf("Cannot create DAV handler: %s", err)
		}
	}

	t.Run("put-safe", func(t *testing.T) {
		w := httptest.NewRecorder()
		handlers["safe"].ServeHTTP(w, httptest.NewRequest("PUT", "/tmp/safe/fileA.txt", bytes.NewReader(f["a"])))
		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("putting safe/fileA.txt not %d: %#v", http.StatusCreated, resp)
		}
		testA, err := os.ReadFile(tmpDirs["safe"] + "/fileA.txt")
		if err != nil {
			t.Fatalf("cannot read fileA: %s", err)
		}
		if !bytes.Equal(testA, f["a"]) {
			t.Fatalf("testA!=fileA: %#v != %#v", testA, f["a"])
		}
		if err := os.Symlink(tmpDirs["unsafe"], path.Join(tmpDirs["safe"], "unsafe")); err != nil {
			t.Errorf("Cannot create symlink to unsafe in safe: %s", err)
		} else {
			t.Run("symlink", func(t *testing.T) {
				w := httptest.NewRecorder()
				handlers["safe"].ServeHTTP(w, httptest.NewRequest("PUT", "/tmp/safe/unsafe/fileC.txt", bytes.NewReader(f["c"])))
				resp := w.Result()
				if resp.StatusCode != http.StatusNotFound {
					t.Errorf("Can put unsafe fileC: %#v", resp)
				}
			})
		}
	})
	t.Run("put-unsafe", func(t *testing.T) {
		w := httptest.NewRecorder()
		handlers["unsafe"].ServeHTTP(w, httptest.NewRequest("PUT", "/tmp/unsafe/fileB.txt", bytes.NewReader(f["b"])))
		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("putting unsafe/fileB.txt not %d: %#v", http.StatusCreated, resp)
		}
	})
}
