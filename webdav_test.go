package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
)

func TestWebDavPut(t *testing.T) {
	handlers := map[string]http.Handler{}
	tmpDirs := map[string]string{}
	f := map[string][]byte{"a": []byte("ThisIsFileA"), "b": []byte("ThisIsFileB"), "c": []byte("ThisIsFileC"), "d": []byte("ThisIsFileD")}
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
		if err := os.Symlink(tmpDirs["safe"], path.Join(tmpDirs["unsafe"], "safe")); err != nil {
			t.Errorf("Cannot create symlink to safe in unsafe: %s", err)
		} else {
			t.Run("symlink", func(t *testing.T) {
				w := httptest.NewRecorder()
				handlers["unsafe"].ServeHTTP(w, httptest.NewRequest("PUT", "/tmp/unsafe/safe/fileC.txt", bytes.NewReader(f["c"])))
				resp := w.Result()
				if resp.StatusCode != http.StatusCreated {
					t.Errorf("Cannot put unsafe fileC: %#v", resp)
				}
			})
		}
	})

	t.Run("mkcol", func(t *testing.T) {
		w := httptest.NewRecorder()
		handlers["safe"].ServeHTTP(w, httptest.NewRequest("MKCOL", "/tmp/safe/dirA", nil))
		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Cannot make collection dirA under safe: %#v", resp)
		} else {
			t.Run("put-in-col", func(t *testing.T) {
				w := httptest.NewRecorder()
				handlers["safe"].ServeHTTP(w, httptest.NewRequest("PUT", "/tmp/safe/dirA/fileD", bytes.NewReader(f["d"])))
				resp := w.Result()
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("Cannot put fileD under collection dirA: %#v", resp)
				}
				testD, err := os.ReadFile(path.Join(tmpDirs["safe"], "dirA", "fileD"))
				if err != nil {
					t.Fatalf("Cannot read fileD: %s", err)
				}
				if !bytes.Equal(testD, f["d"]) {
					t.Fatalf("testD != fileD (%#v != %#v)", string(testD), string(f["d"]))
				}
				t.Run("get-col-file", func(t *testing.T) {
					w := httptest.NewRecorder()
					handlers["safe"].ServeHTTP(w, httptest.NewRequest("GET", "/tmp/safe/dirA/fileD", nil))
					resp := w.Result()
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("Could not retrieve file: %#v", resp)
					}
					testD1, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatalf("Could not read fileD: %#v", err)
					}
					if !bytes.Equal(testD1, f["d"]) {
						t.Fatalf("testD1!=fileD: %#v != %#v", string(testD1), string(f["d"]))
					}
				})
			})
		}
	})
}
