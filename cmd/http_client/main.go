package main

import (
	"io"
	"net/http"
	"os"
)

func main() {
	resp, err := http.Get(os.Args[1])
	if err != nil {
		panic(err)
	}
	io.Copy(os.Stdout, resp.Body)
}
