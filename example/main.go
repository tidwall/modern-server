package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tidwall/modern-server"
)

func main() {
	server.Main(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/time" {
			fmt.Fprintf(w, "Hello world, it's %s\n", time.Now())
		} else {
			server.HandleFiles(w, r)
		}
	}, &server.Options{
		Version: "0.0.1",
		Name:    "example-server",
	})
}
