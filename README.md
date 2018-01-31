# `modern-server`
[![GoDoc](https://img.shields.io/badge/api-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/tidwall/modern-server)

Just a basic http server with some auto config junk that makes spinning up a web server super easy... for me at least. Because like 99% of the time all I want is **A)** HTTPS with Let's Encrypt **B)** some custom API handling **C)** access to static files.

Based on the codez from the [simple-httpd](https://github.com/briandowns/simple-httpd) project by [@briandowns](https://github.com/briandowns). If you like this project then be a good sport and buy Brian a beer.

## Installing
To start using modern-server, install Go and run go get:

```
$ go get -u github.com/tidwall/modern-server
```

This will retrieve the library.

## Usage

```go
func main() {
	server.Main(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello world, it's %s\n", time.Now())
	}, nil)
}
```

## Static File Handler

If you want to serve static files:

```go
func main() {
	server.Main(func(w http.ResponseWriter, r *http.Request) {
        if strings.HasPrefix(r.URL.Path, "/api/"){
            // do some custom magic
            w.Write([]byte("API command result"))
        } else {
            // otherwise fallback to handling files
            server.HandleFiles(w, r)
        }
	}, nil)
}
```

## Example

Run the built-in example:

```
$ go run example/main.go
```

Then visit [http://localhost:8000](http://localhost:8000).

See all the command line options:

```
$ go run example/main.go --help
```
