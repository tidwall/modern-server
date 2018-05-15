package server

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const pathSeperator = "/"

const (
	cert    = "cert.pem"
	key     = "key.pem"
	certDir = ".autocert"
)

// httpServer holds the relavent info/state
type httpServer struct {
	Port    int
	TLSPort int
	HTTPS   bool
	log     *log.Logger
	waiter  sync.WaitGroup
	handler func(w http.ResponseWriter, r *http.Request)
}

type writerExtra struct {
	base http.ResponseWriter
	log  *log.Logger
}

func (w *writerExtra) Header() http.Header         { return w.base.Header() }
func (w *writerExtra) WriteHeader(code int)        { w.base.WriteHeader(code) }
func (w *writerExtra) Write(p []byte) (int, error) { return w.base.Write(p) }
func (w *writerExtra) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.base.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("base response does not implement http.Hijacker")
	}
	return hj.Hijack()
}

// ServeHTTP handles inbound requests
func (h *httpServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.waiter.Wait()
	if h.HTTPS && req.TLS == nil {
		url := "https://" + strings.Split(req.Host, ":")[0]
		if h.TLSPort != 443 {
			url = url + ":" + strconv.FormatInt(int64(h.TLSPort), 10)
		}
		url += req.URL.String()
		http.Redirect(w, req, url, 302)
		return
	}
	h.handler(&writerExtra{w, h.log}, req)
}

type keepAliveListener struct {
	*net.TCPListener
}

func (k keepAliveListener) Accept() (net.Conn, error) {
	tc, err := k.AcceptTCP()
	if err != nil {
		return nil, err
	}

	if err := tc.SetKeepAlive(true); err != nil {
		return nil, err
	}
	if err := tc.SetKeepAlivePeriod(time.Minute * 3); err != nil {
		return nil, err
	}

	return tc, nil
}

func getpwd() string {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return pwd
}

func homeDir() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return u.HomeDir
}

const usage = `{{NAME}} version: {{VERSION}}

Usage: {{NAME}} [-p port] [-l domain]

Options:
  -h           : this help
  -v           : show version and exit
  -g           : enable TLS/HTTPS generate and use a self signed certificate
  -p port      : bind HTTP port (default: 8000)
  -l domain    : enable TLS/HTTPS with Let's Encrypt for the given domain name.
  -c path      : enable TLS/HTTPS use a predefined HTTPS certificate
  -t port      : bind HTTPS port (default: 443, 4433 for -g)
{{USAGE}}
Examples: {{NAME}}               start {{NAME}}. http://localhost:8000
  or: {{NAME}} -p 80             use HTTP port 80. http://localhost
  or: {{NAME}} -g                enable HTTPS generated certificate. https://localhost:4433
  or: {{NAME}} -l example.com    enable HTTPS with Let's Encrypt. https://example.com
`

// Options are server options
type Options struct {
	// Name gives the server binary a name.
	Name string
	// Version is the version of the server.
	Version string
	// Init is an optional function that fires after the server is listening
	// but before allowing incoming requests.
	Init func()
	// Flags is an optional function that allows for adding command line flags.
	Flags func()
	// FlagsParsed is an optional function that fires immediately after flags are parsed.
	FlagsParsed func()
	// Usage is an optional function that allows for altering the usage text.
	Usage func(usage string) string
	// Logger is a custom logger
	Logger *log.Logger
}

// Main starts the server environment.
func Main(handler func(w http.ResponseWriter, r *http.Request), opts *Options) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Name == "" {
		opts.Name = "server"
	}
	if opts.Version == "" {
		opts.Version = "0.0.0"
	}
	l := opts.Logger
	if l == nil {
		l = log.New(os.Stderr, "", log.LstdFlags)
	}
	var port int
	var le string
	var gs bool
	var tlsPort int
	var tlsCert string
	var vers bool

	flag.Usage = func() {
		w := os.Stderr
		for _, arg := range os.Args {
			if arg == "-h" {
				w = os.Stdout
				break
			}
		}
		s := usage
		s = strings.Replace(s, "{{VERSION}}", opts.Version, -1)
		s = strings.Replace(s, "{{NAME}}", opts.Name, -1)
		if opts.Usage != nil {
			s = opts.Usage(s)
		}
		s = strings.Replace(s, "{{USAGE}}", "", -1)
		w.Write([]byte(s))
	}

	flag.BoolVar(&vers, "v", false, "")
	flag.IntVar(&port, "p", 8000, "")
	flag.StringVar(&le, "l", "", "")
	flag.StringVar(&tlsCert, "c", "", "")
	flag.BoolVar(&gs, "g", false, "")
	flag.IntVar(&tlsPort, "t", -1, "")
	if opts.Flags != nil {
		opts.Flags()
	}
	flag.Parse()
	if opts.FlagsParsed != nil {
		opts.FlagsParsed()
	}

	if vers {
		fmt.Fprintf(os.Stdout, "%s version: %s\n", opts.Name, opts.Version)
		return
	}
	if tlsPort == -1 {
		if gs {
			tlsPort = 4433
		} else {
			tlsPort = 443
		}
	}
	if le != "" {
		// flags that are not allowed with Let's Encrypt
		badFlags := []string{"p", "c", "g", "t"}
		var bad bool
		for _, f := range badFlags {
			var found bool
			flag.Visit(func(ff *flag.Flag) {
				if ff.Name == f {
					found = true
				}
			})
			if found {
				bad = true
				fmt.Fprintf(os.Stderr, "flags -l and -%s cannot be used together\n", f)
			}
		}
		if bad {
			os.Exit(1)
		}
		tlsPort = 443
		port = 80
	}

	h := &httpServer{
		Port:    port,
		TLSPort: tlsPort,
		log:     l,
		handler: handler,
		HTTPS:   le != "" || tlsCert != "" || gs,
	}

	pinit := func() {
		h.waiter.Add(1)
		defer h.waiter.Done()
		if opts.Init != nil {
			opts.Init()
		}
	}

	if le != "" {
		// Let's Encrypt!
		cacheDir := filepath.Join(homeDir(), certDir)
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			l.Fatalf("could not create cache directory: %s" + err.Error())
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(le),
		}
		go http.ListenAndServe(":http", m.HTTPHandler(h))
		go func() {
			time.Sleep(time.Millisecond * 100)
			l.Printf("Serving with Let's Encrypt!...\n")
			pinit()
		}()
		s := &http.Server{
			Addr:      ":https",
			TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
			Handler:   h,
		}
		l.Fatal(s.ListenAndServeTLS("", ""))
		return
	}

	if h.HTTPS {
		var certPath, keyPath string
		switch {
		case tlsCert != "":
			if gs {
				l.Fatal("cannot specify both -tls-cert and -g")
			}
			certPath, keyPath = tlsCert, tlsCert // assume a single PEM format
		case gs:
			hd := homeDir()
			certPath = filepath.Join(hd, certDir, cert)
			keyPath = filepath.Join(hd, certDir, key)
			if err := generateCertificates(certPath, keyPath); err != nil {
				l.Fatalln(err)
			}
		}
		go l.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", tlsPort), certPath, keyPath, h))
		go func() {
			time.Sleep(time.Millisecond * 100)
			l.Printf("Serving HTTP on port %v, HTTPS on port %v...\n", h.Port, tlsPort)
			pinit()
		}()
	} else {
		go func() {
			time.Sleep(time.Millisecond * 100)
			l.Printf("Serving HTTP on port %v ...\n", h.Port)
			pinit()
		}()
	}
	l.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), h))
}

// most of the certificate stuff shamelessly lifted from the
// example found here https://golang.org/src/crypto/tls/generate_cert.go

// namesAndAddresses generates a slice of hostnames and addresses
// to generate certificates for
func namesAndAddresses() ([]string, error) {
	var r []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				r = append(r, v.IP.String())
			}
		}
	}

	h, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	r = append(r, h)

	return r, nil
}

var (
	ecdsaCurve = ""
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// generateCertificates will generate a certificate and key and save them to
// the given paths
func generateCertificates(certPath, keyPath string) error {
	var priv interface{}
	var err error
	switch ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return fmt.Errorf("unrecognized elliptic curve: %q", ecdsaCurve)
	}
	if err != nil {
		return err
	}

	start := time.Now()
	expire := start.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             start,
		NotAfter:              expire,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts, err := namesAndAddresses()
	if err != nil {
		return err
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		return err
	}
	return keyOut.Close()
}

// HandleFiles is handler for ... wait for it ... handling files.
// It just handles static files from your current directory.
func HandleFiles(w http.ResponseWriter, r *http.Request) {
	var l *log.Logger
	if w, ok := w.(*writerExtra); ok {
		l = w.log
	}
	code := 200
	path := r.URL.Path[1:]
	if l != nil {
		defer func() {
			l.Printf("%s %d /%s", r.RemoteAddr, code, path)
		}()
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
again:
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			code = 404
			http.NotFound(w, r)
		} else {
			code = 500
			http.Error(w, err.Error(), 500)
		}
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		code = 500
		http.Error(w, err.Error(), 500)
		return
	}
	if fi.IsDir() {
		f.Close()
		path = filepath.Join(path, "index.html")
		goto again
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%d-%s", fi.Size(), fi.ModTime())))
	etag := hex.EncodeToString(sum[:])
	petag := r.Header.Get("If-None-Match")
	if petag != "" && etag == petag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(path)))
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("Last-Modified", fi.ModTime().Format(time.RFC1123))
	w.Header().Set("ETag", etag)
	w.WriteHeader(200)
	if r.Method != "HEAD" {
		io.Copy(w, f)
	}
}
