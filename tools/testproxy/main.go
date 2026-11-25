// testproxy runs a small proxy server (or an echo server) for trying out
// OddlyProxifier by hand:
//
//	testproxy -type socks5 -listen 127.0.0.1:1091
//	testproxy -type http   -listen 127.0.0.1:1092 -user u -pass p
//	testproxy -type echo   -listen 127.0.0.1:7
//
// It is a test tool: no access control beyond the optional user/password.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"

	"oddlyproxifier/internal/proxytest"
)

func main() {
	typ := flag.String("type", "socks5", "socks5 | socks4 | socks4a | http | https | echo")
	listen := flag.String("listen", "127.0.0.1:1091", "address to listen on")
	user := flag.String("user", "", "require this user name")
	pass := flag.String("pass", "", "require this password")
	banner := flag.String("banner", "", "echo: greeting sent to every client")
	quiet := flag.Bool("quiet", false, "do not log requests")
	flag.Parse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	if *typ == "echo" {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("echo server listening on %s", ln.Addr())
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if !*quiet {
						log.Printf("echo: client %s", c.RemoteAddr())
					}
					if *banner != "" {
						_, _ = fmt.Fprintf(c, "%s\r\n", *banner)
					}
					_, _ = io.Copy(c, c)
				}()
			}
		}()
		<-stop
		_ = ln.Close()
		return
	}

	o := proxytest.Options{Type: *typ, Listen: *listen, User: *user, Pass: *pass}
	if !*quiet {
		o.Logf = log.Printf
	}
	s, err := proxytest.Start(o)
	if err != nil {
		log.Fatal(err)
	}
	auth := "no authentication"
	if *user != "" {
		auth = "user " + *user
	}
	log.Printf("%s proxy listening on %s (%s)", *typ, s.Addr(), auth)
	<-stop
	s.Close()
}
