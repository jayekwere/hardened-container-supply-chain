// netprobe is a test-only client executed in a pod network namespace from its node.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type result struct {
	ExpectedIP string `json:"expectedIP"`
	Reachable  bool   `json:"reachable"`
	Outcome    string `json:"outcome"`
	Detail     string `json:"detail,omitempty"`
}

func main() {
	r, code := run(os.Args[1:])
	_ = json.NewEncoder(os.Stdout).Encode(r)
	os.Exit(code)
}

func run(args []string) (result, int) {
	r := result{Outcome: "error"}
	if len(args) != 3 {
		r.Detail = "expected: POD_IP http|dns TARGET"
		return r, 20
	}
	r.ExpectedIP = args[0]
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		r.Detail = err.Error()
		return r, 20
	}
	found := false
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip != nil && ip.String() == args[0] {
			found = true
		}
	}
	if !found {
		r.Detail = "expected pod IP absent: wrong network namespace"
		return r, 20
	}
	switch args[1] {
	case "http":
		err = probeHTTP(args[2], args[0])
	case "dns":
		err = probeDNS(args[2], args[0])
	default:
		err = fmt.Errorf("unknown probe mode")
	}
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			r.Outcome = "timeout"
			r.Detail = err.Error()
			return r, 10
		}
		r.Detail = err.Error()
		return r, 20
	}
	r.Outcome = "reachable"
	r.Reachable = true
	return r, 0
}

func probeHTTP(target, source string) error {
	dialer := &net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect rejected") }}
	response, err := client.Get(target)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 || string(body) != "ok\n" {
		return fmt.Errorf("unexpected HTTP status/body: %d %q", response.StatusCode, body)
	}
	return nil
}

func probeDNS(target, source string) error {
	dialer := &net.Dialer{Timeout: time.Second, LocalAddr: &net.UDPAddr{IP: net.ParseIP(source)}}
	c, err := dialer.Dial("udp4", net.JoinHostPort(target, "53"))
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	query := make([]byte, 12)
	if _, err := rand.Read(query[:2]); err != nil {
		return err
	}
	query[2], query[5] = 1, 1
	for _, label := range strings.Split("kubernetes.default.svc.cluster.local", ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	if _, err := c.Write(query); err != nil {
		return err
	}
	reply := make([]byte, 512)
	n, err := c.Read(reply)
	if err != nil {
		return err
	}
	if n < 12 || string(reply[:2]) != string(query[:2]) || reply[2]&0x80 == 0 || reply[3]&0x0f != 0 || binary.BigEndian.Uint16(reply[6:8]) == 0 {
		return fmt.Errorf("invalid or unsuccessful DNS response")
	}
	return nil
}
