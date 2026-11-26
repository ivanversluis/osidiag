package diag

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func defaultOptions() Options {
	return Options{Target: "localhost", Interface: "auto", Family: "auto", Port: 443, DNSType: "A",
		Count: 1, Hops: 2, Probes: 1, Timeout: time.Second, Limit: 10}
}
func TestOptionsValidate(t *testing.T) {
	o := defaultOptions()
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	o.Family = "7"
	if o.Validate() == nil {
		t.Fatal("invalid address family accepted")
	}
	o = defaultOptions()
	o.Port = 0
	if o.Validate() == nil {
		t.Fatal("invalid port accepted")
	}
}
func TestHTTPHeadFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusPartialContent)
	}))
	defer server.Close()
	o := defaultOptions()
	o.URL = server.URL
	got := HTTPOnly(o)
	if got.Status != OK || got.Data["status"] != http.StatusPartialContent || got.Data["method"] != "GET" {
		t.Fatalf("HEAD fallback: %+v", got)
	}
}
func TestTLSUntrustedIsFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	number, _ := strconv.Atoi(port)
	o := defaultOptions()
	o.Target = host
	o.Port = number
	got := Presentation(o)
	if got.Status != Fail || got.Data["certificate_verified"] != false || got.Data["subject"] == nil {
		t.Fatalf("self-signed cert should be inspection-only: %+v", got)
	}
}
func TestDNSLocalhost(t *testing.T) {
	o := defaultOptions()
	got := DNSOnly(o)
	if got.Status != OK || got.Data["total"].(int) < 1 {
		t.Fatalf("DNS: %+v", got)
	}
}

func TestHTTPResponseHeadersAreCompleteAndCookiesMasked(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Add("X-Osi-Test", "first")
        w.Header().Add("X-Osi-Test", "second")
        w.Header().Add("Set-Cookie", "session=private; HttpOnly")
        w.WriteHeader(http.StatusOK)
    }))
    defer server.Close()
    o := defaultOptions(); o.URL = server.URL
    r := HTTPOnly(o)
    if r.Status != OK {t.Fatalf("HTTP failure: %+v",r)}
    headers,ok := r.Data["response_headers"].(http.Header)
    if !ok {t.Fatalf("headers missing: %+v",r.Data)}
    if len(headers.Values("X-Osi-Test"))!=2 {t.Fatalf("duplicate values lost: %v",headers)}
    if headers.Get("Set-Cookie") != "[redacted]" {t.Fatalf("cookie leaked: %+v",headers)}
    if _,ok := r.Data["header_count"].(int);!ok {t.Fatal("header count missing")}
}
