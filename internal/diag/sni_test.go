package diag

import (
 "crypto/tls"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "math/big"
 "net"
 "net/http"
 "net/http/httptest"
 "strconv"
 "testing"
 "time"
)

func TestSNIComparisonAgainstLocalTLS(t *testing.T) {
 server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.WriteHeader(http.StatusOK)
 }))
 defer server.Close()
 host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
 if err != nil { t.Fatal(err) }
 port, err := strconv.Atoi(portText)
 if err != nil { t.Fatal(err) }
 o := Options{Target:"localhost", Port:port, Timeout:2*time.Second, ConnectIP:host, SNI:"localhost", CompareSNI:true}
 got := SNIPresentation(o)
 // httptest's default certificate is self-signed. An unsuccessful verification
 // must be reported as a failure even when certificate inspection succeeds.
 if got.Status != Fail { t.Fatalf("expected verification failure: %+v", got) }
 data, ok := got.Data["with_sni"].(map[string]any)
 if !ok || data["certificate_verified"] != false || data["certificate_sha256"] == nil {
  t.Fatalf("expected unverified certificate inspection: %+v", got.Data)
 }
}

func TestSNIWithoutNameNeverClaimsVerified(t *testing.T) {
 server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
 defer server.Close()
 host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
 if err != nil { t.Fatal(err) }
 port, _ := strconv.Atoi(portText)
 o := Options{Target:host, Port:port, Timeout:2*time.Second, SNI:"none"}
 got := SNIPresentation(o)
 if got.Status != Warn || got.Data["certificate_verified"] != false || got.Data["sni_sent"] != "" {
  t.Fatalf("no-SNI should be unverified warning: %+v", got)
 }
}

func TestSNIProbeSelectsDifferentCertificate(t *testing.T) {
 primary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
 defer primary.Close()
 secondary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
 defer secondary.Close()
 // These servers each have independent self-signed certificates.
 key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
 if err != nil { t.Fatal(err) }
 template := &x509.Certificate{SerialNumber:big.NewInt(42), NotBefore:time.Now().Add(-time.Hour), NotAfter:time.Now().Add(time.Hour), DNSNames:[]string{"custom.test"}, KeyUsage:x509.KeyUsageDigitalSignature, ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
 der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
 if err != nil { t.Fatal(err) }
 primaryCert := tls.Certificate{Certificate:[][]byte{der}, PrivateKey:key}
 secondaryCert := secondary.TLS.Certificates[0]
 listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
  MinVersion: tls.VersionTLS12,
  GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
   if hello.ServerName == "custom.test" { return &primaryCert, nil }
   return &secondaryCert, nil
  },
 })
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 go func() {
  for {
   c, err := listener.Accept()
   if err != nil { return }
   go func(conn net.Conn) {
    defer conn.Close()
    tc := conn.(*tls.Conn)
    if tc.Handshake() == nil { _, _ = tc.Write([]byte("ok")) }
   }(c)
  }
 }()
 named, err := sniProbe(listener.Addr().String(), "custom.test", 2*time.Second, true)
 if err != nil { t.Fatal(err) }
 noSNI, err := sniProbe(listener.Addr().String(), "", 2*time.Second, true)
 if err != nil { t.Fatal(err) }
 if named["certificate_sha256"] == noSNI["certificate_sha256"] {
  t.Fatalf("SNI did not select a different certificate")
 }
 if named["sni_sent"] != "custom.test" || noSNI["sni_sent"] != "" {
  t.Fatalf("wrong requested SNI: %+v / %+v", named, noSNI)
 }
}

func TestOnlyExplicitNoSNIFlagSuppressesHost(t *testing.T) {
	// A legitimate internal hostname may be exactly "none".
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"internal host named none", Options{Target:"none", ConnectIP:"127.0.0.1"}, "none"},
		{"explicit no SNI", Options{Target:"none", SNI:"none", ConnectIP:"127.0.0.1"}, ""},
	} {
		name := requestedSNIName(tc.opts)
		if name != tc.want { t.Errorf("%s: name = %q, want %q", tc.name, name, tc.want) }
	}
}

func TestSentTLSNameExcludesIPAddresses(t *testing.T) {
	for _, tc := range []struct { name, want string }{
		{"example.com", "example.com"},
        {"example.com.", "example.com"},
		{"none", "none"},
		{"192.0.2.1", ""},
		{"2001:db8::1", ""},
		{"", ""},
	} {
		if got := sentTLSName(tc.name); got != tc.want {
			t.Errorf("sentTLSName(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
