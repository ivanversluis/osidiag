package diag

import (
 "context"
 "crypto/sha256"
 "crypto/tls"
 "encoding/hex"
 "fmt"
 "net"
 "strconv"
 "strings"
 "time"
)

// sentTLSName reports the ClientHello SNI value, not the certificate verification name.
// Go suppresses the SNI extension for literal IPv4 and IPv6 addresses.
func sentTLSName(serverName string) string {
 if net.ParseIP(serverName) != nil { return "" }
 return strings.TrimSuffix(serverName, ".")
}

// requestedSNIName only recognizes "none" as an explicit CLI override.
// A real internal hostname can legitimately be named "none".
func requestedSNIName(o Options) string {
 if o.SNI == "none" { return "" }
 if o.SNI != "" { return o.SNI }
 return o.Target
}

// sniProbe runs a TLS handshake against a pinned address. An inspection-only
// handshake deliberately does not claim that a certificate was verified.
func sniProbe(address, serverName string, timeout time.Duration, inspectOnly bool) (map[string]any, error) {
 d := &net.Dialer{Timeout: timeout}
 cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: inspectOnly} //nolint:gosec
 start := time.Now()
 conn, err := tls.DialWithDialer(d, "tcp", address, cfg)
 if err != nil {
  return nil, err
 }
 defer conn.Close()
 state := conn.ConnectionState()
 out := tlsStateData(state)
 out["address"] = address
 out["sni_sent"] = sentTLSName(serverName)
 out["handshake_ms"] = time.Since(start).Milliseconds()
 out["certificate_verified"] = !inspectOnly
 out["path"] = "direct TCP (does not traverse HTTP proxy)"
 if remote := conn.RemoteAddr(); remote != nil {
  out["peer_address"] = remote.String()
 }
 if len(state.PeerCertificates) > 0 {
  sum := sha256.Sum256(state.PeerCertificates[0].Raw)
  out["certificate_sha256"] = hex.EncodeToString(sum[:])
 }
 return out, nil
}

func inspectSNI(address, serverName string, timeout time.Duration) (map[string]any, error) {
 // Deliberately omit the SNI extension when serverName is empty. Go's TLS
 // client requires InsecureSkipVerify for a connection without ServerName.
 if serverName == "" {
  return sniProbe(address, "", timeout, true)
 }
 verified, err := sniProbe(address, serverName, timeout, false)
 if err == nil {
  return verified, nil
 }
 // Allow certificate inspection when validation fails, but keep original
 // verification failure as the outcome. A second network attempt may fail.
 inspected, inspectionErr := sniProbe(address, serverName, timeout, true)
 if inspected == nil {
  inspected = map[string]any{}
 }
 inspected["certificate_verified"] = false
 inspected["verification_error"] = err.Error()
 if inspectionErr != nil {
  inspected["inspection_error"] = inspectionErr.Error()
 }
 return inspected, err
}

func SNIPresentation(o Options) Result {
 name := requestedSNIName(o)
 addressHost := o.Target
 if o.ConnectIP != "" {
  addressHost = o.ConnectIP
 }
 address := net.JoinHostPort(addressHost, strconv.Itoa(o.Port))
 // For comparison, pin the first resolved address to avoid comparing two
 // different edge nodes by accident. Explicit --connect-ip overrides this.
 if o.CompareSNI && o.ConnectIP == "" {
  ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
  defer cancel()
  resolved, err := net.DefaultResolver.LookupIPAddr(ctx, addressHost)
  if err != nil || len(resolved) == 0 {
   if err == nil {
    err = fmt.Errorf("no addresses returned for %s", addressHost)
   }
   return result(6, "Presentation", Fail, "could not resolve SNI comparison endpoint", nil, err)
  }
  address = net.JoinHostPort(resolved[0].IP.String(), strconv.Itoa(o.Port))
 }
 named, namedErr := inspectSNI(address, name, o.Timeout)
 if named == nil {
  named = map[string]any{}
 }
 named["requested_sni"] = name
 if !o.CompareSNI {
  status := OK
  summary := "verified TLS with explicit SNI settings"
  if name == "" {
   status, summary = Warn, "TLS handshake without SNI (certificate unverified)"
  } else if namedErr != nil {
   status, summary = Fail, "TLS handshake or certificate verification failed"
  }
  return result(6, "Presentation", status, summary, named, namedErr)
 }
 if name == "" || net.ParseIP(name) != nil {
  return result(6, "Presentation", Fail, "SNI comparison requires a DNS hostname", named,
   fmt.Errorf("set a hostname target or --sni name"))
 }
 without, noSNIErr := inspectSNI(address, "", o.Timeout)
 data := map[string]any{"address": address, "with_sni": named,
  "without_sni": without, "requested_sni": name}
 if namedErr != nil {
  if noSNIErr != nil {
   data["without_sni_error"] = noSNIErr.Error()
  }
  return result(6, "Presentation", Fail, "named SNI TLS handshake or certificate verification failed", data, namedErr)
 }
 if noSNIErr != nil {
  data["without_sni_error"] = noSNIErr.Error()
  data["comparison"] = "handshake_failed_without_sni"
  return result(6, "Presentation", OK, "verified with SNI; handshake without SNI failed", data, nil)
 }
 first, _ := named["certificate_sha256"].(string)
 second, _ := without["certificate_sha256"].(string)
 if first == "" || second == "" {
  data["comparison"] = "inconclusive"
  return result(6, "Presentation", Warn, "TLS comparison inconclusive", data, nil)
 }
 if first == second {
  data["comparison"] = "same_certificate"
  return result(6, "Presentation", OK, "verified TLS; same certificate without SNI", data, nil)
 }
 data["comparison"] = "different_certificate"
 return result(6, "Presentation", OK, "verified TLS; SNI selects a different certificate", data, nil)
}
