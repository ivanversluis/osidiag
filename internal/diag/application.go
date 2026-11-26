package diag

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func tlsStateData(state tls.ConnectionState) map[string]any {
	out := map[string]any{"tls_version": tls.VersionName(state.Version), "cipher_suite": tls.CipherSuiteName(state.CipherSuite),
		"server_name": state.ServerName, "negotiated_protocol": state.NegotiatedProtocol, "certificates": len(state.PeerCertificates)}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		out["subject"] = cert.Subject.String()
		out["issuer"] = cert.Issuer.String()
		out["dns_names"] = cert.DNSNames
		out["not_before"] = cert.NotBefore.UTC().Format(time.RFC3339)
		out["not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
		out["days_until_expiry"] = int(time.Until(cert.NotAfter).Hours() / 24)
	}
	return out
}
func tlsHandshake(o Options, inspectOnly bool) (map[string]any, error) {
	addr := net.JoinHostPort(o.Target, strconv.Itoa(o.Port))
	d := &net.Dialer{Timeout: o.Timeout}
	// The inspection-only retry is never reported as verified.
	cfg := &tls.Config{ServerName: o.Target, MinVersion: tls.VersionTLS12, InsecureSkipVerify: inspectOnly} //nolint:gosec
	start := time.Now()
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	out := tlsStateData(c.ConnectionState())
	out["address"] = addr
	out["handshake_ms"] = time.Since(start).Milliseconds()
	out["certificate_verified"] = !inspectOnly
	out["path"] = "direct TCP (does not traverse HTTP proxy)"
	return out, nil
}
func Presentation(o Options) Result {
	if o.SNI != "" || o.ConnectIP != "" || o.CompareSNI {
		return SNIPresentation(o)
	}
	data, err := tlsHandshake(o, false)
	if err == nil {
		return result(6, "Presentation", OK, fmt.Sprintf("verified TLS to %s:%d", o.Target, o.Port), data, nil)
	}
	inspected, inspectionErr := tlsHandshake(o, true)
	if inspected == nil {
		inspected = map[string]any{}
	}
	inspected["certificate_verified"] = false
	if inspectionErr != nil {
		inspected["inspection_error"] = inspectionErr.Error()
	}
	return result(6, "Presentation", Fail, "TLS handshake or verification failed", inspected, err)
}
func safeHTTPURL(address string) string {
	if address == "" {
		return ""
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return "[invalid URL]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}
// publicResponseHeaders preserves every response-header name and multiple
// values while masking cookie and proxy-authentication secrets in reports.
func publicResponseHeaders(headers http.Header) http.Header {
    safe := headers.Clone()
    for _, name := range []string{"Set-Cookie", "Proxy-Authenticate"} {
        if values, ok := safe[http.CanonicalHeaderKey(name)]; ok {
            masked := make([]string,len(values))
            for i := range masked { masked[i] = "[redacted]" }
            safe[http.CanonicalHeaderKey(name)] = masked
        }
    }
    return safe
}

func HTTPOnly(o Options) Result {
	address := o.URL
	if address == "" {
		address = "https://" + net.JoinHostPort(o.Target, strconv.Itoa(o.Port)) + "/"
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return result(7, "Application", Fail, "invalid HTTP URL", nil, errors.New("--url must be absolute http:// or https:// URL"))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	client := &http.Client{Timeout: o.Timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, address, nil)
	if err != nil {
		return result(7, "Application", Fail, "invalid HTTP request", nil, err)
	}
	proxyURL, proxyErr := transport.Proxy(req)
	start := time.Now()
	resp, err := client.Do(req)
	method := http.MethodHead
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		_ = resp.Body.Close()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err == nil {
			req.Header.Set("Range", "bytes=0-0")
			resp, err = client.Do(req)
			method = http.MethodGet
		}
	}
	if err != nil {
		return result(7, "Application", Fail, "HTTP request failed", map[string]any{"url": safeHTTPURL(address), "method": method}, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	proxy := "none"
	if proxyErr == nil && proxyURL != nil {
		proxy = proxyURL.Scheme + "://" + proxyURL.Host
	}
	data := map[string]any{"url": safeHTTPURL(address), "method": method, "status": resp.StatusCode,
		"http_proto": resp.Proto, "latency_ms": time.Since(start).Milliseconds(), "proxy": proxy,
		"server": resp.Header.Get("Server"), "location": safeHTTPURL(resp.Header.Get("Location")),
        "response_headers": publicResponseHeaders(resp.Header), "header_count": len(resp.Header),
        "headers_note": "All received response headers are included; Set-Cookie and Proxy-Authenticate values are redacted for safe sharing."}
	status := OK
	if resp.StatusCode >= 500 {
		status = Fail
	} else if resp.StatusCode >= 400 || resp.StatusCode < 200 {
		status = Warn
	}
	// 3xx redirects are valid HTTP responses. The Location is reported but
	// not followed, so an expected redirect never becomes an orange failure.
	return result(7, "Application", status, fmt.Sprintf("HTTP %d via %s", resp.StatusCode, method), data, nil)
}
func dnsResolver(o Options) *net.Resolver {
	if o.DNSServer == "" {
		return net.DefaultResolver
	}
	addr := o.DNSServer
	if net.ParseIP(addr) != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	dialer := net.Dialer{Timeout: o.Timeout}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}}
}
func DNSOnly(o Options) Result {
	resolver := dnsResolver(o)
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	kind := strings.ToUpper(o.DNSType)
	name := o.Target
	records := []string{}
	start := time.Now()
	var err error
	switch kind {
	case "A", "AAAA":
		family := "ip4"
		if kind == "AAAA" {
			family = "ip6"
		}
		var ips []net.IP
		ips, err = resolver.LookupIP(ctx, family, name)
		for _, ip := range ips {
			records = append(records, ip.String())
		}
	case "MX":
		var mx []*net.MX
		mx, err = resolver.LookupMX(ctx, name)
		for _, v := range mx {
			records = append(records, fmt.Sprintf("%d %s", v.Pref, v.Host))
		}
	case "NS":
		var ns []*net.NS
		ns, err = resolver.LookupNS(ctx, name)
		for _, v := range ns {
			records = append(records, v.Host)
		}
	case "TXT":
		records, err = resolver.LookupTXT(ctx, name)
	case "CNAME":
		var v string
		v, err = resolver.LookupCNAME(ctx, name)
		if err == nil {
			records = append(records, v)
		}
	case "PTR":
		if net.ParseIP(name) == nil {
			err = errors.New("PTR requires IP address in --target")
		} else {
			records, err = resolver.LookupAddr(ctx, name)
		}
	case "SRV":
		var srv []*net.SRV
		_, srv, err = resolver.LookupSRV(ctx, "", "", name)
		for _, v := range srv {
			records = append(records, fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target))
		}
	}
	if err != nil {
		return result(7, "Application", Fail, fmt.Sprintf("DNS %s lookup failed", kind),
			map[string]any{"name": name, "dns_type": kind, "server": o.DNSServer}, err)
	}
	count := len(records)
	if count > o.Limit {
		records = records[:o.Limit]
	}
	server := o.DNSServer
	if server == "" {
		server = "system resolver"
	}
	return result(7, "Application", OK, fmt.Sprintf("DNS %s: %d answer(s)", kind, count),
		map[string]any{"name": name, "dns_type": kind, "server": server, "records": records, "total": count,
			"elapsed_ms": time.Since(start).Milliseconds(), "note": "Go resolver does not expose DNS TTL or raw authoritative flags."}, nil)
}
func Application(o Options) Result {
	h, d := HTTPOnly(o), DNSOnly(o)
	status := OK
	if h.Status != OK || d.Status != OK {
		status = Warn
	}
	if h.Status == Fail && d.Status == Fail {
		status = Fail
	}
	return result(7, "Application", status, fmt.Sprintf("HTTP %s; DNS %s", h.Status, d.Status),
		map[string]any{"http": h, "dns": d}, nil)
}
