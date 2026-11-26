package diag

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDownloadSampleBounded(t *testing.T) {
	size := bytes.Repeat([]byte{0x72}, 2<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(size)
	}))
	defer server.Close()
	sample, err := downloadSample(server.URL, 1<<20, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Bytes != 1<<20 || sample.Mbps <= 0 || sample.Seconds <= 0 {
		t.Fatalf("sample: %+v", sample)
	}
}
func TestDownloadRejectsWebPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
	}))
	defer server.Close()
	if _, err := downloadSample(server.URL, 1<<20, 3*time.Second); err == nil {
		t.Fatal("HTML page incorrectly treated as bandwidth test")
	}
}
func TestSpeedSiteWithoutPayloadIsReachabilityOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	o := defaultOptions()
	o.URL = server.URL
	o.MaxBytes = 1 << 20
	r := SpeedOnly(o)
	if r.Status != OK || r.Data["download_mbps"] != nil || !strings.Contains(r.Summary, "not measured") {
		t.Fatalf("speed website must not be fake throughput: %+v", r)
	}
}
func TestHTTPRedirectIsOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer server.Close()
	o := defaultOptions()
	o.URL = server.URL
	r := HTTPOnly(o)
	if r.Status != OK || r.Data["status"] != 301 || r.Data["location"] != "https://example.com/" {
		t.Fatalf("unexpected redirect: %+v", r)
	}
}
