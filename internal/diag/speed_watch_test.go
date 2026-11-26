package diag

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSpeedWatchRepeatedBoundedDownloads(t *testing.T) {
	payload := bytes.Repeat([]byte{0x34}, 2<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/payload" {
			// On fast Windows loopback the entire sample can complete within a
			// single timer tick; allow elapsed time to be measurable in CI.
			time.Sleep(10 * time.Millisecond)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(payload)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	o := defaultOptions()
	o.DownloadURL = server.URL + "/payload"
	o.Timeout = 5 * time.Second
	o.MaxBytes = 256 << 10
	updates := []SpeedProgress{}
	result := WatchSpeed(context.Background(), o, 2, 10*time.Millisecond, func(p SpeedProgress) { updates = append(updates, p) })
	if result.Status != OK || result.Data["service_url"] != "" {
		t.Fatalf("result: %+v", result)
	}
	if result.Data["samples"] != 2 || result.Data["bytes_downloaded"] != int64(2*256<<10) {
		t.Fatalf("incorrect sample count or byte cap: %+v", result.Data)
	}
	if result.Data["average_mbps"].(float64) <= 0 || len(updates) < 3 {
		t.Fatalf("no measured throughput or progress: %+v / %+v", result, updates)
	}
	if !strings.Contains(result.Summary, "2 sample(s)") {
		t.Fatal(result.Summary)
	}
}

func TestSpeedWatchCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := defaultOptions()
	o.URL = "http://127.0.0.1:1"
	o.DownloadURL = "http://127.0.0.1:1/payload"
	o.Timeout = time.Second
	o.MaxBytes = 256 << 10
	result := WatchSpeed(ctx, o, 0, 0, nil)
	if result.Data["stopped_by_user"] != true || result.Data["samples"] != 0 {
		t.Fatalf("cancel not recorded: %+v", result)
	}
}

func TestWatchRejectsHTMLAsPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 1<<20))
	}))
	defer server.Close()
	_, err := downloadSampleLive(context.Background(), server.URL, 256<<10, time.Second, nil)
	if err == nil {
		t.Fatal("HTML was incorrectly counted as speed test payload")
	}
}
