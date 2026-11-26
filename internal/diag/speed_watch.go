package diag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SpeedProgress is a snapshot from the active bounded HTTP download session.
// The only throughput measurement is application-layer single-stream download.
type SpeedProgress struct {
	State          string  `json:"state"`
	CurrentBytes   int64   `json:"current_bytes"`
	SampleLimit    int64   `json:"sample_limit"`
	CurrentMbps    float64 `json:"current_mbps"`
	LastMbps       float64 `json:"last_mbps"`
	AverageMbps    float64 `json:"average_mbps"`
	PeakMbps       float64 `json:"peak_mbps"`
	Completed      int     `json:"completed_samples"`
	TotalBytes     int64   `json:"total_bytes"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	Error          string  `json:"error,omitempty"`
}

// downloadSampleLive always caps bytes read. The context stops an in-flight
// request promptly on Ctrl+C. The callback is best effort and optional.
func downloadSampleLive(ctx context.Context, address string, maxBytes int64, timeout time.Duration, update func(int64, time.Duration)) (speedSample, error) {
	var sample speedSample
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return sample, errors.New("--download-url must be a valid HTTP(S) URL without credentials")
	}
	if maxBytes < 256<<10 || maxBytes > 128<<20 {
		return sample, errors.New("download cap must be between 256 KiB and 128 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return sample, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return sample, fmt.Errorf("download endpoint returned HTTP %d (expected 200 or 206)", resp.StatusCode)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		return sample, fmt.Errorf("download endpoint returned %s instead of a test payload", contentType)
	}
	if resp.ContentLength >= 0 && resp.ContentLength < 256<<10 {
		return sample, fmt.Errorf("download endpoint too small (%d bytes)", resp.ContentLength)
	}
	var count int64
	buf := make([]byte, 32<<10)
	lastUpdate := start
	for count < maxBytes {
		request := len(buf)
		if int64(request) > maxBytes-count {
			request = int(maxBytes - count)
		}
		n, readErr := resp.Body.Read(buf[:request])
		count += int64(n)
		now := time.Now()
		if update != nil && (now.Sub(lastUpdate) >= 120*time.Millisecond || count == maxBytes || readErr != nil) {
			update(count, now.Sub(start))
			lastUpdate = now
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return sample, fmt.Errorf("download interrupted after %d bytes: %w", count, readErr)
		}
		if n == 0 && ctx.Err() != nil {
			return sample, ctx.Err()
		}
	}
	elapsed := time.Since(start).Seconds()
	if count < 256<<10 {
		return sample, fmt.Errorf("only %d bytes received: at least 256 KiB required", count)
	}
	if elapsed <= 0 {
		return sample, errors.New("invalid download timing")
	}
	sample = speedSample{Mbps: 8 * float64(count) / elapsed / 1e6, Bytes: count, Seconds: elapsed}
	if update != nil {
		update(count, time.Since(start))
	}
	return sample, nil
}

// WatchSpeed repeats bounded downloads until the context is cancelled or
// maxSamples is reached (0 means unlimited). It does not perform upload tests.
func WatchSpeed(ctx context.Context, o Options, maxSamples int, pause time.Duration, update func(SpeedProgress)) Result {
	if o.MaxBytes == 0 {
		o.MaxBytes = defaultMaxBytes
	}
	if o.Timeout < time.Second {
		o.Timeout = 10 * time.Second
	}
	if o.DownloadURL == "" {
		return result(7, "Speedtest", Fail, "download URL required for a continuous test", nil, errors.New("provide --download-url"))
	}

	started := time.Now()
	p := SpeedProgress{State: "checking speedtest service", SampleLimit: o.MaxBytes}
	notify := func() {
		if update != nil {
			update(p)
		}
	}
	notify()
	portal := speedtestService(o)
	data := map[string]any{
		"service_url":   safeHTTPURL(o.URL),
		"download_url":  safeHTTPURL(o.DownloadURL),
		"site_status":   portal.Status,
		"service_probe": portal.Summary,
		"note":          "Repeating capped HTTP downloads uses bandwidth until stopped. This is single-stream application throughput, not an ISP speed certification or an upload test.",
	}
	if portal.Data != nil {
		if status, exists := portal.Data["status"]; exists {
			data["site_http_status"] = status
		}
		if ms, exists := portal.Data["latency_ms"]; exists {
			data["site_latency_ms"] = ms
		}
	}
	var sumSeconds float64
	var failure error
	failures := 0
	for ctx.Err() == nil && (maxSamples == 0 || p.Completed < maxSamples) {
		p.State = "downloading"
		p.CurrentBytes = 0
		p.ElapsedSeconds = time.Since(started).Seconds()
		notify()
		sample, err := downloadSampleLive(ctx, o.DownloadURL, o.MaxBytes, o.Timeout, func(bytes int64, elapsed time.Duration) {
			p.CurrentBytes = bytes
			secs := elapsed.Seconds()
			if secs > 0 {
				p.CurrentMbps = 8 * float64(bytes) / secs / 1e6
			}
			p.ElapsedSeconds = time.Since(started).Seconds()
			notify()
		})
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			p.Error = err.Error()
			p.State = "download error; retrying"
			failure = err
			failures++
			notify()
			// Do not spin indefinitely on a broken URL or a failed server.
			if failures >= 3 {
				break
			}
		} else {
			failure = nil
			failures = 0
			p.Error = ""
			p.Completed++
			p.TotalBytes += sample.Bytes
			sumSeconds += sample.Seconds
			p.CurrentMbps = sample.Mbps
			p.LastMbps = sample.Mbps
			if sample.Mbps > p.PeakMbps {
				p.PeakMbps = sample.Mbps
			}
			if sumSeconds > 0 {
				p.AverageMbps = 8 * float64(p.TotalBytes) / sumSeconds / 1e6
			}
			p.State = "sample complete"
			notify()
		}
		if maxSamples != 0 && p.Completed >= maxSamples {
			break
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	p.State = "stopped"
	p.ElapsedSeconds = time.Since(started).Seconds()
	notify()
	data["samples"] = p.Completed
	data["bytes_downloaded"] = p.TotalBytes
	data["average_mbps"] = p.AverageMbps
	data["peak_mbps"] = p.PeakMbps
	data["last_mbps"] = p.LastMbps
	data["elapsed_seconds"] = p.ElapsedSeconds
	data["stopped_by_user"] = ctx.Err() != nil
	status := OK
	if p.Completed == 0 {
		status = Warn
	}
	if o.ExpectedMbps > 0 {
		data["expected_mbps"] = o.ExpectedMbps
		if p.Completed > 0 && p.AverageMbps < .8*o.ExpectedMbps {
			status = Warn
		}
	}
	if portal.Status == Fail {
		status = Warn
	}
	if p.Completed > 0 && status == OK {
		return result(7, "Speedtest", status, fmt.Sprintf("%d sample(s), %.1f Mbps avg / %.1f Mbps peak", p.Completed, p.AverageMbps, p.PeakMbps), data, nil)
	}
	if failure == nil && p.Completed == 0 && ctx.Err() != nil {
		return result(7, "Speedtest", Warn, "stopped before a complete sample", data, nil)
	}
	return result(7, "Speedtest", status, fmt.Sprintf("%d sample(s), %.1f Mbps avg", p.Completed, p.AverageMbps), data, failure)
}
