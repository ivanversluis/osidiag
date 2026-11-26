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

const defaultMaxBytes = 8 << 20

type speedSample struct {
	Mbps    float64
	Bytes   int64
	Seconds float64
}

func downloadSample(address string, maxBytes int64, timeout time.Duration) (speedSample, error) {
	var sample speedSample
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return sample, errors.New("--download-url must be a valid HTTP(S) URL without credentials")
	}
	if maxBytes < 256<<10 || maxBytes > 128<<20 {
		return sample, errors.New("download cap must be between 256 KiB and 128 MiB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return sample, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableCompression = true
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
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
		return sample, fmt.Errorf("download endpoint is too small (%d bytes) to benchmark throughput", resp.ContentLength)
	}
	n, copyErr := io.CopyN(io.Discard, resp.Body, maxBytes)
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		return sample, fmt.Errorf("download incomplete after %d bytes: %w", n, copyErr)
	}
	elapsed := time.Since(start).Seconds()
	if n < 256<<10 {
		return sample, fmt.Errorf("only %d bytes received: at least 256 KiB required", n)
	}
	if elapsed <= 0 {
		return sample, errors.New("invalid download timing")
	}
	return speedSample{Mbps: 8 * float64(n) / elapsed / 1e6, Bytes: n, Seconds: elapsed}, nil
}

func speedtestService(o Options) Result {
	if o.URL == "" {
		if o.DownloadURL == "" {
			return result(7, "Speedtest", Warn, "no speed-test endpoint selected", nil, nil)
		}
		return result(7, "Speedtest", OK, "service reachability skipped; explicit download only", map[string]any{"site_check": "skipped"}, nil)
	}
	return HTTPOnly(o)
}

// SpeedOnly checks an HTTP speed-test portal and optionally measures a bounded
// transfer. A portal response alone is never reported as a bandwidth result.
func SpeedOnly(o Options) Result {
	if o.Timeout < time.Second {
		o.Timeout = 10 * time.Second
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = defaultMaxBytes
	}
	service := speedtestService(o)
	data := map[string]any{
		"service_url": safeHTTPURL(o.URL),
		"site_status": service.Status,
		"note":        "Portal reachability is not a line-speed test. A single HTTP download estimates application throughput only; it does not measure upload speed or full ISP capacity.",
	}
	if code, ok := service.Data["status"]; ok {
		data["site_http_status"] = code
	}
	if ms, ok := service.Data["latency_ms"]; ok {
		data["site_latency_ms"] = ms
	}
	if service.Error != "" {
		data["service_error"] = service.Error
	}
	if service.Status == Fail {
		return result(7, "Speedtest", Fail, "speed-test service not reachable", data, errors.New(service.Error))
	}
	summary := "speed-test website reachable; throughput not measured (use --download-url)"
	if service.Status == Warn {
		summary = "Speedtest service not confirmed; download/upload not measured"
	}
	if o.DownloadURL == "" {
		return result(7, "Speedtest", service.Status, summary, data, nil)
	}
	data["download_url"] = safeHTTPURL(o.DownloadURL)
	sample, err := downloadSample(o.DownloadURL, o.MaxBytes, o.Timeout)
	if err != nil {
		return result(7, "Speedtest", Warn, "download throughput test unavailable", data, err)
	}
	data["download_mbps"] = sample.Mbps
	data["bytes_downloaded"] = sample.Bytes
	data["download_seconds"] = sample.Seconds
	status := service.Status
	if o.ExpectedMbps > 0 {
		data["expected_mbps"] = o.ExpectedMbps
		data["reference_ratio"] = sample.Mbps / o.ExpectedMbps
		if sample.Mbps < 0.8*o.ExpectedMbps {
			status = Warn
		}
	}
	return result(7, "Speedtest", status, fmt.Sprintf("sampled %.1f Mbps (independent single HTTP stream; upload not measured)", sample.Mbps), data, nil)
}
