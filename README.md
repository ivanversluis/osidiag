# osidiag

<img src="assets/logo.svg" width="136" alt="osidiag pixel-art Ethernet, terminal and OSI-layer multitool logo" />

The compact 7-layer pixel-art logo is generated reproducibly from `scripts/generate-logo.py` (standard library only). Run `python3 scripts/generate-logo.py` to regenerate `assets/logo.svg` and synchronize the SVG with Networknet.

**The Swiss Army knife for network troubleshooting.** One Go CLI that turns local interface state, routing, DNS, TCP connectivity, TLS, HTTP and Wi-Fi observations into an OSI-layer troubleshooting view.

Project home: [networknet.nl/projects/osidiag/](https://networknet.nl/projects/osidiag/) · [Releases](https://github.com/ivanversluis/osidiag/releases) · [Code signing policy](docs/CODE_SIGNING.md)

**Publication status:** public. [v0.4.1](https://github.com/ivanversluis/osidiag/releases/tag/v0.4.1) provides Linux AMD64/ARM64 and portable Windows AMD64 downloads. The Windows v0.4.1 ZIP is explicitly **unsigned**; SignPath Foundation approval and Authenticode signing are still pending. Checksums and provenance attestations do not establish trusted Windows publisher identity.

An OSI network diagnostics CLI for Linux and native Windows 11. Linux system checks use kernel interfaces; Windows uses native IP Helper APIs for adapter, route, ARP, DHCP lease, ICMPv4, TCP and UDP snapshots. Explicit IPv6 ping/traceroute and Wi-Fi radio details still invoke Windows system tools.

## OSI-layer checks

| Layer | Command | Checks |
| --- | --- | --- |
| L1 Physical | `osidiag l1` / `osidiag wifi` | Route-selected NIC, driver and negotiation, link errors/drops, flaps, and passive Wi-Fi details |
| L2 Data Link | `osidiag l2` | IPv4 ARP, cached gateway MAC and passive DHCP on Windows; IPv4/IPv6 neighbor cache on Linux |
| L3 Network | `osidiag l3 example.com` | Native ICMP ping and TTL-based traceroute |
| L4 Transport | `osidiag l4` | Direct TCP connection to target:port, plus local TCP listeners and UDP endpoints |
| L5 Session | `osidiag l5` | Local TCP states (ESTABLISHED/TIME_WAIT/CLOSE_WAIT); session-layer approximation only |
| L6 Presentation | `osidiag tls --target example.com` | TLS certificate, trust, cipher, expiry |
| L7 Application | `osidiag l7 example.com` | HTTP HEAD, expected redirects and DNS lookup |
| Speedtest | `osidiag speedtest --url https://example.com/` | Explicit portal HTTP reachability, or optional bounded HTTP download (alias `speed`) |

## Networknet terminal interface (v0.3)

The default `check` output is now a **bordered, wrapped table** with a
Networknet-inspired dark graphite, white, and amber palette when ANSI color
is available. The table exposes the **local L2 MAC**, **local IPv4/IPv6
interface CIDR**, and **default gateway** (plus gateway MAC if cached). IPv4
and IPv6 default routes are obtained from Linux kernel procfs. This reflects
the selected interface's default route, not a guaranteed next hop to a
particular target; policy routing and direct on-link traffic may differ.

```bash
./osidiag check example.com               # default: neat table
./osidiag check example.com --output text # legacy text view
./osidiag check example.com --output tui  # fullscreen manager view
./osidiag check example.com -v            # extra raw detail
```

The **`--output tui`** view uses an alternate terminal screen, with no
additional third-party Go dependencies. The terminal is restored on exit.
Keyboard shortcuts: `1`–`7` drill down by OSI layer, `0` returns to overview,
`j`/`k` scroll detail, `v` toggles detail mode, `r` reruns the scan,
`q` or Ctrl+C exits. Requires an interactive console on Linux, WSL2 or Windows Terminal/PowerShell; for logs or automation use `--output table` or `--output json`.
Colors honor `NO_COLOR` and `--no-color`.

## Compact diagnostic UX (v0.2)

By default, every command prints a short, human-readable diagnostic. `check` shows
the seven-layer traffic-light scorecard, key measurements, a final completion bar,
and a cautious troubleshooting suggestion. A live progress bar and ANSI stoplights
appear **only in an interactive terminal**. `NO_COLOR=1`, `--no-color` and
`--no-progress` suppress them as appropriate. Redirects (301/302) are **OK**
with their `Location` shown; intermediate traceroute timeouts are not treated
as proof of end-to-end packet loss.

```sh
./osidiag check example.com
./osidiag check example.com -v                  # full L1-L7 diagnostic data
./osidiag check example.com --output table       # aligned scorecard
./osidiag check example.com --output json > report.json
./osidiag check example.com --json > report.json  # backwards-compatible alias
./osidiag trace example.com --hops 20 --probes 3 # hop IPs, latency, missing replies
./osidiag trace --url https://example.com       # URL host is actually traced
./osidiag dns nu.nl --dns-type MX              # positional hostname and flags
./osidiag http --url https://example.com/      # inspect HTTP response
```

`--strict` turns an orange warning into exit status 1, useful for scripting.
The default nonzero status is reserved for failed checks, while JSON is stdout-only
and includes no progress or colors.

### Wi-Fi radio assessment

```sh
./osidiag wifi                     # inspect radio interfaces (no active scan)
./osidiag wifi --iface wlan0
./osidiag l1 --iface wlan0         # include Wi-Fi metrics in L1
```

Signal scores (dBm, advisory, not a speed measurement): **good** ≥ -67 dBm
(green), **fair** -76 to -68 dBm (orange), **poor** ≤ -77 dBm (legacy signal classification). The office survey independently flags RSSI below -75 dBm as severe RF degradation.
Reads Linux `/proc/net/wireless` and sysfs, with optional passive `iw` queries for association, band, channel, bitrate, station retries and power-save. No active scan occurs.
Some modern drivers do not expose RSSI through Wireless Extensions: the tool
returns **unknown** instead of fabricating a signal. WSL2 exposes a virtual
Ethernet interface and normally cannot read the Windows host's physical Wi-Fi
radio. Run on native Linux to inspect it.

### Crowded office Wi-Fi / Meraki diagnostics

Inspect the **real Windows host**, not the WSL2 virtual Ethernet adapter:

```powershell
.\osidiag.exe wifi --iface "Wi-Fi" --wifi-sample 15s --min-wifi-mbps 100 -v
.\osidiag.exe wifi --iface "Wi-Fi" --wifi-sample 15s --output json
.\osidiag.exe l2 --iface "Wi-Fi" --gateway-probe -v
```

Native Linux examples:

```sh
osidiag wifi --iface wlan0 --wifi-sample 15s -v
osidiag l2 --iface wlan0 --gateway-probe --lldp -v
```

**OS scan cache, no active scan:** Native Windows `WlanGetNetworkBssList` and Linux `iw dev IFACE scan dump` inspect **cached** BSSID entries. Radios are grouped by SSID and de-duplicated by BSSID; count is not the number of SSIDs. Windows may need **Settings → Privacy & security → Location** for BSS data. Empty/stale caches produce **unknown**, not an assertion of healthy channels. The tool does not trigger a Wi-Fi scan.

**Interpretation:** On the standalone `wifi` command, associated RSSI below -67 dBm warns and below -75 dBm fails the *RF-quality* check; low RSSI does not by itself prove a dead physical connection. `check`/L1 downgrades that RF-quality failure to a warning and continues upper layers if the carrier is operational. SNR warns under 25 dB **only when a real driver noise reading exists** (usually Linux). Windows quality percent is **not** converted into dBm.

The cache is used for sticky-client checks (weak association below -70 dBm and another same-SSID BSSID at least 10 dB stronger), 2.4 GHz preference when a usable same-SSID 5/6 GHz BSSID is visible, strong cochannel BSSID counts above three, and AP-advertised BSS Load utilization above 50%. An 80 MHz or wider channel gets a warning only when there is corresponding occupancy evidence. These are design heuristics: cached RSSI, BSS Load and another AP's PHY do not prove a client can roam there. Review Meraki RF profile minimum bitrate, 802.11k/v, band steering, AP power and channel width, with client capabilities in mind.

`--wifi-sample 15s` (10–30 seconds, disabled by default) polls association changes every ~2 seconds. Linux additionally samples station TX packets/retries/failures/beacon loss as **counter deltas** and computes retries **per TX packet**, not the percentage of distinct frames retried; rates above 0.15 warn. Neither OS currently recovers *past* deauthentication reason codes, and short transients can be missed between polls. Actual interface MAC is reported as `client_mac`; Windows/modern Wi-Fi may use a **randomized MAC**, which is the MAC to search in Meraki Dashboard.

**L2:** the selected gateway's passive ARP/NDP state is shown where supported. A Windows dynamic ARP entry or a Linux STALE entry is cache evidence, **not RTT**. `--gateway-probe` explicitly sends one ICMP echo (an L3 test reported beside L2 evidence); ICMP filtering can cause timeouts without proving the link is broken. `--lldp` optionally reads an existing Linux `lldpcli` daemon to show switch/port; Windows native LLDP neighbor collection is unavailable. No external Meraki API key, active scan, network configuration change or switch polling is required.

### L1 link-health diagnostics (issue #20)

```sh
osidiag l1 -v                               # route-selected adapter, link and driver
osidiag l1 --iface eth0 --min-link-mbps 1000 # warn if wired link negotiates too slowly
osidiag l1 --link-sample 5s --output json   # two error-counter samples (default)
osidiag l1 --link-sample 0s                 # immediate state, rates unknown
osidiag check example.com                   # skip dependent layers on confirmed L1 failure
```

The L1 result contains `data.checks[]` (`name`, `status`, `value`, `evidence`, `hint`) with `unknown` for missing OS/driver evidence. `data.error_rates_per_sec` uses deltas over the sample window; nonzero lifetime totals are not interpreted as new errors. No default minimum link speed is assumed. Virtual default-route adapters (WSL2, Hyper-V, VPN, containers) are not misidentified as physical Ethernet ports.

Linux uses passive sysfs and optional `iw`; Windows uses native `GetIfEntry2` with 64-bit counters and Native WLAN radio/security queries. The default 5-second counter window adds about five seconds to L1; disable with `--link-sample 0s`. Cable TDR, SFP optical levels, vendor-specific Windows CRC/FCS, and historical deauthentication reason codes remain unavailable without specialized hardware, APIs or notification subscriptions.

### Connection-speed checks

```sh
./osidiag speedtest --url https://example.com/
# Test an explicitly selected site's HTTPS reachability and response time.
# Does NOT claim to measure Mbps just by loading a speedtest web page.

# Measure a separate explicit binary endpoint, with an 8 MiB transfer cap:
./osidiag speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608'
# Compare to an expectation, but do not confuse a single-stream result with line capacity:
./osidiag speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608' --expected-mbps 500
```

### Live speed monitor

On an interactive terminal, providing `--download-url` now starts the
Networknet **live speed monitor**, which repeats individually bounded HTTP
download samples **until Ctrl+C or `q`**. The display updates the current
sample, per-sample progress, latest throughput, session average, peak, sample
count, and cumulative downloaded data. After stopping, a copyable final
summary is printed in the normal shell. Each sample remains capped by
`--max-bytes` (8 MiB default), but repeating samples **continues to consume
network data**, so stop when you have enough measurements.

```bash
./osidiag speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608'
# Keep monitoring on a non-interactive stream until interrupted:
./osidiag speedtest --watch --download-url 'https://speed.cloudflare.com/__down?bytes=8388608'
# Run three samples and stop, pausing one second between transfers:
./osidiag speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608' --samples 3 --pause 1s
# Older one-shot behavior, useful in scripts:
./osidiag speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608' --once
```

When redirected to a file or used with `--output json`, the default is a
**single sample** unless `--watch` or `--samples` explicitly requests
multiple downloads. JSON output is not supported in continuous mode;
use `--once --output json` instead.

No speed-test endpoint is selected by default. Supply a portal URL for reachability or a separate payload URL for bounded HTTP download sampling.
`--download-url` explicitly opts in to an ordinary HTTP download from
another endpoint, with `--max-bytes` limited to 256 KiB–128 MiB and a timeout.
Transfer volume depends on the remote service and the supplied cap.
No upload test is performed. A single HTTP stream can measure less than true
provisioned bandwidth, especially with caching, proxies, server limits or WSL2.

## WSL2 quick start

Download the `osidiag-linux-amd64` artifact from **Actions → CI → latest successful
run → Artifacts**. The artifact is a ZIP containing a tar.gz archive.

```bash
tar -xzf osidiag-linux-amd64.tar.gz
chmod +x osidiag
./osidiag --version
./osidiag check --target example.com --iface auto --timeout 2s
./osidiag dns example.com --dns-type AAAA
./osidiag http --url https://example.com/
./osidiag tls --target example.com --port 443
./osidiag check example.com --output json > report.json
```

For L3 native raw ICMP, grant the executable CAP_NET_RAW once:

```bash
sudo setcap cap_net_raw+ep ./osidiag
./osidiag ping --target 1.1.1.1
./osidiag trace --target 1.1.1.1 --hops 20 --probes 3
```

If your WSL2 environment restricts raw sockets, L3 reports a warning. Other
layers work without elevated privileges. L1 reports the virtual WSL2 NIC, not
the Windows host's physical NIC. TLS checks use direct TCP, whereas HTTP
uses standard environment proxy settings.

## Official downloads and verification

Official packages include the Apache-2.0 `LICENSE` and `NOTICE` files and will be published only on [GitHub Releases](https://github.com/ivanversluis/osidiag/releases) once the repository is public and an annotated release tag has been created. Until that first release is present, the repository has **no official public downloads**. CI artifacts are development previews and are not Authenticode-signed.

- Windows: `osidiag-windows-amd64-unsigned.zip` before SignPath approval, or `osidiag-windows-amd64-signed.zip` only after signature verification passes.
- Linux: `osidiag-linux-amd64.tar.gz` and `osidiag-linux-arm64.tar.gz`.
- Each release includes `SHA256SUMS`. GitHub provenance attestations identify the repository and workflow, not a Windows publisher certificate.

Verify the downloaded archive against the manifest. On Windows, extract `osidiag.exe` and run `Get-AuthenticodeSignature .\\osidiag.exe` in PowerShell: `Status: Valid` is expected **only** for an explicitly signed release. For provenance verification, use `gh attestation verify <archive> -R ivanversluis/osidiag`. See [the full verification and signing guide](docs/RELEASE_SIGNING.md).

## Build from source

Requires Go 1.22+.

```bash
git clone https://github.com/ivanversluis/osidiag.git
cd osidiag
go test ./...
make build
./bin/osidiag check --target example.com
```

## CI/CD

- **CI**: PR and main-branch testing (race detector), vet, staticcheck,
  dependency vulnerability audit (govulncheck), Go security scanning (gosec).
- **Build**: static `CGO_ENABLED=0` archives for linux/amd64 and linux/arm64,
  uploaded as workflow artifacts for every successful PR/main run.
- **Release**: an annotated `vMAJOR.MINOR.PATCH` tag on a reviewed `main` commit builds Linux AMD64/ARM64 and Windows AMD64. On a public repository, CI verifies the Windows file, produces SHA256SUMS and GitHub provenance attestations, and publishes a GitHub Release. Windows stays clearly **unsigned** until SignPath Foundation approves signing and the signing policy is enabled.
- **Windows signature**: signing is performed on the original CI-built EXE using SignPath's trusted GitHub artifact connector; on signed releases the Windows job checks Windows certificate trust, publisher, timestamp and version metadata before packaging. It must fail closed when signing is enabled but unavailable.

Generated workflow artifacts remain downloadable for 30 days. A tagged release
provides longer-lived downloads. Use the [single-archive verification procedure](docs/RELEASE_SIGNING.md) when downloading one release archive; `sha256sum -c SHA256SUMS` tries to verify **all** manifest entries.

## Limitations

- Native Windows 11 support is a preview; Windows IP Helper and WLAN APIs run without PowerShell for routine checks, and TUI requires an interactive console.
- ICMP traceroute requires CAP_NET_RAW; ICMP routers may rate limit replies.
- Wi-Fi RSSI is Linux-driver-dependent and not available for the Windows host through WSL2.
- Speedtest portal availability does not measure internet speed; true download sampling requires an explicit payload URL.
- Repeated speed samples consume data until interrupted; the tool does not test upload throughput or infer contractual line speed.
- L2 is a local neighbor-cache and passive DHCP inspection, not active LAN or DHCP discovery.
- L5 uses TCP socket states as an OSI session-layer approximation.
- DNS uses Go's resolver and does not expose TTL or raw authoritative flags.
- Requests should target networks and systems you are authorized to diagnose.

## License

Copyright 2026 Ivan Versluis. Licensed under the [Apache License 2.0](LICENSE). Contributions are accepted under the same license; the project name and logo do not grant trademark rights.

## Native Windows 11 (preview)

Version 0.4.0 builds on v0.3.1, which replaced repeated PowerShell launches with native Windows APIs. L1/L2/L4/L5 are local, read-only, and should complete substantially faster; L3 IPv4 uses native ICMP echo without the built-in `ping.exe` one-second probe intervals. The CLI does **not** require elevation for these passive inspections. Native Windows speed depends on the host; verify with the timings below.

```powershell
# Per-layer timings are emitted in JSON (milliseconds).
.\osidiag.exe check example.com --output json | ConvertFrom-Json |
  Select-Object -ExpandProperty results |
  Select-Object layer, name, status, duration_ms
Measure-Command { .\osidiag.exe check example.com --output json | Out-Null }
```


Download the Windows AMD64 artifact from CI, extract `osidiag.exe`, and run in PowerShell:

```powershell
.\osidiag.exe --version
.\osidiag.exe l1 --output json
.\osidiag.exe l2 --output json
.\osidiag.exe check example.com --output table
.\osidiag.exe wifi --output json
```

Use `--iface "Wi-Fi"`, `--iface "Ethernet"`, or `--iface 22` to select a Windows adapter (confirm names and indices with `Get-NetAdapter`). `auto` chooses the active IPv4 default route with the lowest route-table metric. A Hyper-V *external* vSwitch can legitimately own the Windows host's IP and default route: `vEthernet (vSwitch)` is then the correct logical egress, although its backing physical link is Ethernet. For testing a disconnected or non-default NIC, specify its alias explicitly. Destination-specific and VPN routing are outside this simple default-route model. Windows L2 reports the IPv4 ARP cache (not IPv6 NDP), the IPv4 default gateway from the routing table, and the cached gateway MAC if available; read-only DHCP configuration and lease details are included. **This does not send DHCPDISCOVER or confirm that a DHCP server is presently responding.** IP Helper APIs keep normal checks native; the same terminal TUI works on Windows 11 when launched from an interactive PowerShell or Windows Terminal session; use table or JSON when redirecting output.

The Windows executable is currently **unsigned**. Windows SmartScreen may warn, and Smart App Control may block it. Check the SHA256 checksum and (for public releases) GitHub build provenance before running. See [Code signing policy](docs/CODE_SIGNING.md) and [Release verification](docs/RELEASE_SIGNING.md). Trusted Authenticode signing is **not yet enabled**. Even after a trusted signature is approved, SmartScreen reputation can take time to develop.

### Open-source publication checklist

For a truly clean public history, review current source and use the [clean public baseline handoff](docs/PUBLIC_BASELINE.md) **after PR #19 is merged**. Squash-merging or force-pushing `main` does not erase old GitHub pull-request refs and caches. The original repository stays private under a different name; a **new** GitHub repository with one verified root commit takes the canonical URL. Old issues, PRs, tags and settings do not transfer.

## Diagnostics interpretation and Wi-Fi access points

Command categories are now **Assessments** (`check`, `wifi`, `speedtest`), **OSI layers** (`l1`–`l7`) and **Individual tests** (`ping`, `trace`, `tls`, `http`, `dns`). The old `speed` spelling still works.

- **Windows Wi-Fi** uses the native WLAN API to select an associated Wi-Fi adapter, not a disconnected Wi-Fi Direct virtual adapter. Connected SSID and BSSID identify the Wi-Fi network and serving AP radio. Windows exposes signal quality (%) and negotiated RX/TX radio rates; these are **not** measured throughput, and AP BSSID can change during roaming. This is especially useful for troubleshooting dense Cisco Meraki deployments.
- **Location privacy**: recent Windows 11 versions may deny WLAN SSID/BSSID queries unless Location access is permitted at **Settings > Privacy & security > Location**. osidiag reports a warning rather than fabricating a network or BSSID. No Wi-Fi scan is initiated.
- **L4 Transport**: TCP connection test to `target:port` is evidence of direct outbound reachability. Local TCP listener and UDP endpoint counts describe only your machine; they are context, not an end-to-end test. An enterprise HTTP proxy can make the HTTP test pass while direct TCP fails.
- **L5 Session**: `ESTABLISHED` counts active TCP connections; `TIME_WAIT` represents normal post-close cleanup; persistent high `CLOSE_WAIT` may warrant investigating an application failing to close connections. TCP states are **not** a genuine OSI Layer 5 protocol assertion.
- **HTTP headers**: use `osidiag http example.com -v` or JSON for all received response-header names and multi-values, except cookie and proxy-authentication values, which are redacted for safe sharing. These are the headers of the final HEAD response (or bounded GET fallback), not a dump of request headers.

### Recommended Dell Windows 11 validation

```powershell
.\osidiag.exe check example.com --output tui
.\osidiag.exe wifi -v
.\osidiag.exe l1 --iface Wi-Fi -v
.\osidiag.exe l4 example.com -v
.\osidiag.exe l5 -v
.\osidiag.exe http example.com -v
.\osidiag.exe speedtest --url https://example.com/
.\osidiag.exe speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608' --once
```

For a clean comparison, try with Ethernet connected, then Wi-Fi connected; `--iface` explicitly overrides the routing-table selection for local adapter checks. Use `--output json` to inspect `duration_ms` per OSI layer. TUI and continuous download monitoring need real terminal input; they do not work over redirected stdin/stdout.

## Passive DHCP lease and TLS SNI diagnostics

`osidiag dhcp --iface auto -v` reports read-only lease metadata when available.
It does **not** broadcast DHCPDISCOVER, renew a lease, or confirm that the server
is currently responding. Linux may not expose DHCP metadata and reports a warning.

Use a fixed edge/backend IP with the expected hostname and compare certificate
selection and TLS handshake results:

```bash
osidiag tls app.example.com --connect-ip 203.0.113.10 --compare-sni -v
osidiag tls app.example.com --connect-ip 203.0.113.10 --sni none -v
```

`--sni none` explicitly omits the SNI extension. IP verification names do not
appear in ClientHello SNI, even when used for IP SAN verification. Insecure
inspection-only retries never count as verified certificate connections.

`--sni` controls the ClientHello DNS name, while `--connect-ip` selects the
connection endpoint without changing the certificate-verification name.
`--compare-sni` pins a single IP and TCP port for both handshakes. The named
handshake must pass normal certificate verification to count as OK. A
no-SNI handshake is inspection-only and is WARN when tested by itself;
a certificate difference or failed no-SNI handshake does not prove that
all of a service's endpoints require SNI. Individual handshakes use `--timeout`.

Cloudflare edge TLS and Cloudflare-to-origin TLS are separate connections.
Testing a public Cloudflare IP cannot establish the origin certificate's
validity or the underlying cause of Cloudflare 525/526 errors. Direct L6 TLS
tests bypass `HTTPS_PROXY`, while the HTTP test may use the environment proxy.
