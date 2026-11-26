# Cross-platform diagnostic architecture

## CLI categories

| Category | Commands | Purpose |
| --- | --- | --- |
| Assessments | `check`, `wifi`, `speedtest` | Aggregate network health, associated AP radio, or speed-service readiness |
| OSI layers | `l1` ... `l7` | One diagnostic subsystem, including clearly identified approximations |
| Individual tests | `ping`, `trace`, `tls`, `http`, `dns` | Focus on an individual protocol |
| Compatibility | `speed` | Retained alias of `speedtest` |

`check` runs L1 through L7 sequentially, but short-circuits dependent L2-L7 checks after a confirmed physical failure. Skipped layers are explicit in JSON/table/TUI.
`Report.Results[].duration_ms` exposes per-layer time without logging personal network data.
The default interface is selected using the OS's active IPv4 default route (or IPv6 default route on IPv6-only Linux); the most-specific route to a particular destination (including VPN tunnels) may differ.

## Platform boundaries

- `internal/diag/types.go`, `application.go`, `speed.go`, `transport.go` are platform-neutral. Layer 4 now adds an actual direct TCP connection test to the selected target and port; local socket counts remain separately described.
- `internal/diag/linux.go`, `route_linux.go`, `icmp_linux.go`, `wifi_linux.go`, `link_linux.go` and `wifi_iw_linux.go` use procfs, sysfs, Linux netlink, native sockets and optional passive `iw` station queries.
- `internal/diag/platform_windows.go` and `link_windows.go` use Win32 IP Helper, including `GetIfEntry2` for 64-bit link counters, speed and media state, in addition to IPv4 ARP, DHCP leases, TCP states, UDP endpoints and native ICMPv4. It retains an explicit Windows trace command for hop-by-hop detail.
- `internal/diag/wlan_windows.go` uses wlanapi.dll to enumerate Wi-Fi interfaces and inspect the **associated** SSID, BSSID, link rate and Windows signal quality. Wi-Fi Direct virtual interfaces are not treated as an associated AP. No scan or association/renew operation is performed.
- `cmd/osidiag/tui.go` and `speed_monitor.go` are cross-platform terminal presentation. `tty_linux.go` implements Linux raw input; `tty_windows.go` uses Windows Console mode and enables VT output/input; both restore the original terminal state on exit.
- `cmd/osidiag/tty_other.go` and `internal/diag/platform_other.go` remain explicit unsupported-platform implementations.

## Office Wi-Fi and L2 gateway checks

- `wifi_office.go` holds platform-neutral normalized `LinkCheck` assessments for RSSI, optional SNR, PHY bitrate (only with user-provided minimum), sticky client, same-SSID band choices, cochannel BSS counts, BSS Load IE channel utilization, and observed roaming transitions. The OS BSS cache can be empty/stale; never equate BSSID counts or AP-advertised utilization with measured RF airtime.
- Linux `wifi_scan_linux.go` reads `iw dev <if> scan dump` (cached scan; **not** `iw scan trigger`) and samples `iw ... station dump` for retry/failed-TX/beacon deltas. Polling with `--wifi-sample 10s..30s` may miss short transitions; no deauth reason history is captured.
- Windows `wifi_bss_windows.go` reads `WlanGetNetworkBssList` with bounded native struct and information-element decoding, including current BSSID RSSI and optional BSS Load, without a `WlanScan` call. Native connection quality percentage is **not RSSI**. The BSS cache and SSID/BSSID access can require location permission. Polling does not replace `WlanRegisterNotification` history.
- `gateway_l2.go`, `l2_linux.go`, `l2_windows.go` separate ARP/NDP cache status from optional **L3** gateway RTT (`--gateway-probe`). Windows NDP remains unsupported; Linux IPv6 link-local gateway echo requires scoped probing and is reported unknown rather than failing. `--lldp` is an optional read-only query of a local Linux `lldpcli` daemon; Windows switch/port information remains unknown.
- RF-quality `fail` on standalone `wifi` is **downgraded to warn** in end-to-end `check` and physical L1 checks, preventing an associated weak client from incorrectly suppressing L3-L7. Only proven link/carrier failures short-circuit higher layers.
- Reports include current client interface MAC (may be randomized), not automatically a permanent hardware address or a Meraki Dashboard client identifier.

## What evidence each diagnostic provides

| Layer | Evidence and limitation |
| --- | --- |
| L1 | Route-selected interface, administrative/operational/carrier status, NIC kind, driver/duplex, 5-second error/drop rates, link-flap counts and passive Wi-Fi detail. Driver-dependent fields are explicitly `unknown`. |
| L2 | Cached gateway ARP/NDP state and MAC, optional opt-in L3 gateway RTT and Linux LLDP inventory. Windows ARP is IPv4-only; stale or missing cache is not proof of failure. Passive DHCP lease is not current server reachability. |
| L3 | IP address/route and ICMP response. ICMP filtering or loss may differ from application reachability. |
| L4 | Direct TCP handshake to `target:port`; local listener/UDP counts are system metadata. A proxy may allow HTTP even if direct TCP is blocked. |
| L5 | Counts of TCP states: ESTABLISHED, TIME_WAIT, CLOSE_WAIT. This is *not* an OSI session-protocol test and is not targeted at the configured destination. |
| L6 | TLS handshake and certificate verification, including expiry. |
| L7 | HTTP HEAD (bounded GET fallback) plus DNS resolution. `http -v` exposes received response headers, redacting cookie and proxy-authentication values. |

## HTTP speed-test sampling

Portal reachability alone is not a throughput measurement. No portal is contacted unless explicitly selected.

The opt-in `--download-url` transfers up to `--max-bytes` (default 8 MiB) using an *independent HTTP endpoint*. A single HTTP download measures only application throughput, not full-capacity multi-stream transfer or upload. Continuous mode uses real network data until stopped or the sample limit is reached.

## Windows privacy and safety

- On current Windows 11 releases, WLAN SSID/BSSID may require **Settings > Privacy & security > Location** to grant the process access. A denial is reported as a warning; no attempt is made to bypass privacy controls.
- Association details (SSID/BSSID), IP addresses and DHCP servers are environment-specific and can reveal network topology. Encourage users to inspect JSON before publishing results.
- An elevated shell is normally unnecessary for passive IP Helper, ARP, lease or WLAN reporting.
- No active DHCPDISCOVER, unsolicited port scan, ARP sweep, Wi-Fi scan or invasive enterprise network discovery is performed. Optional Linux `iw` queries are read-only.

## Validation

CI must run unit tests on Linux and native Windows runners, cross-build `windows/amd64`, and keep standalone CLI smoke tests. Before release, confirm interactively on real Windows hardware:

```powershell
Get-NetRoute -DestinationPrefix '0.0.0.0/0'
.\osidiag.exe wifi -v
.\osidiag.exe l1 -v
.\osidiag.exe l2 -v
.\osidiag.exe l4 example.com -v
.\osidiag.exe check example.com --output tui
.\osidiag.exe http example.com -v
.\osidiag.exe speedtest
```

Windows CI cannot verify a physical AP's SSID/BSSID or simulate interactive console input. Those tests require a physical Wi-Fi workstation such as the Dell, with a consenting user.

## Issue #20: L1 evidence and limitations

`LinkProbe` is implemented per OS; `LinkCheck` normalizes `name`, `status`, `value`, `evidence`, and `hint`. `unknown` does not imply success or failure. `--link-sample` is 0-10 seconds (default 5s); rates derive from two snapshots, skipping reset/wrapped counters. Linux exposes sysfs CRC/frame/collisions; Windows exposes IP Helper 64-bit errors/discards. No lifetime totals alone cause a warning.

`--min-link-mbps` sets an explicit wired minimum, avoiding speculative speed assumptions on virtual NICs. Linux `iw` (if installed) enriches passive Wi-Fi association, frequency, width, bitrate, TX retries, connection age and power-save; Windows WLAN API exposes associated radio, channel and security. This tool never initiates an active Wi-Fi scan. Detailed optical power/TDR, Windows driver-specific CRC, complete neighbor-AP cache and historical BSSID roaming remain intentionally unknown.
