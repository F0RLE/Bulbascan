# Roadmap

---

## v0.1.3 — Transport Layer

### DNS-level block detection (~150 lines)
Before HTTP probing, compare ISP DNS response (`resolve_host()` in `network.rs` — uses system DNS) with DoH response (`resolve_host_via_path_dns()` — already uses Cloudflare/Google DoH). Detect NXDOMAIN injection, blockpage IP substitution, and DNS poisoning.

### SNI-based block detection (~120 lines)
`probe_tls_443()` already sends SNI. Extend: if TCP succeeds but TLS resets → probe with benign SNI (e.g. `cloudflare.com`). If that succeeds → confirmed SNI block.

### IPv6 dual-stack probing (~60 lines)
Extend `collect_network_evidence()` to probe AAAA records. Report when IPv4 is blocked but IPv6 works (common in partial rollouts).

---

## v0.1.4 — Output & Export Formats

### Direct `.srs` (sing-box Rule Set) Compilation (~200 lines)
In 2026, `.srs` is heavily preferred over `.dat` for performance on low-end routers. Implement direct binary serialization to `.srs` to bypass the need for users to run `sing-box rule-set compile`.

### GeoIP — output: `geoip.dat` generation (~150 lines)
Aggregate blocked IPs into CIDR subnets and compile into V2Ray `GeoIP` binary. Useful for IP-based routing rules.

### Clash / Mihomo / Shadowrocket exports (~100 lines)
Add mechanical exporters for YAML (Clash/Mihomo `.mrs`) and INI (Shadowrocket) formats using existing `RouterExportSpec`.

---

## v0.1.5 — State & Workflow

### Adaptive Worker Concurrency (~100 lines)
Automatically decrease worker count if the error rate (Unreachable/Timeout) spikes, and gradually increase it when stability returns. Prevents overwhelming the control proxy or triggering ISP rate limits.

### Concurrent Domain Ingestion (~80 lines)
Speed up startup by reading and normalizing multiple input files concurrently using `tokio::fs` and async tasks (rather than blocking the main thread). Essential for quickly loading massive datasets (100k+ domains).

### State expiry / TTL (~40 lines)
Add timestamps to `LocalState`. Expire old entries to catch domains that were unblocked or moved to new infrastructure.

### Periodic state flush (~30 lines)
Save state every N processed domains to prevent progress loss during long scans or crashes.

---

## v0.1.6 — Intelligence & Accuracy

### User-Loadable Service Profiles (~120 lines)
Move `service_profiles.rs` logic to an external `profiles.toml`. Allows users to define custom API check paths and critical roles for niche services without recompiling.

### Smart WAF/Captcha Promotion (~120 lines)
Currently, WAF (403) and Captcha verdicts often fall into `ManualReview`. **Upgrade:** If Local sees WAF/Captcha but Control Proxy sees 200 OK → promote to `ConfirmedProxyRequired`.

### Cross-Vantage Header Analysis (~80 lines)
Compare WAF-specific headers (like `CF-RAY`, `X-Akamai-Reference`, `Server`) between local and proxy to reinforce the Geo-block hypothesis.

### DPI Middlebox Locator (Application-Layer Traceroute) (~250 lines)
Find *where* the block occurs by incrementally increasing the IP TTL on a blocked TLS ClientHello.

### Next-Gen TLS Fingerprinting (JA4+ / `impersonate-rs`) (~150 lines)
Cloudflare's 2026 WAF heavily relies on JA4+ and HTTP/2 frame ordering. Replace or augment `wreq` with `impersonate-rs` to perfectly mimic modern browsers (Chrome 146+, Safari 18+) to bypass aggressive ML bot-detection layers.

### Automated Turnstile/reCAPTCHA Solver Integration (~200 lines)
For domains enforcing strict "AI Labyrinth" JS challenges, replace generic headless Chrome with `Nodriver` or `Camoufox` integrations, potentially hooking into a lightweight local solver or CapSolver API to read the underlying page.

### HTTP-Level IP Spoofing (~80 lines)
Inject fake resident IP headers (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`) into HTTP requests. Many poorly configured backend WAFs trust these headers to determine geographic origin, allowing the Control Proxy to bypass IP reputation limits.

---

## v0.1.7 — Performance & Quality

### O(N log N) Domain Minimization (~100 lines)
Replace the $O(N \times M)$ subdomain collapsing logic in `geosite::compile_categories`. Instead of a heavy Radix Trie, reverse domain strings (`com.example.www`), sort the array in $O(N \log N)$, and use a single linear pass to filter out redundant subdomains. This will make compiling large routing lists (100k+ domains) virtually instantaneous with zero allocations.

### Detailed Proxy Statistics
Track and report success/failure rates and average latency for each proxy in the rotation. Help identify "lazy" or dead proxies in the pool.

### Moving Average for Progress Speed (~30 lines)
Smooth out the domains/sec speed calculation in `progress.rs` by implementing a moving average over a 3-second history window, replacing the jumpy 2-second interval logic.

### Enhanced Scan Reports (~50 lines)
Add sections for "Confidence histogram" and "Non-technical per-service summary" in the human-readable text report output (`reports.rs`).

### Structured JSON logging (`--log-json`)
Emit newline-delimited JSON for piping into `jq` or external dashboards.

### Benchmark / regression test suite
Fixture-based harness using mocked HTTP responses to ensure detection logic doesn't regress.

---

## v0.1.8 — Advanced Architecture & Tooling

### Global Configuration File (`bulbascan.toml`)
Support reading default settings (proxy addresses, timeouts, concurrency limits, and export profiles) from a `bulbascan.toml` in the current directory or user config path to avoid passing long CLI flags every time.

### HTTP/3 (QUIC) / XHTTP Probing
DPI systems and CDNs behave differently on UDP. Extend transport probing to check HTTP/3 and newer protocols like Xray's `XHTTP` to test bypass viability without traditional TLS.

### Daemon / REST API Mode
Run Bulbascan as a long-running background service providing a local HTTP JSON API. Useful for integrating dynamic scans into network dashboards, router scripts, or custom web interfaces.

### Automated Geosite / GeoIP Fetching
Add a built-in command to fetch the latest lists directly into the cache to streamline the `--import-geosite` workflow.

