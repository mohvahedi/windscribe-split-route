# Windscribe Split-Route (Native Rust Engine)

Ultra-fast, native direct CIDR routing and DNS split-tunnel engine for Windscribe and full-tunnel VPNs on Windows 10/11.

Keeps international traffic encrypted inside Windscribe while routing domestic subnets, regional payment infrastructure, and local intranet services directly through your physical network adapter at full line speed with sub-millisecond route injection.

---

## The problem

When connecting to Windscribe (IKEv2, WireGuard, or OpenVPN), Windows directs all network traffic (`0.0.0.0/0`) into the VPN tunnel.

Regional services (local banking gateways, payment switches, municipal portals, domestic delivery services, and streaming CDNs) frequently enforce geographic IP whitelisting or block non-local IP ranges. While the VPN is connected, those services either fail to load or drop connection attempts.

Additionally, full-tunnel VPNs route all DNS lookups to remote international resolvers. Because local authoritative nameservers often throttle or block overseas recursive queries, domestic domain lookups can stall for 2–4 seconds before resolving.

This tool resolves both issues simultaneously:
1. **Kernel Route Splitting**: Routes 1,740 specific regional IPv4 subnets directly via your physical network adapter.
2. **Direct DNS Split-Tunneling**: Enforces Windows NRPT rules so regional domains resolve via fast local resolvers while international lookups stay encrypted in the VPN.

---

## How it works

* **Longest-Prefix Match**: Specific subnet routes (such as `/24` or `/16`) take precedence over the default catch-all route `0.0.0.0/0` in the Windows TCP/IP stack.
* **Direct Win32 NetIO FFI**: Written in Rust, calling `CreateIpForwardEntry2` directly in the kernel routing table (`iphlpapi.dll`). Bypasses `route.exe` entirely and applies all 1,740 subnets in **7 milliseconds**.
* **Zero Flashing Windows**: Compiled with `#![windows_subsystem = "windows"]` and dual-mode console attachment. Task Scheduler runs it completely windowless.
* **Smart Adapter Arbitration**: Queries active kernel routes (`GetIpForwardTable2`), filters out virtual/VPN tunnels, and selects the physical adapter (Ethernet or Wi-Fi) with the lowest metric.
* **Automatic Route Migration**: If you switch from Ethernet to Wi-Fi or mobile hotspot, the engine purges previous routes and binds to the new physical gateway without collision.
* **Embedded Database**: All 1,740 allocated IPv4 CIDRs are compiled directly into the 400 KB standalone executable. Zero runtime dependencies.

---

## Quick start

### 1. One-click install

1. Clone or download this repository.
2. Right-click `install.bat` and select **Run as administrator**.

The installer will:
* Install `split-route.exe` to `%USERPROFILE%\bin` (on PATH).
* Auto-detect your physical gateway and inject routes in 7ms.
* Activate the native Windows DNS split-tunnel policy.
* Register the silent background task (`\SplitRouteSync`) triggered on network connect and logon.

### 2. Verify status

Run `status.bat` or run from any terminal:

```bash
split-route status
```

Expected output:

```text
Split Route Status (Native Rust Engine 1.1.0):
  Physical Adapter:         Ethernet (Ethernet, Index: 10)
  Physical Gateway:         192.168.0.1 (Local IP: 192.168.0.170)
  Live routes active:       YES (1740 subnets)
  DNS Split-Tunnel (NRPT):  ACTIVE (78.157.42.100;78.157.42.101)

--- Parallel Routing & DNS Latency Verification ---
  [OK] Regional Payment Gateway         : Status 200 (360ms)
  [OK] Regional E-Commerce (.com)       : Status 301 (184ms)
  [OK] Regional Classifieds (.ir)       : Status 200 (372ms)
  [OK] International VPN Endpoint       : ip: 37.120.146.81 (city: Frankfurt am Main, country: DE) (629ms)
```

---

## CLI commands

```bash
# View dashboard, adapter details, route count, and parallel latency test
split-route status

# Apply routes and DNS split-tunneling
split-route enable

# Force route re-application
split-route enable --force

# Run silently (used by Task Scheduler with named mutex guard)
split-route enable --silent

# Remove all injected routes and DNS split-tunnel rules
split-route disable

# Run fast parallel latency verification
split-route test

# View recent background synchronization logs
split-route log
```

---

## Building from source

Requires standard Rust toolchain:

```bash
cd rust
cargo build --release
```

The optimized binary is produced at `rust/target/release/split-route.exe` (~400 KB).
