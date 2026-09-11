# Windscribe Iran Bypass (Native Rust Engine)

Ultra-fast, native domestic routing bypass and DNS split-tunnel engine for Windscribe and full-tunnel VPNs on Windows 10/11.

Keeps international traffic encrypted inside Windscribe while routing all domestic Iranian websites, banking gateways, and intranet services directly through your physical network adapter at full ISP speed with sub-millisecond route injection.

---

## The problem

When you connect to Windscribe (IKEv2, WireGuard, OpenVPN), Windows directs all network traffic (`0.0.0.0/0`) into the VPN tunnel.

Iranian domestic services (banking gateways like Shaparak, government portals, Snapp, Digikala, Divar, Aparat, and Telewebion) block foreign IP addresses. As long as Windscribe is connected, those websites either fail to load or time out with connection errors.

Additionally, Windscribe directs all DNS queries to foreign resolvers (e.g. Frankfurt, Germany). Because Iranian nameservers often throttle or block foreign DNS queries, domestic domains hang for 2–4 seconds before resolving.

This tool solves both issues simultaneously:
1. **Kernel Route Splitting**: Routes all 1,740 collapsed Iranian IPv4 subnets directly via your physical adapter.
2. **Native DNS Split-Tunneling**: Enforces Windows NRPT rules so `.ir` and domestic apps query fast local DNS servers directly while international lookups stay encrypted in the VPN.

---

## How it works

* **Longest-Prefix Match**: A specific CIDR subnet (like `185.167.72.0/22`) always takes precedence over the catch-all default route `0.0.0.0/0`.
* **Direct Win32 NetIO FFI**: Written in Rust, calling `CreateIpForwardEntry2` directly in the kernel routing table (`iphlpapi.dll`). Bypasses `route.exe` entirely and applies all 1,740 subnets in **7 milliseconds**.
* **Zero Flashing Windows**: Compiled with `#![windows_subsystem = "windows"]` and dual-mode console attachment. Task Scheduler runs it completely windowless.
* **Smart Adapter Arbitration**: Queries active kernel routes (`GetIpForwardTable2`), filters out virtual/VPN tunnels, and selects the physical adapter (Ethernet or Wi-Fi) with the lowest metric.
* **Automatic Route Migration**: If you switch from Ethernet to Wi-Fi or mobile hotspot, the engine purges previous routes and binds to the new physical gateway without collision.
* **Embedded Database**: All 1,740 RIPE NCC IPv4 CIDRs are compiled directly into the 400 KB standalone executable. Zero runtime dependencies.

---

## Quick start

### 1. One-click install

1. Clone or download this repository.
2. Right-click `install.bat` and select **Run as administrator**.

The installer will:
* Install `iran-route.exe` to `%USERPROFILE%\bin` (on PATH).
* Auto-detect your physical gateway and inject routes in 7ms.
* Activate the native Windows DNS split-tunnel policy.
* Register the silent background task (`\IranRouteSync`) triggered on network connect and logon.

### 2. Verify status

Run `status.bat` or run from any terminal:

```bash
iran-route status
```

Expected output:

```text
Iran Route Status (Native Rust Engine 1.1.0):
  Physical Adapter:         Ethernet (Ethernet, Index: 10)
  Physical Gateway:         192.168.0.1 (Local IP: 192.168.0.170)
  Live routes active:       YES (1740 subnets)
  DNS Split-Tunnel (NRPT):  ACTIVE (78.157.42.100;78.157.42.101)

--- Parallel Routing & DNS Latency Verification ---
  [OK] Domestic Bank/Payment Gateway   : Status 200 (362ms)
  [OK] Domestic E-Commerce (.com)      : Status 301 (245ms)
  [OK] Domestic Classifieds (.ir)      : Status 200 (392ms)
  [OK] International VPN Endpoint      : ip: 37.120.146.81 (city: Frankfurt am Main, country: DE) (621ms)
```

---

## CLI commands

```bash
# View dashboard, adapter details, route count, and parallel latency test
iran-route status

# Apply routes and DNS split-tunneling
iran-route enable

# Force route re-application
iran-route enable --force

# Run silently (used by Task Scheduler with named mutex guard)
iran-route enable --silent

# Remove all injected routes and DNS split-tunnel rules
iran-route disable

# Run fast parallel latency verification
iran-route test

# View recent background synchronization logs
iran-route log
```

---

## Building from source

Requires standard Rust toolchain:

```bash
cd rust
cargo build --release
```

The optimized binary is produced at `rust/target/release/iran-route.exe` (~400 KB).
