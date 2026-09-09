# Windscribe Iran Bypass

Automatic domestic routing bypass for Windscribe and full-tunnel VPNs on Windows.

Keeps international traffic encrypted inside Windscribe while routing all domestic Iranian websites, banking portals, and intranet services directly through your local physical network.

---

## The problem

When you connect to Windscribe (IKEv2, WireGuard, or OpenVPN), Windows directs all network traffic (`0.0.0.0/0`) into the VPN tunnel.

Iranian domestic services (banking gateways like Shaparak, government portals, Snapp, Digikala, Divar, Aparat, and Telewebion) block foreign IP addresses. As long as Windscribe is connected, those websites either fail to load or time out with connection errors.

Users usually end up disconnecting Windscribe just to pay a bill or book a ride, leaving the rest of their traffic exposed, and then reconnecting afterwards.

v2rayN solved this with its `geoip:ir` direct routing profile. This tool brings that exact functionality to Windscribe on Windows natively.

---

## How it works

Windows TCP/IP routing prioritizes specific network routes over general ones (longest-prefix match).

1. Windscribe holds the default catch-all route: `0.0.0.0/0`.
2. This tool injects routes for all 1,740 collapsed Iranian IPv4 CIDR blocks (sourced directly from RIPE NCC allocation data) pointing to your physical network gateway.
3. Because a `/22` or `/16` subnet route is more specific than `0.0.0.0/0`, Windows automatically sends Iranian domestic traffic out of your local physical adapter at full ISP speed.
4. All international traffic (Google, YouTube, X, GitHub, Claude, Discord) continues through the encrypted VPN tunnel.
5. An event-driven Windows Scheduled Task listens for network connection events (Event ID 10000). When Windscribe connects, disconnects, or your network changes, it verifies the routes in milliseconds in the background without opening any command prompt windows.

---

## Requirements

* Windows 10 or Windows 11
* Python 3.8+ (must be added to PATH)
* Windscribe desktop client (or any standard Windows VPN)

---

## Quick start

### 1. One-click install

1. Clone or download this repository.
2. Right-click `install.bat` and select **Run as administrator**.

The installer will:
* Detect your active physical network gateway (Ethernet or Wi-Fi).
* Inject all 1,740 Iranian CIDRs into your active routing table in a few seconds.
* Write them to Windows persistent registry (`HKLM\...\PersistentRoutes`) so they survive reboots.
* Register a silent background task (`WindscribeIranRouteSync`) that auto-syncs routes on network connect.
* Run an immediate connectivity test.

### 2. Verify it works

Run `status.bat` or run from terminal:

```bash
python iran_route.py status
```

Expected output:

```text
Iran Route Status:
  Physical Gateway:         192.168.0.1
  Live routes active:       YES
  Persistent registry keys: 1740 / 1740
  Event task installed:     YES

--- Testing Routing & Connectivity ---
  [Domestic Intranet] shaparak.ir:  Status 200 (175ms) -> DIRECT LOCAL ROUTE OK
  [International VPN] ipinfo.io:    IP 37.120.146.102 (Frankfurt am Main, DE) -> VPN TUNNEL ROUTE OK
```

Open your browser while Windscribe is running. You can now use `shaparak.ir` or your local banking app without disconnecting the VPN.

---

## CLI usage

From an elevated terminal:

```bash
# Check status and test routing
python iran_route.py status

# Re-apply routes manually
python iran_route.py enable

# Remove all routes
python iran_route.py disable

# Full uninstall (removes task, live routes, and registry keys)
python iran_route.py uninstall

# Refresh CIDR list from RIPE NCC
python iran_route.py update-cidrs
```

---

## Edge cases and common questions

#### What happens when I disconnect from Windscribe?
Nothing breaks. When Windscribe disconnects, its tunnel route disappears and all general traffic falls back to your local ISP gateway. Domestic routes already point there, so both continue working normally.

#### Does this conflict with v2rayN?
No. In v2rayN system proxy mode, domestic sites match `geoip:ir -> direct`, which tells Windows to open a direct socket. Windows then routes that socket through your physical gateway. Both tools want Iranian traffic to go direct, so there is no collision.

#### What if I change my router or Wi-Fi network?
The background event task detects network changes and updates the gateway IP automatically. If you ever switch to a new network and need an immediate update, run `python iran_route.py enable --force` or run `install.bat`.

#### How do I remove it completely?
Right-click `uninstall.bat` and select **Run as administrator**. It deletes the background task, removes all live routes, and cleans the registry keys.

---

## راهنمای فارسی (Persian guide)

هنگام اتصال به وینداسکرایب، تمام ترافیک ویندوز از تونل وی‌پی‌ان عبور می‌کند و به همین دلیل سایت‌های بانکی (شاپرک)، سامانه‌های دولتی، اسنپ، دیجی‌کالا، آپارات و تلوبیون باز نمی‌شوند یا خطای تایم‌اوت می‌دهند.

این ابزار تمامی رنج‌های آی‌پی ایران (۱۷۴۰ رنج معتبر برگرفته از دیتابیس رسمی رایپ) را مستقیما به گیت‌وی کارت شبکه فیزیکی شما هدایت می‌کند.

### نحوه نصب

۱. این مخزن را دانلود کنید.
۲. روی فایل `install.bat` راست‌کلیک کرده و گزینه **Run as administrator** را بزنید.
۳. تمام شد. بدون نیاز به قطع کردن وینداسکرایب، تمام سایت‌های داخلی با نهایت سرعت و آی‌پی ایران باز می‌شوند، در حالی که ترافیک خارجی (یوتیوب، تلگرام، گوگل و ...) از داخل تونل امن وینداسکرایب عبور می‌کند.

برای حذف کامل، کافیست فایل `uninstall.bat` را به صورت ادمین اجرا کنید.

---

## License

MIT License. Feel free to use, modify, and share.
