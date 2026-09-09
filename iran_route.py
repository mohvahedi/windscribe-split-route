#!/usr/bin/env python3
"""
Windscribe Iran Bypass (Iran Direct Route Manager)
Routes all Iranian domestic intranet/banking/services traffic directly through
the physical network interface while keeping international traffic inside the VPN tunnel.
"""

import os
import sys
import time
import socket
import struct
import winreg
import argparse
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CIDR_FILE = os.path.join(SCRIPT_DIR, "iran_cidrs.txt")
VBS_FILE = os.path.join(SCRIPT_DIR, "iran_route_silent.vbs")
TASK_NAME = "WindscribeIranRouteSync"
REG_PATH = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"
SAMPLE_NET = "2.57.3.0"

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_physical_gateway():
    """Detects active physical default gateway and interface index."""
    res = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True)
    gateway = None
    iface_ip = None
    
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0":
            gw = parts[2]
            ip = parts[3]
            # Ignore VPN tunnel gateways (e.g. On-link, 10.x tunnel IPs)
            if gw != "On-link" and not gw.startswith("10.191.") and not gw.startswith("10.255."):
                gateway = gw
                iface_ip = ip
                break

    if not gateway or not iface_ip:
        raise RuntimeError("Could not detect physical default gateway. Verify your network connection.")

    if_idx = None
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit() and parts[3] == iface_ip:
            if_idx = parts[0]
            break

    if not if_idx:
        in_if_list = False
        for line in res.stdout.splitlines():
            if "Interface List" in line:
                in_if_list = True
                continue
            if "===" in line and in_if_list:
                in_if_list = False
                continue
            if in_if_list and any(k in line for k in ["Intel", "Realtek", "Ethernet", "Wi-Fi"]):
                match = line.strip().split(".")[0]
                if match.isdigit():
                    if_idx = match
                    break

    if not if_idx:
        if_idx = "10"

    return gateway, iface_ip, if_idx

def load_cidrs():
    if not os.path.exists(CIDR_FILE):
        raise FileNotFoundError(f"CIDR file not found at {CIDR_FILE}. Run update-cidrs first.")
    cidrs = []
    with open(CIDR_FILE, "r", encoding="utf-8") as f:
        for line in f:
            c = line.strip()
            if c and not c.startswith("#") and "/" in c:
                net, prefix = c.split("/")
                mask_int = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
                netmask = socket.inet_ntoa(struct.pack("!I", mask_int))
                cidrs.append((net, netmask, int(prefix)))
    return cidrs

def check_live_route_active(gw):
    r = subprocess.run(["route", "print", SAMPLE_NET], capture_output=True, text=True)
    return gw in r.stdout

def enable(force=False, silent=False):
    gw, if_ip, if_idx = get_physical_gateway()
    
    if not force and check_live_route_active(gw):
        if not silent:
            print(f"[+] Iran routes already active and pointing to {gw}. Nothing to do.")
        return

    cidrs = load_cidrs()
    if not silent:
        print(f"[*] Physical gateway: {gw} (Interface: {if_ip}, Index: {if_idx})")
        print(f"[*] Applying {len(cidrs)} Iranian CIDR routes to live routing table...")

    t0 = time.time()
    def _add_live_route(item):
        net, mask, _ = item
        subprocess.run(
            ["route", "add", net, "mask", mask, gw, "metric", "1", "if", if_idx],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    with ThreadPoolExecutor(max_workers=24) as ex:
        list(ex.map(_add_live_route, cidrs))
    dur_live = round(time.time() - t0, 2)
    
    if not silent:
        print(f"[+] Live routes applied in {dur_live}s.")
        print("[*] Writing persistent routes to Windows registry...")
    
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_SET_VALUE)
        for net, mask, _ in cidrs:
            val_name = f"{net},{mask},{gw},1"
            winreg.SetValueEx(k, val_name, 0, winreg.REG_SZ, "")
        winreg.CloseKey(k)
        if not silent:
            print("[+] Saved to persistent registry.")
    except Exception as e:
        if not silent:
            print(f"[-] Registry write error: {e}")

    if not silent:
        test_connectivity()

def disable(silent=False):
    cidrs = load_cidrs()
    if not silent:
        print(f"[*] Removing {len(cidrs)} routes from live routing table...")
    t0 = time.time()

    def _del_live_route(item):
        net, _, _ = item
        subprocess.run(
            ["route", "delete", net],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    with ThreadPoolExecutor(max_workers=24) as ex:
        list(ex.map(_del_live_route, cidrs))
    dur_live = round(time.time() - t0, 2)
    
    if not silent:
        print(f"[+] Live routes deleted in {dur_live}s.")
        print("[*] Removing routes from Windows registry...")
    
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_ALL_ACCESS)
        net_set = set(c[0] for c in cidrs)
        to_delete = []
        cnt = winreg.QueryInfoKey(k)[1]
        for i in range(cnt):
            name, _, _ = winreg.EnumValue(k, i)
            parts = name.split(",")
            if len(parts) >= 1 and parts[0] in net_set:
                to_delete.append(name)
        for name in to_delete:
            try:
                winreg.DeleteValue(k, name)
            except Exception:
                pass
        winreg.CloseKey(k)
        if not silent:
            print(f"[+] Removed {len(to_delete)} persistent entries from registry.")
    except Exception as e:
        if not silent:
            print(f"[-] Registry cleanup error: {e}")

def install():
    if not is_admin():
        print("[-] Administrator privileges required. Run as Administrator.")
        sys.exit(1)

    print("[*] Setting up Windscribe Iran Bypass as native Windows background service...")
    
    # Author VBS runner
    vbs_content = f'''Dim WShell
Set WShell = CreateObject("WScript.Shell")
WShell.Run """pythonw.exe"" ""{os.path.join(SCRIPT_DIR, "iran_route.py")}"" enable --silent", 0, False
'''
    with open(VBS_FILE, "w", encoding="utf-8") as f:
        f.write(vbs_content)

    # Task XML with Logon and Network Connect event triggers
    task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Auto-sync Iran direct routes for Windscribe on logon and network connect</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[(EventID=10000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>//B "{VBS_FILE}"</Arguments>
    </Exec>
  </Actions>
</Task>'''
    
    tmp_xml = os.path.join(os.environ.get("TEMP", SCRIPT_DIR), "IranRouteTask.xml")
    with open(tmp_xml, "w", encoding="utf-16") as f:
        f.write(task_xml)

    subprocess.run(["schtasks", "/create", "/tn", TASK_NAME, "/xml", tmp_xml, "/f"], stdout=subprocess.DEVNULL)
    try:
        os.remove(tmp_xml)
    except Exception:
        pass

    print("[+] Registered event-driven background task in Windows Task Scheduler.")
    print("[*] Applying routes now...")
    enable(force=True)
    print("\n[+] Installation complete. The bypass is now fully automatic.")

def uninstall():
    if not is_admin():
        print("[-] Administrator privileges required. Run as Administrator.")
        sys.exit(1)

    print(f"[*] Removing scheduled task {TASK_NAME}...")
    subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Removing routing rules...")
    disable()
    if os.path.exists(VBS_FILE):
        try:
            os.remove(VBS_FILE)
        except Exception:
            pass
    print("[+] Uninstall complete. System restored to default routing.")

def update_cidrs():
    print("[*] Downloading latest RIPE NCC delegated stats for Iran...")
    import ipaddress
    url = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    
    with urllib.request.urlopen(req, timeout=15) as resp:
        all_nets = []
        for line in resp:
            l = line.decode("ascii", errors="ignore").strip()
            if l.startswith("ripencc|IR|ipv4|"):
                parts = l.split("|")
                start_ip = ipaddress.ip_address(parts[3])
                count = int(parts[4])
                status = parts[6]
                if status in ("allocated", "assigned"):
                    end_ip = start_ip + count - 1
                    for net in ipaddress.summarize_address_range(start_ip, end_ip):
                        all_nets.append(net)

    collapsed = sorted(list(ipaddress.collapse_addresses(all_nets)), key=lambda x: int(x.network_address))
    with open(CIDR_FILE, "w", encoding="utf-8") as f:
        for c in collapsed:
            f.write(f"{c}\n")
    print(f"[+] Successfully updated {len(collapsed)} Iranian CIDR blocks in {CIDR_FILE}")

def status():
    cidrs = load_cidrs()
    gw = None
    try:
        gw, if_ip, _ = get_physical_gateway()
    except Exception:
        pass
    
    live_active = check_live_route_active(gw) if gw else False
    
    reg_count = 0
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
        cnt = winreg.QueryInfoKey(k)[1]
        net_set = set(c[0] for c in cidrs)
        for i in range(cnt):
            name, _, _ = winreg.EnumValue(k, i)
            parts = name.split(",")
            if len(parts) >= 1 and parts[0] in net_set:
                reg_count += 1
        winreg.CloseKey(k)
    except Exception:
        pass

    task_exists = False
    r = subprocess.run(["schtasks", "/query", "/tn", TASK_NAME], capture_output=True, text=True)
    if r.returncode == 0:
        task_exists = True

    print("Iran Route Status:")
    print(f"  Physical Gateway:         {gw or 'Not detected'}")
    print(f"  Live routes active:       {'YES' if live_active else 'NO'}")
    print(f"  Persistent registry keys: {reg_count} / {len(cidrs)}")
    print(f"  Event task installed:     {'YES' if task_exists else 'NO'}")
    test_connectivity()

def test_connectivity():
    print("\n--- Testing Routing & Connectivity ---")
    try:
        t0 = time.time()
        req = urllib.request.Request("https://shaparak.ir", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            ms = round((time.time() - t0) * 1000)
            print(f"  [Domestic Intranet] shaparak.ir:  Status {resp.status} ({ms}ms) -> DIRECT LOCAL ROUTE OK")
    except Exception as e:
        print(f"  [Domestic Intranet] shaparak.ir:  FAILED ({e})")

    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            import json
            data = json.loads(resp.read().decode())
            print(f"  [International VPN] ipinfo.io:    IP {data.get('ip')} ({data.get('city')}, {data.get('country')}) -> VPN TUNNEL ROUTE OK")
    except Exception as e:
        print(f"  [International VPN] ipinfo.io:    FAILED ({e})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windscribe Iran Direct Route Bypass")
    parser.add_argument("action", choices=["enable", "disable", "status", "test", "install", "uninstall", "update-cidrs"])
    parser.add_argument("--force", action="store_true", help="Force re-applying routes even if active")
    parser.add_argument("--silent", action="store_true", help="Silent execution for background tasks")
    args = parser.parse_args()

    if args.action == "enable":
        enable(force=args.force, silent=args.silent)
    elif args.action == "disable":
        disable(silent=args.silent)
    elif args.action == "status":
        status()
    elif args.action == "test":
        test_connectivity()
    elif args.action == "install":
        install()
    elif args.action == "uninstall":
        uninstall()
    elif args.action == "update-cidrs":
        update_cidrs()
