#![windows_subsystem = "windows"]

use std::env;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Console::AttachConsole;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const REG_PERSISTENT_ROUTES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes";
const DNS_POLICY_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const SAMPLE_NET: [u8; 4] = [2, 57, 3, 0];

#[link(name = "dnsapi")]
extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

static CIDRS_RAW: &str = include_str!("../iran_cidrs.txt");

const DOMESTIC_NAMESPACES: &[&str] = &[
    ".ir",
    "digikala.com",
    "torob.com",
    "snapp.express",
    "aparat.com",
    "filimo.com",
    "telewebion.com",
    "eitaa.com",
    "bale.ai",
    "gap.im",
    "neshan.org",
    "basalam.com",
    "snapptrip.com",
    "sheypoor.com",
    "cinematicket.org",
    "tiwall.com",
    "fidibo.com",
    "taaghche.com",
    "paziresh24.com",
];

const DOMESTIC_DNS_SERVERS: &[&str] = &[
    "78.157.42.100",
    "78.157.42.101",
    "185.51.200.2",
    "1.1.1.1",
];

struct Cidr {
    ip: u32, // network byte order
    prefix_len: u8,
}

struct PhysicalAdapter {
    gateway_ip: u32,
    gateway_str: String,
    interface_ip_str: String,
    if_index: u32,
    metric: u32,
    name: String,
    adapter_type: &'static str,
}

struct InstanceGuard {
    handle: HANDLE,
}

impl InstanceGuard {
    fn try_acquire() -> Option<Self> {
        let name = to_wide("Global\\IranRouteSyncMutex");
        let handle = unsafe { CreateMutexW(std::ptr::null(), TRUE, name.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return None;
        }
        Some(InstanceGuard { handle })
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn flush_dns_cache() {
    unsafe {
        DnsFlushResolverCache();
    }
}

fn load_cidrs() -> Vec<Cidr> {
    let mut list = Vec::with_capacity(1800);
    for line in CIDRS_RAW.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((net_str, prefix_str)) = line.split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (net_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>()) {
                list.push(Cidr {
                    ip: u32::from_ne_bytes(ip.octets()),
                    prefix_len: prefix,
                });
            }
        }
    }
    list
}

/// Detects the physical internet-facing default adapter.
/// Inspects Windows kernel default routes (`0.0.0.0/0`) from `GetIpForwardTable2`,
/// selects non-VPN routes, and cross-references `GetAdaptersAddresses` to verify
/// physical hardware (Ethernet or Wi-Fi) with the lowest metric.
fn detect_physical_interface() -> Option<PhysicalAdapter> {
    // 1. Get default routes from kernel forward table
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let res = unsafe { GetIpForwardTable2(AF_INET as u16, &mut table_ptr) };
    if res != 0 || table_ptr.is_null() {
        return None;
    }

    let mut default_routes: Vec<(u32, u32, u32)> = Vec::new(); // (if_index, next_hop_ip, metric)
    unsafe {
        let t = &*table_ptr;
        let slice = std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize);
        for row in slice {
            if row.DestinationPrefix.PrefixLength == 0 {
                let nh = row.NextHop.Ipv4.sin_addr.S_un.S_addr;
                let b = nh.to_ne_bytes();
                // Filter out on-link (0.0.0.0), APIPA, loopback, and obvious internal VPN subnets
                if nh != 0 && b[0] != 127 && (b[0] != 169 || b[1] != 254) {
                    default_routes.push((row.InterfaceIndex, nh, row.Metric));
                }
            }
        }
        FreeMibTable(table_ptr as *const _);
    }

    // Sort candidate default routes by metric ascending (lowest metric = primary interface)
    default_routes.sort_by_key(|r| r.2);

    // 2. Query adapter details from GetAdaptersAddresses
    let mut buf_len: u32 = 0;
    unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_GATEWAYS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut buf_len,
        );
    }
    if buf_len == 0 {
        return None;
    }

    let mut buf = vec![0u8; buf_len as usize];
    let res = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_GATEWAYS,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut buf_len,
        )
    };
    if res != 0 {
        return None;
    }

    // 3. Match candidate routes against physical adapters
    for (candidate_idx, candidate_gw, candidate_metric) in default_routes {
        let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !curr.is_null() {
            let a = unsafe { &*curr };
            let if_idx = unsafe { a.Anonymous1.Anonymous.IfIndex };

            if if_idx == candidate_idx
                && (a.IfType == IF_TYPE_ETHERNET_CSMACD || a.IfType == IF_TYPE_IEEE80211)
                && a.OperStatus == 1
            {
                let desc = if !a.Description.is_null() {
                    let mut len = 0;
                    while unsafe { *a.Description.add(len) } != 0 {
                        len += 1;
                    }
                    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(a.Description, len) })
                } else {
                    String::new()
                };

                let name = if !a.FriendlyName.is_null() {
                    let mut len = 0;
                    while unsafe { *a.FriendlyName.add(len) } != 0 {
                        len += 1;
                    }
                    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(a.FriendlyName, len) })
                } else {
                    String::new()
                };

                // Exclude any virtual / Hyper-V adapters
                if !desc.contains("Hyper-V")
                    && !desc.contains("Virtual")
                    && !name.contains("vEthernet")
                    && !name.contains("TAP")
                    && !name.contains("Wintun")
                    && !name.contains("TunnelBear")
                    && !name.contains("Nord")
                    && !name.contains("Windscribe")
                {
                    // Find unicast IPv4
                    let mut unicast_ip_str = String::new();
                    if !a.FirstUnicastAddress.is_null() {
                        let u_node = unsafe { &*a.FirstUnicastAddress };
                        if !u_node.Address.lpSockaddr.is_null() {
                            let sin = unsafe { &*(u_node.Address.lpSockaddr as *const SOCKADDR_IN) };
                            let ip_val = unsafe { sin.sin_addr.S_un.S_addr };
                            let b = ip_val.to_ne_bytes();
                            if b[0] != 169 || b[1] != 254 {
                                unicast_ip_str = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                            }
                        }
                    }

                    let b = candidate_gw.to_ne_bytes();
                    let gw_str = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);

                    return Some(PhysicalAdapter {
                        gateway_ip: candidate_gw,
                        gateway_str: gw_str,
                        interface_ip_str: unicast_ip_str,
                        if_index: candidate_idx,
                        metric: candidate_metric,
                        name,
                        adapter_type: if a.IfType == IF_TYPE_ETHERNET_CSMACD {
                            "Ethernet"
                        } else {
                            "Wi-Fi"
                        },
                    });
                }
            }
            curr = a.Next;
        }
    }

    None
}

fn get_physical_gateway(settle: bool) -> Option<PhysicalAdapter> {
    if settle {
        sleep(Duration::from_millis(1000));
    }
    // Up to 5 attempts with 500ms intervals to allow DHCP handshake to complete
    for attempt in 0..5 {
        if let Some(adapter) = detect_physical_interface() {
            return Some(adapter);
        }
        if settle && attempt < 4 {
            sleep(Duration::from_millis(500));
        }
    }
    None
}

/// Checks if sample Iranian network is already pointing to the target gateway on target interface.
fn is_route_active(gateway_ip: u32, if_index: u32) -> bool {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    row.DestinationPrefix.Prefix.si_family = AF_INET as u16;
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET as u16;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(SAMPLE_NET);
    row.DestinationPrefix.PrefixLength = 24;

    let res = unsafe { GetIpForwardEntry2(&mut row) };
    if res == 0 {
        let nh = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr };
        return nh == gateway_ip && row.InterfaceIndex == if_index;
    }
    false
}

fn apply_routes(gateway_ip: u32, if_index: u32, cidrs: &[Cidr]) -> usize {
    let mut count = 0;
    for cidr in cidrs {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = if_index;
        row.DestinationPrefix.Prefix.si_family = AF_INET as u16;
        row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET as u16;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = cidr.ip;
        row.DestinationPrefix.PrefixLength = cidr.prefix_len;

        row.NextHop.si_family = AF_INET as u16;
        row.NextHop.Ipv4.sin_family = AF_INET as u16;
        row.NextHop.Ipv4.sin_addr.S_un.S_addr = gateway_ip;
        row.Metric = 1;

        let res = unsafe { CreateIpForwardEntry2(&row) };
        if res == 0 || res == 5010 {
            count += 1;
        }
    }
    count
}

fn delete_routes(cidrs: &[Cidr]) -> usize {
    let mut count = 0;
    for cidr in cidrs {
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.DestinationPrefix.Prefix.si_family = AF_INET as u16;
        row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET as u16;
        row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = cidr.ip;
        row.DestinationPrefix.PrefixLength = cidr.prefix_len;

        let res = unsafe { DeleteIpForwardEntry2(&row) };
        if res == 0 {
            count += 1;
        }
    }
    count
}

fn is_nrpt_active() -> (bool, String) {
    let subkey_w = to_wide(DNS_POLICY_PATH);
    let mut hkey: HKEY = std::ptr::null_mut();
    let res = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    if res != 0 {
        return (false, String::new());
    }

    let mut index = 0;
    let mut key_name_buf = [0u16; 256];
    loop {
        let mut name_len = key_name_buf.len() as u32;
        let enum_res = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                key_name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if enum_res != 0 {
            break;
        }

        let mut child_key: HKEY = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(hkey, key_name_buf.as_ptr(), 0, KEY_READ, &mut child_key) } == 0 {
            let mut val_buf = [0u8; 512];
            let mut val_len = val_buf.len() as u32;
            let val_name = to_wide("DisplayName");
            if unsafe {
                RegQueryValueExW(
                    child_key,
                    val_name.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    val_buf.as_mut_ptr(),
                    &mut val_len,
                )
            } == 0 {
                let disp = String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(val_buf.as_ptr() as *const u16, (val_len / 2) as usize)
                });
                if disp.trim_matches('\0') == "IranDomesticDNS" {
                    let mut srv_buf = [0u8; 512];
                    let mut srv_len = srv_buf.len() as u32;
                    let srv_name = to_wide("GenericDNSServers");
                    let servers = if unsafe {
                        RegQueryValueExW(
                            child_key,
                            srv_name.as_ptr(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            srv_buf.as_mut_ptr(),
                            &mut srv_len,
                        )
                    } == 0 {
                        String::from_utf16_lossy(unsafe {
                            std::slice::from_raw_parts(srv_buf.as_ptr() as *const u16, (srv_len / 2) as usize)
                        })
                        .trim_matches('\0')
                        .to_string()
                    } else {
                        "Electro DNS".to_string()
                    };
                    unsafe {
                        RegCloseKey(child_key);
                        RegCloseKey(hkey);
                    }
                    return (true, servers);
                }
            }
            unsafe { RegCloseKey(child_key) };
        }
        index += 1;
    }
    unsafe { RegCloseKey(hkey) };
    (false, String::new())
}

fn ensure_nrpt_policy() -> bool {
    let (active, _) = is_nrpt_active();
    if active {
        return true;
    }

    let ns_list = DOMESTIC_NAMESPACES
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ");

    let srv_list = DOMESTIC_DNS_SERVERS
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ");

    let cmd = format!(
        "Add-DnsClientNrptRule -Namespace @({}) -Nameservers @({}) -DisplayName 'IranDomesticDNS'",
        ns_list, srv_list
    );

    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    flush_dns_cache();
    status.map(|s| s.success()).unwrap_or(false)
}

fn remove_nrpt_policy() {
    let subkey_w = to_wide(DNS_POLICY_PATH);
    let mut hkey: HKEY = std::ptr::null_mut();
    let res = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_ALL_ACCESS, &mut hkey) };
    if res != 0 {
        return;
    }

    let mut to_delete = Vec::new();
    let mut index = 0;
    let mut key_name_buf = [0u16; 256];
    loop {
        let mut name_len = key_name_buf.len() as u32;
        let enum_res = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                key_name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if enum_res != 0 {
            break;
        }

        let mut child_key: HKEY = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(hkey, key_name_buf.as_ptr(), 0, KEY_READ, &mut child_key) } == 0 {
            let mut val_buf = [0u8; 512];
            let mut val_len = val_buf.len() as u32;
            let val_name = to_wide("DisplayName");
            if unsafe {
                RegQueryValueExW(
                    child_key,
                    val_name.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    val_buf.as_mut_ptr(),
                    &mut val_len,
                )
            } == 0 {
                let disp = String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(val_buf.as_ptr() as *const u16, (val_len / 2) as usize)
                });
                if disp.trim_matches('\0') == "IranDomesticDNS" {
                    to_delete.push(key_name_buf[..name_len as usize].to_vec());
                }
            }
            unsafe { RegCloseKey(child_key) };
        }
        index += 1;
    }

    for sub in to_delete {
        let mut null_term = sub;
        null_term.push(0);
        unsafe { RegDeleteKeyW(hkey, null_term.as_ptr()) };
    }
    unsafe { RegCloseKey(hkey) };
    flush_dns_cache();
}

fn purge_stale_persistent_routes(cidrs: &[Cidr]) {
    let subkey_w = to_wide(REG_PERSISTENT_ROUTES);
    let mut hkey: HKEY = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_ALL_ACCESS, &mut hkey) } != 0 {
        return;
    }

    let mut to_delete = Vec::new();
    let mut index = 0;
    let mut val_name_buf = [0u16; 512];
    loop {
        let mut val_len = val_name_buf.len() as u32;
        let res = unsafe {
            RegEnumValueW(
                hkey,
                index,
                val_name_buf.as_mut_ptr(),
                &mut val_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if res != 0 {
            break;
        }
        let name_str = String::from_utf16_lossy(&val_name_buf[..val_len as usize]);
        if let Some((first, _)) = name_str.split_once(',') {
            if let Ok(ip) = first.parse::<Ipv4Addr>() {
                let raw_ip = u32::from_ne_bytes(ip.octets());
                if cidrs.iter().any(|c| c.ip == raw_ip) {
                    to_delete.push(val_name_buf[..val_len as usize].to_vec());
                }
            }
        }
        index += 1;
    }

    for val in to_delete {
        let mut null_term = val;
        null_term.push(0);
        unsafe { RegDeleteValueW(hkey, null_term.as_ptr()) };
    }
    unsafe { RegCloseKey(hkey) };
}

fn test_connectivity() {
    println!("\n--- Testing Routing, DNS & Connectivity ---");
    let tests = [
        ("https://shaparak.ir", "Domestic Bank/Payment Gateway"),
        ("https://digikala.com", "Domestic E-Commerce (.com)"),
        ("https://divar.ir", "Domestic Classifieds (.ir)"),
        ("https://ipinfo.io/json", "International VPN Endpoint"),
    ];

    for (url, label) in tests {
        let t0 = Instant::now();
        let out = Command::new("curl")
            .args(["-s", "-m", "5", "-w", "%{http_code}:%{time_total}", "-o", "nul", url])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        let dur = t0.elapsed().as_millis();
        match out {
            Ok(output) => {
                let res = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some((code, _)) = res.split_once(':') {
                    if code == "200" || code == "301" || code == "302" {
                        if url.contains("ipinfo.io") {
                            let ip_res = Command::new("curl")
                                .args(["-s", "-m", "5", url])
                                .creation_flags(CREATE_NO_WINDOW)
                                .output();
                            let ip_info = if let Ok(ip_out) = ip_res {
                                let body = String::from_utf8_lossy(&ip_out.stdout);
                                let ip = body
                                    .lines()
                                    .find(|l| l.contains("\"ip\":"))
                                    .map(|l| l.replace('\"', "").replace(',', "").trim().to_string())
                                    .unwrap_or_default();
                                let city = body
                                    .lines()
                                    .find(|l| l.contains("\"city\":"))
                                    .map(|l| l.replace('\"', "").replace(',', "").trim().to_string())
                                    .unwrap_or_default();
                                format!("{} ({})", ip, city)
                            } else {
                                "Connected".to_string()
                            };
                            println!("  [OK] {:<32}: {} ({}ms)", label, ip_info, dur);
                        } else {
                            println!("  [OK] {:<32}: Status {} ({}ms)", label, code, dur);
                        }
                    } else {
                        println!("  [WARN] {:<30}: Status {} ({}ms)", label, code, dur);
                    }
                } else {
                    println!("  [FAIL] {:<30}: Request timed out ({}ms)", label, dur);
                }
            }
            Err(e) => {
                println!("  [FAIL] {:<30}: Error {} ({}ms)", label, e, dur);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let action = args.get(1).map(|s| s.as_str()).unwrap_or("status");
    let silent = args.iter().any(|a| a == "--silent");
    let force = args.iter().any(|a| a == "--force");

    if !silent {
        unsafe { AttachConsole(0xFFFFFFFF) };
    }

    let cidrs = load_cidrs();

    match action {
        "enable" => {
            let _guard = if silent {
                match InstanceGuard::try_acquire() {
                    Some(g) => Some(g),
                    None => return, // Another sync is already in progress
                }
            } else {
                None
            };

            let adapter = match get_physical_gateway(silent) {
                Some(a) => a,
                None => {
                    if !silent {
                        eprintln!("[-] Could not detect active physical gateway. Network adapter may still be initializing.");
                    }
                    return;
                }
            };

            ensure_nrpt_policy();

            // Check if routes are already active for THIS gateway on THIS interface
            if !force && is_route_active(adapter.gateway_ip, adapter.if_index) {
                if !silent {
                    println!(
                        "[+] Iran routes already active and pointed to {} on interface {}. Nothing to do.",
                        adapter.gateway_str, adapter.if_index
                    );
                }
                return;
            }

            if !silent {
                println!(
                    "[*] Detected physical gateway: {} (Adapter: {}, Index: {}, Metric: {})",
                    adapter.gateway_str, adapter.name, adapter.if_index, adapter.metric
                );
                println!("[*] Applying {} Iranian CIDR routes natively...", cidrs.len());
            }

            // If we are migrating from a previous gateway/interface, wipe older routes first
            delete_routes(&cidrs);

            let t0 = Instant::now();
            let applied = apply_routes(adapter.gateway_ip, adapter.if_index, &cidrs);
            let dur = t0.elapsed();

            purge_stale_persistent_routes(&cidrs);

            if !silent {
                println!("[+] Applied {} routes directly to Windows kernel table in {:.2?}.", applied, dur);
                test_connectivity();
            }
        }
        "disable" => {
            if !silent {
                println!("[*] Removing {} Iranian CIDR routes from live routing table...", cidrs.len());
            }
            let t0 = Instant::now();
            let deleted = delete_routes(&cidrs);
            let dur = t0.elapsed();

            purge_stale_persistent_routes(&cidrs);
            remove_nrpt_policy();

            if !silent {
                println!("[+] Removed {} routes in {:.2?}.", deleted, dur);
                println!("[+] Removed DNS Split-Tunnel (NRPT) policy.");
            }
        }
        "status" => {
            let adapter = detect_physical_interface();
            let (gw_str, ip_str, name, if_type, if_idx, live_active) = if let Some(ref a) = adapter {
                (
                    a.gateway_str.clone(),
                    a.interface_ip_str.clone(),
                    a.name.clone(),
                    a.adapter_type,
                    a.if_index.to_string(),
                    is_route_active(a.gateway_ip, a.if_index),
                )
            } else {
                (
                    "Not detected".to_string(),
                    "?".to_string(),
                    "None".to_string(),
                    "Unknown",
                    "?".to_string(),
                    false,
                )
            };

            let (nrpt_active, nrpt_servers) = is_nrpt_active();

            println!("Iran Route Status (Native Rust Engine):");
            println!("  Physical Adapter:         {} ({}, Index: {})", name, if_type, if_idx);
            println!("  Physical Gateway:         {} (Local IP: {})", gw_str, ip_str);
            println!(
                "  Live routes active:       {} ({} subnets)",
                if live_active { "YES" } else { "NO" },
                cidrs.len()
            );
            println!(
                "  DNS Split-Tunnel (NRPT):  {} ({})",
                if nrpt_active { "ACTIVE" } else { "OFF" },
                if nrpt_active { &nrpt_servers } else { "None" }
            );

            test_connectivity();
        }
        "test" => {
            test_connectivity();
        }
        _ => {
            println!("Usage: iran-route [enable|disable|status|test] [--silent] [--force]");
        }
    }
}
