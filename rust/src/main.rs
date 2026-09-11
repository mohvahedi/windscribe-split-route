#![windows_subsystem = "windows"]

use std::env;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const REG_PERSISTENT_ROUTES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes";
const DNS_POLICY_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const SAMPLE_NET: [u8; 4] = [2, 57, 3, 0];
const LOG_MAX_BYTES: u64 = 64 * 1024; // 64 KB self-rotation

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

const DOMESTIC_DNS_SERVERS_STR: &str = "78.157.42.100;78.157.42.101;185.51.200.2;1.1.1.1";

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

fn encode_multi_sz(strings: &[&str]) -> Vec<u16> {
    let mut out = Vec::new();
    for s in strings {
        out.extend(OsStr::new(s).encode_wide());
        out.push(0);
    }
    out.push(0); // Double null termination
    out
}

fn flush_dns_cache() {
    unsafe {
        DnsFlushResolverCache();
    }
}

fn get_log_path() -> std::path::PathBuf {
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.join("iran-route.log");
        }
    }
    std::path::PathBuf::from(r"C:\Users\Lion\bin\iran-route.log")
}

fn log_event(msg: &str) {
    let log_path = get_log_path();

    // Check for rotation if file exceeds 64KB
    if let Ok(meta) = fs::metadata(&log_path) {
        if meta.len() > LOG_MAX_BYTES {
            if let Ok(mut f) = fs::File::open(&log_path) {
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                if buf.len() > 32 * 1024 {
                    let keep = &buf[buf.len() - 32 * 1024..];
                    let _ = fs::write(&log_path, keep);
                }
            }
        }
    }

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let ts = chrono_timestamp();
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}

fn chrono_timestamp() -> String {
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
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

    default_routes.sort_by_key(|r| r.2);

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

                if !desc.contains("Hyper-V")
                    && !desc.contains("Virtual")
                    && !name.contains("vEthernet")
                    && !name.contains("TAP")
                    && !name.contains("Wintun")
                    && !name.contains("TunnelBear")
                    && !name.contains("Nord")
                    && !name.contains("Windscribe")
                {
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

/// Creates or updates NRPT rule natively in registry without spawning PowerShell.
fn ensure_nrpt_policy() -> bool {
    let (active, _) = is_nrpt_active();
    if active {
        return true;
    }

    let policy_path_w = to_wide(DNS_POLICY_PATH);
    let mut hpolicy: HKEY = std::ptr::null_mut();
    let res = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            policy_path_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            std::ptr::null(),
            &mut hpolicy,
            std::ptr::null_mut(),
        )
    };
    if res != 0 || hpolicy.is_null() {
        return false;
    }

    // Static stable GUID for this rule
    let rule_guid = "{CF636BA7-0BA9-4839-9AE9-451DF6945051}";
    let rule_guid_w = to_wide(rule_guid);
    let mut hrule: HKEY = std::ptr::null_mut();
    let res = unsafe {
        RegCreateKeyExW(
            hpolicy,
            rule_guid_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            std::ptr::null(),
            &mut hrule,
            std::ptr::null_mut(),
        )
    };
    unsafe { RegCloseKey(hpolicy) };

    if res != 0 || hrule.is_null() {
        return false;
    }

    unsafe {
        let disp_w = to_wide("IranDomesticDNS");
        RegSetValueExW(
            hrule,
            to_wide("DisplayName").as_ptr(),
            0,
            REG_SZ,
            disp_w.as_ptr() as *const u8,
            (disp_w.len() * 2) as u32,
        );

        let multi_sz = encode_multi_sz(DOMESTIC_NAMESPACES);
        RegSetValueExW(
            hrule,
            to_wide("Name").as_ptr(),
            0,
            REG_MULTI_SZ,
            multi_sz.as_ptr() as *const u8,
            (multi_sz.len() * 2) as u32,
        );

        let srv_w = to_wide(DOMESTIC_DNS_SERVERS_STR);
        RegSetValueExW(
            hrule,
            to_wide("GenericDNSServers").as_ptr(),
            0,
            REG_SZ,
            srv_w.as_ptr() as *const u8,
            (srv_w.len() * 2) as u32,
        );

        let cfg_opt: u32 = 8;
        RegSetValueExW(
            hrule,
            to_wide("ConfigOptions").as_ptr(),
            0,
            REG_DWORD,
            &cfg_opt as *const _ as *const u8,
            4,
        );

        let ver: u32 = 2;
        RegSetValueExW(
            hrule,
            to_wide("Version").as_ptr(),
            0,
            REG_DWORD,
            &ver as *const _ as *const u8,
            4,
        );

        RegCloseKey(hrule);
    }

    flush_dns_cache();
    true
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

struct TestResult {
    label: &'static str,
    status: String,
    latency_ms: u128,
    extra: String,
    ok: bool,
}

fn run_parallel_connectivity_test() -> Vec<TestResult> {
    let targets: &[(&str, &'static str, bool)] = &[
        ("https://shaparak.ir", "Domestic Bank/Payment Gateway", false),
        ("https://digikala.com", "Domestic E-Commerce (.com)", false),
        ("https://divar.ir", "Domestic Classifieds (.ir)", false),
        ("https://ipinfo.io/json", "International VPN Endpoint", true),
    ];

    let (tx, rx) = mpsc::channel();

    for (url, label, is_vpn) in targets {
        let tx = tx.clone();
        let url = url.to_string();
        thread::spawn(move || {
            let t0 = Instant::now();
            let mut cmd = Command::new("curl");
            cmd.args(["-s", "-m", "5"]);
            if *is_vpn {
                cmd.args(["-w", "\n__METRICS__:%{http_code}:%{time_total}", &url]);
            } else {
                cmd.args(["-w", "%{http_code}:%{time_total}", "-o", "nul", &url]);
            }
            cmd.creation_flags(CREATE_NO_WINDOW);

            let res = cmd.output();
            let dur = t0.elapsed().as_millis();

            match res {
                Ok(output) => {
                    let out_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if *is_vpn {
                        if let Some((body, metrics)) = out_str.split_once("__METRICS__:") {
                            if let Some((code, _)) = metrics.split_once(':') {
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
                                let country = body
                                    .lines()
                                    .find(|l| l.contains("\"country\":"))
                                    .map(|l| l.replace('\"', "").replace(',', "").trim().to_string())
                                    .unwrap_or_default();
                                tx.send(TestResult {
                                    label,
                                    status: code.to_string(),
                                    latency_ms: dur,
                                    extra: format!("{} ({}, {})", ip, city, country),
                                    ok: code == "200",
                                })
                                .unwrap();
                                return;
                            }
                        }
                    } else if let Some((code, _)) = out_str.split_once(':') {
                        let is_ok = code == "200" || code == "301" || code == "302";
                        tx.send(TestResult {
                            label,
                            status: code.to_string(),
                            latency_ms: dur,
                            extra: String::new(),
                            ok: is_ok,
                        })
                        .unwrap();
                        return;
                    }
                    tx.send(TestResult {
                        label,
                        status: "Timeout".to_string(),
                        latency_ms: dur,
                        extra: String::new(),
                        ok: false,
                    })
                    .unwrap();
                }
                Err(_) => {
                    tx.send(TestResult {
                        label,
                        status: "Failed".to_string(),
                        latency_ms: dur,
                        extra: String::new(),
                        ok: false,
                    })
                    .unwrap();
                }
            }
        });
    }

    drop(tx);
    let mut results = Vec::new();
    while let Ok(res) = rx.recv() {
        results.push(res);
    }
    // Maintain presentation order
    results.sort_by_key(|r| match r.label {
        "Domestic Bank/Payment Gateway" => 0,
        "Domestic E-Commerce (.com)" => 1,
        "Domestic Classifieds (.ir)" => 2,
        _ => 3,
    });
    results
}

fn print_connectivity_benchmarks() {
    println!("\n--- Parallel Routing & DNS Latency Verification ---");
    let results = run_parallel_connectivity_test();
    for r in results {
        let tag = if r.ok {
            "\x1b[1;32m[OK]\x1b[0m"
        } else {
            "\x1b[1;31m[FAIL]\x1b[0m"
        };
        if r.extra.is_empty() {
            println!("  {} {:<32}: Status {} ({}ms)", tag, r.label, r.status, r.latency_ms);
        } else {
            println!("  {} {:<32}: {} ({}ms)", tag, r.label, r.extra, r.latency_ms);
        }
    }
}

fn print_help() {
    println!("\x1b[1;36miran-route\x1b[0m 1.1.0 - Native Kernel Route & DNS Split-Tunnel Engine");
    println!("High-performance domestic CIDR bypass for Windscribe & Windows full-tunnel VPNs.\n");
    println!("\x1b[1mUSAGE:\x1b[0m");
    println!("    iran-route [COMMAND] [OPTIONS]\n");
    println!("\x1b[1mCOMMANDS:\x1b[0m");
    println!("    \x1b[32mstatus\x1b[0m      Display current physical adapter, live routes, DNS policy & ping test");
    println!("    \x1b[32menable\x1b[0m      Inject 1,740 domestic CIDRs into kernel table and activate DNS split-tunnel");
    println!("    \x1b[32mdisable\x1b[0m     Remove all injected routes and DNS policy from system");
    println!("    \x1b[32mtest\x1b[0m        Run fast parallel latency and IP routing verification");
    println!("    \x1b[32mlog\x1b[0m         View recent background event synchronization logs\n");
    println!("\x1b[1mOPTIONS:\x1b[0m");
    println!("    \x1b[33m--silent\x1b[0m    Run windowless with settle delay & named mutex (used by Scheduled Task)");
    println!("    \x1b[33m--force\x1b[0m     Force route re-application even if sample network is already active");
    println!("    \x1b[33m-h, --help\x1b[0m  Print this help information");
    println!("    \x1b[33m-V, --version\x1b[0m Print version information\n");
}

fn show_recent_logs() {
    let log_path = get_log_path();
    if !log_path.exists() {
        println!("No sync logs found at {:?}", log_path);
        return;
    }

    if let Ok(content) = fs::read_to_string(&log_path) {
        println!("Recent Background Sync Logs ({:?}):", log_path);
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(25);
        for line in &lines[start..] {
            println!("  {}", line);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let action = args.get(1).map(|s| s.as_str()).unwrap_or("status");
    let silent = args.iter().any(|a| a == "--silent");
    let force = args.iter().any(|a| a == "--force");

    if !silent {
        unsafe {
            AttachConsole(0xFFFFFFFF);
            // Enable ANSI escape processing in console
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }

    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("iran-route 1.1.0 (native rust engine)");
        return;
    }

    let cidrs = load_cidrs();

    match action {
        "enable" => {
            let _guard = if silent {
                match InstanceGuard::try_acquire() {
                    Some(g) => Some(g),
                    None => return,
                }
            } else {
                None
            };

            let adapter = match get_physical_gateway(silent) {
                Some(a) => a,
                None => {
                    log_event("NO_UPLINK: Physical gateway not detected after DHCP settle window.");
                    if !silent {
                        eprintln!("\x1b[1;31m[-] Could not detect active physical gateway. Network adapter may still be initializing.\x1b[0m");
                    }
                    return;
                }
            };

            ensure_nrpt_policy();

            if !force && is_route_active(adapter.gateway_ip, adapter.if_index) {
                log_event(&format!(
                    "SYNC_OK: 1740 routes verified on {} ({} if {})",
                    adapter.gateway_str, adapter.name, adapter.if_index
                ));
                if !silent {
                    println!(
                        "\x1b[1;32m[+]\x1b[0m Iran routes already active and pointed to {} on interface {}. Nothing to do.",
                        adapter.gateway_str, adapter.if_index
                    );
                }
                return;
            }

            if !silent {
                println!(
                    "[*] Detected physical gateway: \x1b[1;36m{}\x1b[0m (Adapter: {}, Index: {}, Metric: {})",
                    adapter.gateway_str, adapter.name, adapter.if_index, adapter.metric
                );
                println!("[*] Applying {} Iranian CIDR routes natively...", cidrs.len());
            }

            delete_routes(&cidrs);

            let t0 = Instant::now();
            let applied = apply_routes(adapter.gateway_ip, adapter.if_index, &cidrs);
            let dur = t0.elapsed();

            purge_stale_persistent_routes(&cidrs);

            log_event(&format!(
                "MIGRATION: {} routes applied to {} ({} if {}) in {:.2?}",
                applied, adapter.gateway_str, adapter.name, adapter.if_index, dur
            ));

            if !silent {
                println!(
                    "\x1b[1;32m[+]\x1b[0m Applied {} routes directly to Windows kernel table in \x1b[1;36m{:.2?}\x1b[0m.",
                    applied, dur
                );
                print_connectivity_benchmarks();
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

            log_event(&format!("DISABLED: {} routes purged, NRPT policy removed.", deleted));

            if !silent {
                println!("\x1b[1;32m[+]\x1b[0m Removed {} routes in {:.2?}.", deleted, dur);
                println!("\x1b[1;32m[+]\x1b[0m Removed DNS Split-Tunnel (NRPT) policy.");
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

            println!("\x1b[1;36mIran Route Status (Native Rust Engine 1.1.0):\x1b[0m");
            println!("  Physical Adapter:         {} ({}, Index: {})", name, if_type, if_idx);
            println!("  Physical Gateway:         {} (Local IP: {})", gw_str, ip_str);
            println!(
                "  Live routes active:       {} ({} subnets)",
                if live_active { "\x1b[1;32mYES\x1b[0m" } else { "\x1b[1;31mNO\x1b[0m" },
                cidrs.len()
            );
            println!(
                "  DNS Split-Tunnel (NRPT):  {} ({})",
                if nrpt_active { "\x1b[1;32mACTIVE\x1b[0m" } else { "\x1b[1;31mOFF\x1b[0m" },
                if nrpt_active { &nrpt_servers } else { "None" }
            );

            print_connectivity_benchmarks();
        }
        "test" => {
            print_connectivity_benchmarks();
        }
        "log" => {
            show_recent_logs();
        }
        _ => {
            print_help();
        }
    }
}
