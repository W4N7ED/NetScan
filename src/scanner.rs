//! Moteur de scan : analyse des plages, ping ICMP, ARP, noms d'hôtes, ports TCP.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Nombre maximal d'adresses par scan (un /16).
pub const MAX_IPS: usize = 65_536;
/// Connexions TCP simultanées par hôte.
const PORT_PARALLELISM: usize = 16;

pub const PORT_PRESETS: &[(&str, &str)] = &[
    ("Par défaut", "21,22,23,80,135,139,443,445,3389,5985,8080,8443"),
    ("Web", "80,443,8000,8008,8080,8081,8443,8888,9443"),
    ("Windows / Active Directory", "53,88,135,139,389,445,636,3268,3389,5985,5986"),
    ("Accès distant", "22,23,3389,5900,5985,5986"),
    ("Bases de données", "1433,1521,3306,5432,6379,9200,27017"),
    ("Messagerie", "25,110,143,465,587,993,995"),
    ("Impression", "515,631,9100"),
    ("Ports 1 à 1024", "1-1024"),
];

/// Ports web proposés dans les actions « Ouvrir dans le navigateur ».
pub const WEB_PORTS: &[(u16, &str)] = &[
    (80, "http"),
    (443, "https"),
    (5001, "https"),
    (8000, "http"),
    (8008, "http"),
    (8080, "http"),
    (8081, "http"),
    (8443, "https"),
    (8888, "http"),
    (9443, "https"),
];

pub fn port_name(p: u16) -> Option<&'static str> {
    Some(match p {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPCbind",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        515 => "LPD",
        554 => "RTSP",
        587 => "Submission",
        631 => "IPP",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        1723 => "PPTP",
        2049 => "NFS",
        3268 => "GlobalCatalog",
        3306 => "MySQL",
        3389 => "RDP",
        5060 => "SIP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        5985 => "WinRM",
        5986 => "WinRM-S",
        6379 => "Redis",
        8000 | 8008 | 8080 | 8081 | 8888 => "HTTP-Alt",
        5001 | 8443 | 9443 => "HTTPS-Alt",
        9100 => "JetDirect",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => return None,
    })
}

/// Libellé d'affichage : « HTTP/80 », ou le numéro seul si le service est inconnu.
pub fn port_badge_label(p: u16) -> String {
    match port_name(p) {
        Some(n) => format!("{n}/{p}"),
        None => p.to_string(),
    }
}

/// Libellé identique au script PowerShell (export CSV) : « HTTP/80 » ou « Port-1234 ».
pub fn port_label(p: u16) -> String {
    match port_name(p) {
        Some(n) => format!("{n}/{p}"),
        None => format!("Port-{p}"),
    }
}

pub fn format_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Fabricant de la carte réseau, d'après le préfixe de l'adresse MAC (registre IEEE embarqué).
pub fn mac_vendor(m: &[u8; 6]) -> Option<&'static str> {
    let hex: String = m.iter().map(|b| format!("{b:02X}")).collect();
    if let Some(r) = oui_data::lookup(&hex) {
        return Some(r.organization());
    }
    // Bit « administrée localement » : adresse aléatoire (téléphones, Windows récents…).
    (m[0] & 0x02 != 0).then_some("Adresse privée (aléatoire)")
}

// ---------------------------------------------------------------------------
// Analyse des saisies
// ---------------------------------------------------------------------------

/// 65536 → « 65 536 » (espace insécable).
pub fn fmt_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('\u{a0}');
        }
        out.push(c);
    }
    out
}

fn parse_ip(s: &str) -> Result<Ipv4Addr, String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_empty()) {
        return Err(format!("Adresse incomplète : « {s} »"));
    }
    for part in &parts {
        if part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("Adresse invalide : « {s} »"));
        }
        let n: u32 = part.parse().unwrap_or(0);
        if n > 255 {
            return Err(format!("Octet invalide : {n} (0 à 255 attendu)"));
        }
    }
    s.parse::<Ipv4Addr>()
        .map_err(|_| format!("Adresse invalide : « {s} »"))
}

/// Formats acceptés (séparables par des virgules) :
/// `192.168.1.0-254`, `192.168.1.1-192.168.1.50`, `192.168.1.0/24`, `10.0.0.5`.
pub fn parse_ip_range(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let parts: Vec<String> = input
        .split([',', ';', '\n'])
        .map(|p| p.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .filter(|p| !p.is_empty())
        .collect();

    if parts.is_empty() {
        return Err("Saisissez une plage IP (ex. 192.168.1.0/24)".into());
    }

    for part in parts {
        let (start, end) = if let Some((ip, prefix)) = part.split_once('/') {
            let ip = u32::from(parse_ip(ip)?);
            let prefix: u32 = prefix
                .parse()
                .ok()
                .filter(|p| *p <= 32)
                .ok_or_else(|| format!("Masque invalide : /{prefix} (0 à 32 attendu)"))?;
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let net = ip & mask;
            let bcast = net | !mask;
            if prefix >= 31 {
                (net, bcast)
            } else {
                (net + 1, bcast - 1)
            }
        } else if let Some((a, b)) = part.split_once('-') {
            let start = parse_ip(a)?;
            let end = if b.contains('.') {
                parse_ip(b)?
            } else {
                let last: u32 = b
                    .parse()
                    .map_err(|_| format!("Fin de plage invalide : « {b} »"))?;
                if last > 255 {
                    return Err(format!("Octet invalide : {last} (0 à 255 attendu)"));
                }
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last as u8)
            };
            let (s, e) = (u32::from(start), u32::from(end));
            if s > e {
                return Err("La fin de plage précède le début".into());
            }
            (s, e)
        } else {
            let ip = u32::from(parse_ip(&part)?);
            (ip, ip)
        };

        let count = (end as u64 - start as u64 + 1) as usize;
        if out.len() + count > MAX_IPS {
            return Err(format!(
                "Trop d'adresses : {} ({} max)",
                fmt_thousands((out.len() + count) as u64),
                fmt_thousands(MAX_IPS as u64)
            ));
        }
        for v in start..=end {
            if seen.insert(v) {
                out.push(Ipv4Addr::from(v));
            }
        }
    }
    Ok(out)
}

/// Formats acceptés : `22,80,443`, `8000-8100`, mélangés. Une liste vide = ping seul.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    fn one(s: &str) -> Result<u16, String> {
        let s = s.trim();
        if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("Port invalide : « {s} »"));
        }
        match s.parse::<u32>() {
            Ok(p) if (1..=65535).contains(&p) => Ok(p as u16),
            _ => Err(format!("Port hors limites : « {s} » (1 à 65 535)")),
        }
    }
    let mut set = BTreeSet::new();
    for part in input
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        if let Some((a, b)) = part.split_once('-') {
            let (a, b) = (one(a)?, one(b)?);
            if a > b {
                return Err(format!("Plage de ports inversée : « {part} »"));
            }
            set.extend(a..=b);
        } else {
            set.insert(one(part)?);
        }
    }
    Ok(set.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Interfaces locales
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LocalNet {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl LocalNet {
    pub fn prefix(&self) -> u32 {
        u32::from(self.mask).count_ones()
    }
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) & u32::from(self.mask))
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let m = u32::from(self.mask);
        u32::from(ip) & m == u32::from(self.ip) & m
    }
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix())
    }
    /// Plage des hôtes utilisables, prête à être scannée.
    pub fn host_range(&self) -> String {
        let m = u32::from(self.mask);
        let net = u32::from(self.ip) & m;
        let bcast = net | !m;
        if self.prefix() >= 31 {
            self.cidr()
        } else {
            format!("{}-{}", Ipv4Addr::from(net + 1), Ipv4Addr::from(bcast - 1))
        }
    }
}

/// Interfaces IPv4 actives (hors boucle locale / APIPA), cartes physiques en premier.
pub fn local_networks() -> Vec<LocalNet> {
    let mut nets: Vec<LocalNet> = if_addrs::get_if_addrs()
        .map(|list| {
            list.into_iter()
                .filter_map(|iface| match iface.addr {
                    if_addrs::IfAddr::V4(ref a)
                        if !a.ip.is_loopback() && !a.ip.is_link_local() =>
                    {
                        Some(LocalNet {
                            name: iface.name.clone(),
                            ip: a.ip,
                            mask: a.netmask,
                        })
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    const VIRTUAL: &[&str] = &[
        "vethernet", "virtual", "vmware", "vbox", "hyper-v", "wsl", "tailscale",
        "zerotier", "docker", "loopback", "npcap", "vpn",
    ];
    nets.sort_by_key(|n| {
        let l = n.name.to_lowercase();
        (VIRTUAL.iter().any(|k| l.contains(k)), n.prefix() < 16)
    });
    nets
}

// ---------------------------------------------------------------------------
// Résultats
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Detection {
    Ping,
    Arp,
    Tcp,
}

impl Detection {
    pub fn label(self) -> &'static str {
        match self {
            Detection::Ping => "Ping",
            Detection::Arp => "ARP",
            Detection::Tcp => "TCP",
        }
    }
    pub fn rank(d: Option<Detection>) -> u8 {
        match d {
            Some(Detection::Ping) => 0,
            Some(Detection::Arp) => 1,
            Some(Detection::Tcp) => 2,
            None => 3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    /// `None` = hôte inactif.
    pub detection: Option<Detection>,
    pub hostname: Option<String>,
    pub mac: Option<[u8; 6]>,
    pub rtt_ms: Option<u32>,
    pub open_ports: Vec<u16>,
    pub scanned_at: String,
}

impl HostResult {
    fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            detection: None,
            hostname: None,
            mac: None,
            rtt_ms: None,
            open_ports: Vec::new(),
            scanned_at: String::new(),
        }
    }
    pub fn is_up(&self) -> bool {
        self.detection.is_some()
    }
    pub fn mac_string(&self) -> Option<String> {
        self.mac.as_ref().map(format_mac)
    }
    pub fn ports_string(&self) -> String {
        self.open_ports
            .iter()
            .map(|&p| port_label(p))
            .collect::<Vec<_>>()
            .join(", ")
    }
    pub fn vendor(&self) -> Option<&'static str> {
        self.mac.as_ref().and_then(mac_vendor)
    }
    /// Colonnes d'export (mêmes intitulés que le script PowerShell + « Detection » et « Vendor »).
    pub fn export_fields(&self) -> [String; 9] {
        [
            self.ip.to_string(),
            if self.is_up() { "Up" } else { "Down" }.to_string(),
            self.detection.map(|d| d.label()).unwrap_or("").to_string(),
            self.hostname.clone().unwrap_or_else(|| "N/A".into()),
            self.mac_string().unwrap_or_else(|| "N/A".into()),
            self.vendor().unwrap_or("N/A").to_string(),
            self.rtt_ms.map(|r| r.to_string()).unwrap_or_else(|| "N/A".into()),
            self.ports_string(),
            self.scanned_at.clone(),
        ]
    }

    /// Une ligne tabulée (enregistrement du dernier scan sur disque).
    pub fn to_line(&self) -> String {
        let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
        let det = match self.detection {
            Some(Detection::Ping) => "P",
            Some(Detection::Arp) => "A",
            Some(Detection::Tcp) => "T",
            None => "",
        };
        let mac: String = self.mac.iter().flatten().map(|b| format!("{b:02X}")).collect();
        let ports: Vec<String> = self.open_ports.iter().map(u16::to_string).collect();
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.ip,
            det,
            clean(self.hostname.as_deref().unwrap_or("")),
            mac,
            self.rtt_ms.map(|r| r.to_string()).unwrap_or_default(),
            ports.join(","),
            clean(&self.scanned_at)
        )
    }

    pub fn from_line(line: &str) -> Option<Self> {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 7 {
            return None;
        }
        let mac = match f[3] {
            "" => None,
            s if s.len() == 12 && s.is_ascii() => {
                let mut m = [0u8; 6];
                for (i, b) in m.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
                }
                Some(m)
            }
            _ => return None,
        };
        Some(Self {
            ip: f[0].parse().ok()?,
            detection: match f[1] {
                "P" => Some(Detection::Ping),
                "A" => Some(Detection::Arp),
                "T" => Some(Detection::Tcp),
                "" => None,
                _ => return None,
            },
            hostname: (!f[2].is_empty()).then(|| f[2].to_string()),
            mac,
            rtt_ms: if f[4].is_empty() { None } else { Some(f[4].parse().ok()?) },
            open_ports: f[5].split(',').filter(|s| !s.is_empty()).map(|s| s.parse().ok()).collect::<Option<_>>()?,
            scanned_at: f[6].to_string(),
        })
    }
}

pub const EXPORT_HEADERS: [&str; 9] = [
    "IP", "Status", "Detection", "Hostname", "MAC", "Vendor", "RTT_ms", "OpenPorts", "ScannedAt",
];

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ScanConfig {
    pub targets: Vec<Ipv4Addr>,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub threads: usize,
    pub resolve_names: bool,
    pub arp_discovery: bool,
    pub tcp_discovery: bool,
}

pub enum ScanEvent {
    Host(HostResult),
    Finished { cancelled: bool },
}

pub struct ScanHandle {
    rx: Receiver<ScanEvent>,
    cancel: Arc<AtomicBool>,
}

impl ScanHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn try_recv(&self) -> Option<ScanEvent> {
        self.rx.try_recv().ok()
    }
}

/// Lance le scan en arrière-plan. `notify` est appelé à chaque résultat (rafraîchit l'UI).
pub fn start_scan<F>(cfg: ScanConfig, notify: F) -> ScanHandle
where
    F: Fn() + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let handle = ScanHandle {
        rx,
        cancel: cancel.clone(),
    };

    thread::spawn(move || {
        // Initialise Winsock (nécessaire avant les résolutions DNS).
        let _ = UdpSocket::bind("0.0.0.0:0");

        let cfg = Arc::new(cfg);
        let nets = Arc::new(local_networks());
        let notify = Arc::new(notify);
        let next = Arc::new(AtomicUsize::new(0));
        let workers = cfg.threads.clamp(1, 512).min(cfg.targets.len().max(1));

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (cfg, nets, notify, next, cancel, tx) = (
                cfg.clone(),
                nets.clone(),
                notify.clone(),
                next.clone(),
                cancel.clone(),
                tx.clone(),
            );
            let spawned = thread::Builder::new()
                .name("scan-worker".into())
                .stack_size(512 * 1024)
                .spawn(move || loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ip) = cfg.targets.get(i) else { break };
                    let result = scan_host(ip, &cfg, &nets, &cancel);
                    if tx.send(ScanEvent::Host(result)).is_err() {
                        break;
                    }
                    notify();
                });
            match spawned {
                Ok(h) => handles.push(h),
                Err(_) => break, // plus de threads disponibles : on continue avec ceux créés
            }
        }
        for h in handles {
            let _ = h.join();
        }
        let _ = tx.send(ScanEvent::Finished {
            cancelled: cancel.load(Ordering::Relaxed),
        });
        notify();
    });

    handle
}

fn scan_host(ip: Ipv4Addr, cfg: &ScanConfig, nets: &[LocalNet], cancel: &AtomicBool) -> HostResult {
    let mut r = HostResult::new(ip);

    // 1. Ping ICMP
    if let Some(rtt) = sys::ping(ip, cfg.timeout) {
        r.detection = Some(Detection::Ping);
        r.rtt_ms = Some(rtt);
    }

    // 2. ARP (même segment uniquement) : MAC + détection des hôtes qui bloquent le ping
    let on_link = nets.iter().any(|n| n.contains(ip));
    if on_link && (r.is_up() || cfg.arp_discovery) && !cancel.load(Ordering::Relaxed) {
        if let Some(mac) = sys::arp(ip) {
            r.mac = Some(mac);
            r.detection.get_or_insert(Detection::Arp);
        }
    }

    // 3. Ports TCP
    if !cfg.ports.is_empty()
        && (r.is_up() || cfg.tcp_discovery)
        && !cancel.load(Ordering::Relaxed)
    {
        r.open_ports = scan_ports(ip, &cfg.ports, cfg.timeout, cancel);
        if !r.open_ports.is_empty() {
            r.detection.get_or_insert(Detection::Tcp);
        }
    }

    // 4. Nom d'hôte (DNS inverse, puis NetBIOS)
    if r.is_up() && cfg.resolve_names && !cancel.load(Ordering::Relaxed) {
        r.hostname = reverse_dns(ip);
        if r.hostname.is_none() || r.mac.is_none() {
            let nb_timeout = cfg.timeout.min(Duration::from_millis(800));
            if let Some((name, mac)) = netbios_query(ip, nb_timeout) {
                if r.hostname.is_none() {
                    r.hostname = Some(name);
                }
                if r.mac.is_none() {
                    r.mac = mac;
                }
            }
        }
    }

    r.scanned_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    r
}

fn scan_ports(ip: Ipv4Addr, ports: &[u16], timeout: Duration, cancel: &AtomicBool) -> Vec<u16> {
    let next = AtomicUsize::new(0);
    let open = Mutex::new(Vec::new());

    let work = || loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let i = next.fetch_add(1, Ordering::Relaxed);
        let Some(&port) = ports.get(i) else { break };
        let addr = SocketAddr::from((ip, port));
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            open.lock().unwrap().push(port);
        }
    };

    let mut spawned = 0;
    thread::scope(|s| {
        for _ in 0..ports.len().min(PORT_PARALLELISM) {
            if thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn_scoped(s, work)
                .is_err()
            {
                break;
            }
            spawned += 1;
        }
    });
    if spawned == 0 {
        work(); // repli séquentiel
    }

    let mut v = open.into_inner().unwrap();
    v.sort_unstable();
    v
}

fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()?;
    let name = name.trim_end_matches('.').to_string();
    if name.is_empty() || name.parse::<Ipv4Addr>().is_ok() {
        None
    } else {
        Some(name)
    }
}

/// Requête NetBIOS « NBSTAT » (UDP 137) : renvoie le nom de la machine et sa MAC.
fn netbios_query(ip: Ipv4Addr, timeout: Duration) -> Option<(String, Option<[u8; 6]>)> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;

    let mut q: Vec<u8> = vec![0x4E, 0x53, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x20];
    q.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // « * » encodé
    q.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]); // NBSTAT / IN
    sock.send_to(&q, (ip, 137)).ok()?;

    let mut buf = [0u8; 1024];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from.ip() != IpAddr::V4(ip) || n < 57 {
        return None;
    }
    let d = &buf[..n];

    // En-tête (12 octets) puis nom interrogé
    let mut off = 12;
    if d[off] & 0xC0 == 0xC0 {
        off += 2;
    } else {
        while off < n && d[off] != 0 {
            off += d[off] as usize + 1;
        }
        off += 1;
    }
    off += 2 + 2 + 4 + 2; // type, classe, TTL, longueur
    let count = *d.get(off)? as usize;
    off += 1;

    let mut name = None;
    for i in 0..count {
        let e = d.get(off + i * 18..off + i * 18 + 18)?;
        let suffix = e[15];
        let group = u16::from_be_bytes([e[16], e[17]]) & 0x8000 != 0;
        if suffix == 0x00 && !group {
            let s = String::from_utf8_lossy(&e[..15]).trim_end().to_string();
            if !s.is_empty() {
                name = Some(s);
                break;
            }
        }
    }
    let mac_off = off + count * 18;
    let mac = d
        .get(mac_off..mac_off + 6)
        .map(|m| [m[0], m[1], m[2], m[3], m[4], m[5]])
        .filter(|m| *m != [0u8; 6]);
    name.map(|n| (n, mac))
}

/// Envoie un « magic packet » Wake-on-LAN en broadcast.
pub fn wake_on_lan(mac: [u8; 6]) -> std::io::Result<()> {
    let mut pkt = vec![0xFFu8; 6];
    for _ in 0..16 {
        pkt.extend_from_slice(&mac);
    }
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.send_to(&pkt, "255.255.255.255:9")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// API Windows (iphlpapi) : ping ICMP sans droits admin + requête ARP
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[repr(C)]
    struct IpOptionInformation {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }

    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut c_void,
        options: IpOptionInformation,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> isize;
        fn IcmpCloseHandle(handle: isize) -> i32;
        fn IcmpSendEcho(
            handle: isize,
            destination: u32,
            request_data: *const c_void,
            request_size: u16,
            request_options: *const IpOptionInformation,
            reply_buffer: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn SendARP(dest_ip: u32, src_ip: u32, mac_addr: *mut c_void, phy_addr_len: *mut u32) -> u32;
    }

    /// Ping ICMP (même API que System.Net.NetworkInformation.Ping). Renvoie le RTT en ms.
    pub fn ping(ip: Ipv4Addr, timeout: Duration) -> Option<u32> {
        let dest = u32::from_ne_bytes(ip.octets());
        let payload = *b"abcdefghijklmnopqrstuvwabcdefghi"; // comme ping.exe
        let mut reply = [0u64; 64]; // 512 octets alignés
        let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        unsafe {
            let h = IcmpCreateFile();
            if h == -1 || h == 0 {
                return None;
            }
            let n = IcmpSendEcho(
                h,
                dest,
                payload.as_ptr() as *const c_void,
                payload.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr() as *mut c_void,
                std::mem::size_of_val(&reply) as u32,
                timeout_ms,
            );
            IcmpCloseHandle(h);
            if n == 0 {
                return None;
            }
            let r = &*(reply.as_ptr() as *const IcmpEchoReply);
            (r.status == 0 && r.address == dest).then_some(r.round_trip_time)
        }
    }

    /// Requête ARP (réseau local uniquement). Renvoie l'adresse MAC.
    pub fn arp(ip: Ipv4Addr) -> Option<[u8; 6]> {
        let mut buf = [0u32; 2];
        let mut len: u32 = 8;
        let rc = unsafe {
            SendARP(
                u32::from_ne_bytes(ip.octets()),
                0,
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        };
        if rc != 0 || len < 6 {
            return None;
        }
        let (a, b) = (buf[0].to_ne_bytes(), buf[1].to_ne_bytes());
        let mac = [a[0], a[1], a[2], a[3], b[0], b[1]];
        (mac != [0; 6] && mac != [0xFF; 6]).then_some(mac)
    }
}

#[cfg(not(windows))]
mod sys {
    use std::net::Ipv4Addr;
    use std::time::Duration;
    pub fn ping(_ip: Ipv4Addr, _timeout: Duration) -> Option<u32> {
        None
    }
    pub fn arp(_ip: Ipv4Addr) -> Option<[u8; 6]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_ip_range("192.168.1.0-254").unwrap().len(), 255);
        assert_eq!(parse_ip_range("10.0.0.1-10.0.0.50").unwrap().len(), 50);
        assert_eq!(parse_ip_range("192.168.1.0/24").unwrap().len(), 254);
        assert_eq!(parse_ip_range("10.0.0.5").unwrap().len(), 1);
        assert_eq!(parse_ip_range("10.0.0.1-3, 10.0.0.2 , 10.0.0.9").unwrap().len(), 4);
        assert_eq!(parse_ip_range("10.0.0.1 - 10.0.1.0").unwrap().len(), 256);
        assert!(parse_ip_range("10.0.0.9-3").is_err());
        assert!(parse_ip_range("10.0.0.0/8").is_err());
        assert!(parse_ip_range("abc").is_err());
    }

    #[test]
    fn messages() {
        let err = |s: &str| parse_ip_range(s).unwrap_err();
        assert_eq!(err("192.168.1.1-300"), "Octet invalide : 300 (0 à 255 attendu)");
        assert_eq!(err("192.168.1"), "Adresse incomplète : « 192.168.1 »");
        assert_eq!(err("10.0.0.0/33"), "Masque invalide : /33 (0 à 32 attendu)");
        assert_eq!(err("10.0.0.9-3"), "La fin de plage précède le début");
        assert_eq!(err("10.0.0.0/8"), "Trop d'adresses : 16\u{a0}777\u{a0}214 (65\u{a0}536 max)");
        assert_eq!(parse_ports("http").unwrap_err(), "Port invalide : « http »");
        assert_eq!(parse_ports("70000").unwrap_err(), "Port hors limites : « 70000 » (1 à 65 535)");
        assert_eq!(fmt_thousands(254), "254");
        assert_eq!(fmt_thousands(65536), "65\u{a0}536");
    }

    #[test]
    fn ports() {
        assert_eq!(parse_ports("22, 80,80;443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("8000-8002").unwrap(), vec![8000, 8001, 8002]);
        assert!(parse_ports("").unwrap().is_empty());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
    }

    /// Scan réel (non lancé par défaut) : `cargo test -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_scan() {
        let nets = local_networks();
        for n in &nets {
            println!("Interface : {} {} ({})", n.name, n.cidr(), n.ip);
        }
        let n = nets.first().expect("aucune interface");
        let base = u32::from(n.network());
        let mut targets: Vec<Ipv4Addr> = (1..=20).map(|i| Ipv4Addr::from(base + i)).collect();
        targets.push(n.ip);
        let cfg = ScanConfig {
            targets,
            ports: parse_ports(PORT_PRESETS[0].1).unwrap(),
            timeout: Duration::from_millis(500),
            threads: 50,
            resolve_names: true,
            arp_discovery: true,
            tcp_discovery: true,
        };
        let t = std::time::Instant::now();
        let h = start_scan(cfg, || {});
        loop {
            match h.rx.recv().unwrap() {
                ScanEvent::Host(r) if r.is_up() => println!(
                    "{:<16} {:<5} {:<30} {:<18} {:>4} ms  {}",
                    r.ip,
                    r.detection.unwrap().label(),
                    r.hostname.clone().unwrap_or_default(),
                    r.mac_string().unwrap_or_default(),
                    r.rtt_ms.map(|v| v.to_string()).unwrap_or("-".into()),
                    r.ports_string()
                ),
                ScanEvent::Host(_) => {}
                ScanEvent::Finished { .. } => break,
            }
        }
        println!("Durée : {:.1} s", t.elapsed().as_secs_f32());
    }

    #[test]
    fn host_lines() {
        let h = HostResult {
            ip: "192.168.1.10".parse().unwrap(),
            detection: Some(Detection::Arp),
            hostname: Some("nas\tsalon".into()),
            mac: Some([0x50, 0xA6, 0xD8, 0x01, 0x02, 0x03]),
            rtt_ms: Some(0),
            open_ports: vec![22, 443],
            scanned_at: "2026-11-14 10:00:00".into(),
        };
        let back = HostResult::from_line(&h.to_line()).unwrap();
        assert_eq!(back.ip, h.ip);
        assert_eq!(back.detection, h.detection);
        assert_eq!(back.hostname.as_deref(), Some("nas salon"));
        assert_eq!(back.mac, h.mac);
        assert_eq!(back.rtt_ms, Some(0));
        assert_eq!(back.open_ports, vec![22, 443]);
        assert_eq!(back.scanned_at, h.scanned_at);

        let down = HostResult::new("10.0.0.1".parse().unwrap());
        let back = HostResult::from_line(&down.to_line()).unwrap();
        assert!(!back.is_up() && back.mac.is_none() && back.open_ports.is_empty());
        assert!(HostResult::from_line("n'importe quoi").is_none());
    }

    #[test]
    fn vendors() {
        assert_eq!(mac_vendor(&[0x50, 0xA6, 0xD8, 0, 0, 0]), Some("Apple, Inc."));
        assert_eq!(mac_vendor(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]), Some("Adresse privée (aléatoire)"));
    }

    #[test]
    fn local_net() {
        let n = LocalNet {
            name: "x".into(),
            ip: "192.168.10.42".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
        };
        assert_eq!(n.cidr(), "192.168.10.0/24");
        assert_eq!(n.host_range(), "192.168.10.1-192.168.10.254");
        assert!(n.contains("192.168.10.200".parse().unwrap()));
        assert!(!n.contains("192.168.11.1".parse().unwrap()));
    }
}
