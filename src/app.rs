//! Fenêtre principale — d'après le design Claude Design « NetScan · egui ».

use crate::history::{self, Change};
use crate::icons::{self, Icon};
use crate::scanner::{
    self, fmt_thousands, Detection, HostResult, LocalNet, ScanConfig, ScanEvent, ScanHandle,
    EXPORT_HEADERS, PORT_PRESETS, WEB_PORTS,
};
use crate::theme::{self, mono, regular, semibold, stroke, Palette};
use crate::widgets::{self as w, Button, Input, Kind};
use eframe::egui::{
    self, pos2, text::LayoutJob, vec2, Align, Frame, Label, Layout, Margin, Rect, RichText,
    Rounding, Sense, TextFormat, Ui, UiBuilder, Vec2,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const SHORTCUTS: &str = "F5 Lancer · Échap Arrêter / désélectionner · Clic droit : actions";
const DETAILS_W: f32 = 316.0;

// ---------------------------------------------------------------------------
// Réglages mémorisés
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub range: String,
    pub ports: String,
    pub timeout_ms: u32,
    pub threads: usize,
    pub resolve_names: bool,
    pub arp_discovery: bool,
    pub tcp_discovery: bool,
    pub show_down: bool,
    pub dark_mode: bool,
    /// Fenêtre agrandie à la fermeture.
    pub maximized: bool,
    /// Taille et position de la fenêtre quand elle n'est pas agrandie (en points).
    pub win_size: Option<[f32; 2]>,
    pub win_pos: Option<[f32; 2]>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            range: String::new(),
            ports: PORT_PRESETS[0].1.to_string(),
            timeout_ms: 500,
            threads: 50,
            resolve_names: true,
            arp_discovery: true,
            tcp_discovery: true,
            show_down: false,
            dark_mode: false,
            maximized: false,
            win_size: None,
            win_pos: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Status,
    Ip,
    Hostname,
    Mac,
    Vendor,
    Rtt,
    Ports,
    Time,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MsgKind {
    Info,
    Spin,
    Ok,
    Warn,
    Err,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanEnd {
    Done,
    Cancelled,
}

enum Launch {
    Url(String),
    Rdp(Ipv4Addr),
    Smb(Ipv4Addr),
    Ssh(Ipv4Addr),
    PingT(Ipv4Addr),
    Tracert(Ipv4Addr),
    Wol([u8; 6]),
}

/// Actions déclenchées depuis l'interface, appliquées en fin d'image.
enum Act {
    Copy(String, String),
    Launch(Launch),
    Rescan(Ipv4Addr),
    Select(Ipv4Addr),
    /// Clic droit : la ligne sera sélectionnée à la fermeture du menu.
    MenuTarget(Ipv4Addr),
    Deselect,
    Sort(SortKey),
    ClearFilter,
    ShowInactive,
}

// ---------------------------------------------------------------------------
// Colonnes du tableau
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ColKind {
    Status,
    Ip,
    Name,
    Mac,
    Vendor,
    Rtt,
    Ports,
    Time,
}

impl ColKind {
    fn title(self) -> &'static str {
        match self {
            ColKind::Status => "Statut",
            ColKind::Ip => "Adresse IP",
            ColKind::Name => "Nom d'hôte",
            ColKind::Mac => "Adresse MAC",
            ColKind::Vendor => "Fabricant",
            ColKind::Rtt => "Latence",
            ColKind::Ports => "Ports ouverts",
            ColKind::Time => "Heure",
        }
    }
    fn sort_key(self) -> SortKey {
        match self {
            ColKind::Status => SortKey::Status,
            ColKind::Ip => SortKey::Ip,
            ColKind::Name => SortKey::Hostname,
            ColKind::Mac => SortKey::Mac,
            ColKind::Vendor => SortKey::Vendor,
            ColKind::Rtt => SortKey::Rtt,
            ColKind::Ports => SortKey::Ports,
            ColKind::Time => SortKey::Time,
        }
    }
}

struct Col {
    kind: ColKind,
    x: f32,
    w: f32,
}

/// Grille du design : 76 · 112 · flexible · 138 · 150 · 58 · 224 · 60.
/// Fenêtre moyenne : sans l'heure, ports resserrés. Étroit : sans MAC ni fabricant.
fn layout_columns(left: f32, width: f32, wide: bool) -> Vec<Col> {
    use ColKind::*;
    const FULL: [(ColKind, f32); 8] = [(Status, 76.0), (Ip, 112.0), (Name, 0.0), (Mac, 138.0), (Vendor, 150.0), (Rtt, 58.0), (Ports, 224.0), (Time, 60.0)];
    const MEDIUM: [(ColKind, f32); 7] = [(Status, 76.0), (Ip, 112.0), (Name, 0.0), (Mac, 138.0), (Vendor, 130.0), (Rtt, 58.0), (Ports, 160.0)];
    const NARROW: [(ColKind, f32); 5] = [(Status, 76.0), (Ip, 112.0), (Name, 0.0), (Rtt, 58.0), (Ports, 128.0)];
    let build = |defs: &[(ColKind, f32)]| {
        let fixed: f32 = defs.iter().map(|d| d.1).sum();
        let flex = width - 24.0 - 12.0 * (defs.len() as f32 - 1.0) - fixed;
        let mut x = left + 12.0;
        let mut cols = Vec::new();
        for &(kind, cw) in defs {
            let cw = if cw == 0.0 { flex.max(60.0) } else { cw };
            cols.push(Col { kind, x, w: cw });
            x += cw + 12.0;
        }
        (cols, flex)
    };
    if wide {
        let (cols, flex) = build(&FULL);
        if flex >= 140.0 {
            return cols;
        }
        let (cols, flex) = build(&MEDIUM);
        if flex >= 120.0 {
            return cols;
        }
    }
    build(&NARROW).0
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

pub struct NetScanApp {
    s: Settings,
    nets: Vec<LocalNet>,
    results: Vec<HostResult>,
    targets: Vec<Ipv4Addr>,
    view: Vec<usize>,
    view_dirty: bool,
    filter: String,
    sort: SortKey,
    sort_asc: bool,
    selected: Option<Ipv4Addr>,
    scroll_to: Option<usize>,
    scan: Option<ScanHandle>,
    /// Nouvelle analyse d'un seul hôte (clic droit), indépendante du scan principal.
    rescan: Option<(ScanHandle, Ipv4Addr)>,
    /// Écarts avec le scan précédent : appareils nouveaux ou disparus.
    changes: HashMap<Ipv4Addr, Change>,
    /// Scan précédent : hôtes actifs, et toutes les adresses qu'il avait analysées.
    prev_up: HashMap<Ipv4Addr, HostResult>,
    prev_seen: HashSet<Ipv4Addr>,
    /// Images affichées depuis le lancement (la fenêtre n'est suivie qu'une fois restaurée).
    frames: u32,
    stopping: bool,
    want_start: bool,
    toggle_theme: bool,
    total: usize,
    started: Option<Instant>,
    elapsed: Duration,
    end: Option<ScanEnd>,
    message: Option<(MsgKind, String)>,
    summary: Option<(MsgKind, String)>,
    range_cache: (String, Result<usize, String>),
    ports_cache: (String, Result<usize, String>),
    /// Un menu contextuel était ouvert à l'image précédente (Échap le ferme sans désélectionner).
    menu_open: std::cell::Cell<bool>,
    menu_target: Option<Ipv4Addr>,
    /// Horodatage de la dernière entrée clavier traitée (egui peut rejouer une image en 2 passes).
    last_input_time: f64,
    #[cfg(debug_assertions)]
    script: Option<crate::demo::Script>,
}

impl NetScanApp {
    pub fn new(cc: &eframe::CreationContext<'_>, cli_range: Option<String>, autostart: bool) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        theme::setup_fonts(&cc.egui_ctx);
        let stored: Option<Settings> = cc.storage.and_then(|st| eframe::get_value(st, eframe::APP_KEY));
        let first_run = stored.is_none();
        let mut s = stored.unwrap_or_default();
        if first_run {
            // Premier lancement : on suit le thème clair / sombre de Windows.
            s.dark_mode = crate::win::system_prefers_dark().unwrap_or(false);
        }
        restore_window(&cc.egui_ctx, &s);
        let nets = scanner::local_networks();
        if let Some(r) = cli_range {
            s.range = r;
        }
        if s.range.trim().is_empty() {
            s.range = nets
                .first()
                .map(|n| n.cidr())
                .unwrap_or_else(|| "192.168.1.0/24".into());
        }
        theme::apply(&cc.egui_ctx, s.dark_mode);

        let mut app = Self {
            s,
            nets,
            results: Vec::new(),
            targets: Vec::new(),
            view: Vec::new(),
            view_dirty: false,
            filter: String::new(),
            sort: SortKey::Ip,
            sort_asc: true,
            selected: None,
            scroll_to: None,
            scan: None,
            rescan: None,
            changes: HashMap::new(),
            prev_up: HashMap::new(),
            prev_seen: HashSet::new(),
            frames: 0,
            stopping: false,
            want_start: autostart,
            toggle_theme: false,
            total: 0,
            started: None,
            elapsed: Duration::ZERO,
            end: None,
            message: None,
            summary: None,
            range_cache: ("\0".into(), Ok(0)),
            ports_cache: ("\0".into(), Ok(0)),
            menu_open: std::cell::Cell::new(false),
            menu_target: None,
            last_input_time: -1.0,
            #[cfg(debug_assertions)]
            script: crate::demo::Script::from_env(),
        };
        app.load_last_scan();
        app
    }

    // -- Dernier scan (disque) ----------------------------------------------

    /// Recharge les résultats du dernier scan : ils restent consultables et servent
    /// de référence pour repérer les appareils nouveaux ou disparus au scan suivant.
    fn load_last_scan(&mut self) {
        let Some(saved) = history::load() else { return };
        if saved.rows.is_empty() {
            return;
        }
        let when = saved.rows.iter().map(|(h, _)| h.scanned_at.as_str()).max().unwrap_or("").to_string();
        self.total = saved.total.max(saved.rows.len());
        self.elapsed = Duration::from_millis(saved.elapsed_ms);
        self.end = Some(if saved.cancelled { ScanEnd::Cancelled } else { ScanEnd::Done });
        for (h, change) in saved.rows {
            if let Some(c) = change {
                self.changes.insert(h.ip, c);
            }
            self.results.push(h);
        }
        self.view_dirty = true;
        self.summary = Some((
            MsgKind::Info,
            format!("Résultats du dernier scan ({}) rechargés. F5 pour relancer et voir ce qui a changé.", date_fr(&when)),
        ));
    }

    fn save_last_scan(&self) {
        let rows = self.results.iter().map(|h| (h, self.changes.get(&h.ip).copied()));
        history::save(history::encode(
            self.total,
            self.elapsed.as_millis() as u64,
            self.end == Some(ScanEnd::Cancelled),
            rows,
        ));
    }

    fn is_gone(&self, h: &HostResult) -> bool {
        self.changes.get(&h.ip) == Some(&Change::Gone)
    }

    /// Compare un résultat au scan précédent. Un hôte disparu garde son nom et sa MAC connus.
    fn classify(&mut self, r: &mut HostResult) {
        if r.is_up() {
            if self.prev_seen.contains(&r.ip) && !self.prev_up.contains_key(&r.ip) {
                self.changes.insert(r.ip, Change::New);
            }
        } else if let Some(old) = self.prev_up.get(&r.ip) {
            r.hostname = old.hostname.clone();
            r.mac = old.mac;
            self.changes.insert(r.ip, Change::Gone);
        }
    }

    /// « 2 nouveaux, 1 disparu » (vide s'il n'y avait pas de scan précédent).
    fn changes_text(&self) -> String {
        if self.prev_seen.is_empty() {
            return String::new();
        }
        let new = self.changes.values().filter(|c| **c == Change::New).count();
        let gone = self.changes.len() - new;
        let mut parts = Vec::new();
        if new > 0 {
            parts.push(plural(new, "nouveau", "nouveaux"));
        }
        if gone > 0 {
            parts.push(plural(gone, "disparu", "disparus"));
        }
        if parts.is_empty() {
            " Aucun changement depuis le scan précédent.".into()
        } else {
            format!(" Depuis le scan précédent : {}.", parts.join(", "))
        }
    }

    /// Mémorise taille, position et état « agrandi » pour le prochain lancement.
    fn track_window(&mut self, ctx: &egui::Context) {
        self.frames = self.frames.saturating_add(1);
        if self.frames < 10 {
            return; // la restauration de la fenêtre n'est pas encore appliquée
        }
        let vp = ctx.input(|i| i.viewport().clone());
        if vp.minimized == Some(true) {
            return;
        }
        let maximized = vp.maximized.unwrap_or(false);
        self.s.maximized = maximized;
        if !maximized && vp.fullscreen != Some(true) {
            if let Some(r) = vp.inner_rect.filter(|r| r.width() >= 200.0 && r.height() >= 200.0) {
                self.s.win_size = Some([r.width(), r.height()]);
            }
            if let Some(r) = vp.outer_rect {
                self.s.win_pos = Some([r.left(), r.top()]);
            }
        }
    }

    // -- État dérivé --------------------------------------------------------

    fn range_status(&mut self) -> Result<usize, String> {
        if self.range_cache.0 != self.s.range {
            let r = scanner::parse_ip_range(&self.s.range).map(|v| v.len());
            self.range_cache = (self.s.range.clone(), r);
        }
        self.range_cache.1.clone()
    }

    fn ports_status(&mut self) -> Result<usize, String> {
        if self.ports_cache.0 != self.s.ports {
            let r = scanner::parse_ports(&self.s.ports).map(|v| v.len());
            self.ports_cache = (self.s.ports.clone(), r);
        }
        self.ports_cache.1.clone()
    }

    fn up_count(&self) -> usize {
        self.results.iter().filter(|h| h.is_up()).count()
    }

    fn selected_host(&self) -> Option<&HostResult> {
        let ip = self.selected?;
        self.results.iter().find(|h| h.ip == ip && h.is_up())
    }

    fn status_line(&self) -> (MsgKind, String) {
        if let Some(m) = &self.message {
            return m.clone();
        }
        if self.scan.is_some() {
            let up = self.up_count();
            return (
                MsgKind::Spin,
                format!(
                    "Scan en cours : {} / {} adresses · {}",
                    fmt_thousands(self.results.len() as u64),
                    fmt_thousands(self.total as u64),
                    plural(up, "hôte actif", "hôtes actifs")
                ),
            );
        }
        if let Err(e) = &self.range_cache.1 {
            return (MsgKind::Err, format!("Plage IP invalide : {}.", lower_first(e)));
        }
        if self.ports_cache.1.is_err() {
            return (MsgKind::Err, "Liste de ports invalide : corrigez-la pour lancer le scan.".into());
        }
        if let Some(s) = &self.summary {
            return s.clone();
        }
        (MsgKind::Info, "Prêt. Saisissez une plage IP puis lancez le scan (F5).".into())
    }

    fn count_label(&self) -> String {
        if self.results.is_empty() {
            return if self.scan.is_some() { "Recherche en cours…".into() } else { "Aucun résultat".into() };
        }
        let n = self.view.len();
        let mut s = if n > 1 {
            format!("{} lignes affichées", fmt_thousands(n as u64))
        } else {
            format!("{n} ligne affichée")
        };
        let hidden = self.results.iter().filter(|h| !h.is_up() && !self.is_gone(h)).count();
        if !self.s.show_down && hidden > 0 {
            s.push_str(&format!(" · {}", plural(hidden, "inactif masqué", "inactifs masqués")));
        }
        s
    }

    // -- Scan ---------------------------------------------------------------

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.scan.is_some() {
            return;
        }
        let targets = match scanner::parse_ip_range(&self.s.range) {
            Ok(t) => t,
            Err(e) => {
                self.message = Some((MsgKind::Err, format!("Plage IP invalide : {}.", lower_first(&e))));
                return;
            }
        };
        let ports = match scanner::parse_ports(&self.s.ports) {
            Ok(p) => p,
            Err(e) => {
                self.message = Some((MsgKind::Err, format!("Liste de ports invalide : {}.", lower_first(&e))));
                return;
            }
        };

        // Les résultats affichés deviennent la référence de comparaison.
        self.rescan = None;
        self.changes.clear();
        self.prev_seen = self.results.iter().map(|h| h.ip).collect();
        self.prev_up = self.results.drain(..).filter(|h| h.is_up()).map(|h| (h.ip, h)).collect();
        self.results.reserve(targets.len());
        self.view.clear();
        self.selected = None;
        self.total = targets.len();
        self.targets = targets.clone();
        self.started = Some(Instant::now());
        self.elapsed = Duration::ZERO;
        self.stopping = false;
        self.end = None;
        self.message = None;
        self.summary = None;

        let cfg = ScanConfig {
            targets,
            ports,
            timeout: Duration::from_millis(self.s.timeout_ms.max(50) as u64),
            threads: self.s.threads,
            resolve_names: self.s.resolve_names,
            arp_discovery: self.s.arp_discovery,
            tcp_discovery: self.s.tcp_discovery,
        };
        let ctx = ctx.clone();
        self.scan = Some(scanner::start_scan(cfg, move || ctx.request_repaint()));
    }

    fn stop_scan(&mut self) {
        if let Some(h) = &self.scan {
            h.cancel();
            self.stopping = true;
        }
    }

    /// Relance l'analyse d'un seul hôte avec les réglages courants.
    fn start_rescan(&mut self, ctx: &egui::Context, ip: Ipv4Addr) {
        if self.scan.is_some() {
            self.message = Some((MsgKind::Warn, "Un scan est en cours : attendez sa fin pour rescanner un hôte.".into()));
            return;
        }
        if self.rescan.is_some() {
            return;
        }
        let ports = match scanner::parse_ports(&self.s.ports) {
            Ok(p) => p,
            Err(e) => {
                self.message = Some((MsgKind::Err, format!("Liste de ports invalide : {}.", lower_first(&e))));
                return;
            }
        };
        let cfg = ScanConfig {
            targets: vec![ip],
            ports,
            timeout: Duration::from_millis(self.s.timeout_ms.max(50) as u64),
            threads: 1,
            resolve_names: self.s.resolve_names,
            arp_discovery: self.s.arp_discovery,
            tcp_discovery: self.s.tcp_discovery,
        };
        let ctx = ctx.clone();
        self.rescan = Some((scanner::start_scan(cfg, move || ctx.request_repaint()), ip));
        self.message = Some((MsgKind::Spin, format!("Nouvelle analyse de {ip}…")));
    }

    fn poll_rescan(&mut self) {
        let mut done = None;
        if let Some((h, _)) = &self.rescan {
            while let Some(ev) = h.try_recv() {
                if let ScanEvent::Host(r) = ev {
                    done = Some(r);
                }
            }
        }
        let Some(mut r) = done else { return };
        self.rescan = None;
        let Some(i) = self.results.iter().position(|h| h.ip == r.ip) else { return };
        let (old_name, old_mac) = (self.results[i].hostname.clone(), self.results[i].mac);
        let was_known = self.results[i].is_up() || self.is_gone(&self.results[i]);
        if r.hostname.is_none() {
            r.hostname = old_name;
        }
        if r.mac.is_none() {
            r.mac = old_mac;
        }
        self.message = Some(if r.is_up() {
            if self.is_gone(&r) {
                self.changes.remove(&r.ip);
            }
            (
                MsgKind::Ok,
                format!("{} rescanné : actif, {}.", r.ip, plural(r.open_ports.len(), "port ouvert", "ports ouverts")),
            )
        } else {
            if was_known {
                self.changes.insert(r.ip, Change::Gone);
            }
            (MsgKind::Warn, format!("{} rescanné : ne répond plus.", r.ip))
        });
        self.results[i] = r;
        self.view_dirty = true;
        self.save_last_scan();
    }

    fn poll_scan(&mut self) {
        self.poll_rescan();
        let mut finished = None;
        let mut received = Vec::new();
        if let Some(h) = &self.scan {
            while let Some(ev) = h.try_recv() {
                match ev {
                    ScanEvent::Host(r) => received.push(r),
                    ScanEvent::Finished { cancelled } => finished = Some(cancelled),
                }
            }
        }
        for mut r in received {
            self.classify(&mut r);
            self.results.push(r);
            self.view_dirty = true;
        }
        if let (Some(start), true) = (self.started, self.scan.is_some()) {
            self.elapsed = start.elapsed();
        }
        if let Some(cancelled) = finished {
            self.scan = None;
            self.stopping = false;
            let up = self.up_count();
            let ports: usize = self.results.iter().map(|h| h.open_ports.len()).sum();
            if cancelled {
                self.end = Some(ScanEnd::Cancelled);
                self.summary = Some((
                    MsgKind::Warn,
                    format!(
                        "Scan interrompu à {} / {} : {} trouvés.",
                        fmt_thousands(self.results.len() as u64),
                        fmt_thousands(self.total as u64),
                        plural(up, "hôte actif", "hôtes actifs")
                    ),
                ));
            } else {
                self.end = Some(ScanEnd::Done);
                self.summary = Some((
                    MsgKind::Ok,
                    format!(
                        "Scan terminé en {} s : {}, {}.{}",
                        secs_fr(self.elapsed),
                        plural(up, "hôte actif", "hôtes actifs"),
                        plural(ports, "port ouvert", "ports ouverts"),
                        self.changes_text()
                    ),
                ));
            }
            self.message = None;
            self.save_last_scan();
        }
    }

    // -- Vue (filtre + tri) -------------------------------------------------

    fn rebuild_view(&mut self) {
        let f = self.filter.trim().to_lowercase();
        let r = &self.results;
        let changes = &self.changes;
        // « nouveau » / « disparu » dans le filtre ciblent les écarts avec le scan précédent.
        let change_match = |h: &HostResult| {
            f.len() >= 3
                && match changes.get(&h.ip) {
                    Some(Change::New) => "nouveaux".starts_with(f.as_str()),
                    Some(Change::Gone) => "disparus".starts_with(f.as_str()),
                    None => false,
                }
        };
        let mut v: Vec<usize> = (0..r.len())
            .filter(|&i| {
                let h = &r[i];
                (self.s.show_down || h.is_up() || changes.get(&h.ip) == Some(&Change::Gone))
                    && (f.is_empty() || matches_filter(h, &f) || change_match(h))
            })
            .collect();
        // Actifs (ping, ARP, TCP), puis disparus, puis inactifs.
        let rank = |h: &HostResult| match h.detection {
            Some(_) => Detection::rank(h.detection),
            None if changes.get(&h.ip) == Some(&Change::Gone) => 3,
            None => 4,
        };
        let (key, asc) = (self.sort, self.sort_asc);
        v.sort_by(|&a, &b| {
            let (x, y) = (&r[a], &r[b]);
            let ord = match key {
                SortKey::Status => rank(x).cmp(&rank(y)),
                SortKey::Vendor => {
                    let (vx, vy) = (x.vendor().map(str::to_lowercase), y.vendor().map(str::to_lowercase));
                    (vx.is_none(), vx).cmp(&(vy.is_none(), vy))
                }
                SortKey::Ip => std::cmp::Ordering::Equal,
                SortKey::Hostname => (x.hostname.is_none(), x.hostname.as_deref().map(str::to_lowercase))
                    .cmp(&(y.hostname.is_none(), y.hostname.as_deref().map(str::to_lowercase))),
                SortKey::Mac => (x.mac.is_none(), x.mac).cmp(&(y.mac.is_none(), y.mac)),
                SortKey::Rtt => (x.rtt_ms.is_none(), x.rtt_ms).cmp(&(y.rtt_ms.is_none(), y.rtt_ms)),
                SortKey::Ports => y.open_ports.len().cmp(&x.open_ports.len()),
                SortKey::Time => x.scanned_at.cmp(&y.scanned_at),
            }
            .then_with(|| u32::from(x.ip).cmp(&u32::from(y.ip)));
            if asc {
                ord
            } else {
                ord.reverse()
            }
        });
        self.view = v;
        self.view_dirty = false;
    }

    fn move_selection(&mut self, delta: i32) {
        let ups: Vec<usize> = (0..self.view.len()).filter(|&k| self.results[self.view[k]].is_up()).collect();
        if ups.is_empty() {
            return;
        }
        let cur = self
            .selected
            .and_then(|ip| ups.iter().position(|&k| self.results[self.view[k]].ip == ip));
        let next = match cur {
            None => if delta > 0 { 0 } else { ups.len() - 1 },
            Some(c) => (c as i32 + delta).clamp(0, ups.len() as i32 - 1) as usize,
        };
        let k = ups[next];
        self.selected = Some(self.results[self.view[k]].ip);
        self.scroll_to = Some(k);
    }

    fn view_as_tsv(&self) -> String {
        let mut out = EXPORT_HEADERS.join("\t");
        out.push('\n');
        for &i in &self.view {
            out.push_str(&self.results[i].export_fields().join("\t"));
            out.push('\n');
        }
        out
    }

    fn export_csv(&mut self) {
        let name = format!("netscan_{}.csv", chrono::Local::now().format("%Y-%m-%d_%H%M"));
        let Some(path) = rfd::FileDialog::new()
            .set_title("Exporter les résultats")
            .add_filter("CSV (séparateur ;)", &["csv"])
            .set_file_name(name)
            .save_file()
        else {
            return;
        };
        let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let mut out = String::from("\u{feff}");
        out.push_str(&EXPORT_HEADERS.map(quote).join(";"));
        out.push_str("\r\n");
        for &i in &self.view {
            let fields = self.results[i].export_fields();
            out.push_str(&fields.iter().map(|f| quote(f)).collect::<Vec<_>>().join(";"));
            out.push_str("\r\n");
        }
        self.message = Some(match std::fs::write(&path, out) {
            Ok(()) => (MsgKind::Ok, format!("Export CSV enregistré : {}", path.display())),
            Err(e) => (MsgKind::Err, format!("Export échoué : {e}")),
        });
    }

    fn clear_results(&mut self) {
        self.results.clear();
        self.changes.clear();
        self.rescan = None;
        history::delete();
        self.view.clear();
        self.targets.clear();
        self.selected = None;
        self.total = 0;
        self.elapsed = Duration::ZERO;
        self.started = None;
        self.end = None;
        self.summary = None;
        self.message = Some((MsgKind::Info, "Résultats effacés.".into()));
    }

    fn apply_act(&mut self, ctx: &egui::Context, act: Act) {
        match act {
            Act::Copy(text, msg) => {
                ctx.copy_text(text);
                self.message = Some((MsgKind::Ok, msg));
            }
            Act::Launch(l) => self.launch(l),
            Act::Rescan(ip) => self.start_rescan(ctx, ip),
            Act::Select(ip) => {
                self.selected = Some(ip);
                self.menu_target = None;
            }
            Act::MenuTarget(ip) => self.menu_target = Some(ip),
            Act::Deselect => self.selected = None,
            Act::Sort(k) => {
                if self.sort == k {
                    self.sort_asc = !self.sort_asc;
                } else {
                    self.sort = k;
                    self.sort_asc = true;
                }
                self.view_dirty = true;
            }
            Act::ClearFilter => {
                self.filter.clear();
                self.view_dirty = true;
            }
            Act::ShowInactive => {
                self.s.show_down = true;
                self.view_dirty = true;
            }
        }
        ctx.request_repaint();
    }

    fn launch(&mut self, l: Launch) {
        let res = match l {
            Launch::Url(url) => launch("cmd", &["/C", "start", "", &url]),
            Launch::Rdp(ip) => launch("mstsc", &[&format!("/v:{ip}")]),
            Launch::Smb(ip) => launch("explorer.exe", &[&format!(r"\\{ip}")]),
            Launch::Ssh(ip) => console(&["ssh", &ip.to_string()]),
            Launch::PingT(ip) => console(&["ping", "-t", &ip.to_string()]),
            Launch::Tracert(ip) => console(&["tracert", &ip.to_string()]),
            Launch::Wol(mac) => scanner::wake_on_lan(mac).map(|()| {
                self.message = Some((
                    MsgKind::Ok,
                    format!("Paquet Wake-on-LAN envoyé à {}.", scanner::format_mac(&mac)),
                ));
            }),
        };
        if let Err(e) = res {
            self.message = Some((MsgKind::Err, format!("Action impossible : {e}")));
        }
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        // Une seule fois par image, même si egui exécute une seconde passe.
        let time = ctx.input(|i| i.time);
        if time == self.last_input_time {
            return;
        }
        self.last_input_time = time;
        let typing = ctx.wants_keyboard_input();
        let (f5, esc, copy, shift, up, down) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::F5),
                i.key_pressed(egui::Key::Escape),
                i.events.iter().any(|e| matches!(e, egui::Event::Copy))
                    || (i.modifiers.command && i.key_pressed(egui::Key::C)),
                i.modifiers.shift,
                i.key_pressed(egui::Key::ArrowUp),
                i.key_pressed(egui::Key::ArrowDown),
            )
        });
        if f5 && self.scan.is_none() {
            self.want_start = true;
        }
        if esc {
            if self.scan.is_some() {
                self.stop_scan();
            } else if !typing && !self.menu_open.get() {
                self.selected = None;
            }
        }
        if typing {
            return;
        }
        if copy {
            if let Some(h) = self.selected_host() {
                let act = if shift {
                    Act::Copy(h.export_fields().join("\t"), "Ligne copiée dans le presse-papiers.".into())
                } else {
                    Act::Copy(h.ip.to_string(), format!("Adresse IP copiée : {}", h.ip))
                };
                self.apply_act(ctx, act);
            }
        }
        if up || down {
            self.move_selection(if down { 1 } else { -1 });
        }
    }

    // =======================================================================
    // Barre d'état
    // =======================================================================

    fn status_bar(&self, ctx: &egui::Context, p: &'static Palette) {
        let (kind, text) = self.status_line();
        let (bg, fg, icon) = match kind {
            MsgKind::Info => (p.sidebar, p.accent_text, Some(&icons::INFO)),
            MsgKind::Spin => (p.sidebar, p.accent_text, None),
            MsgKind::Ok => (p.ok_soft, p.ok, Some(&icons::CHECK_CIRCLE)),
            MsgKind::Warn => (p.warn_soft, p.warn, Some(&icons::WARNING)),
            MsgKind::Err => (p.err_soft, p.err, Some(&icons::X_CIRCLE)),
        };
        egui::TopBottomPanel::bottom("status")
            .exact_height(28.0)
            .frame(Frame::none().fill(bg).inner_margin(Margin::symmetric(12.0, 0.0)))
            .show(ctx, |ui| {
                let rect = ui.max_rect();
                let cy = rect.center().y;
                let ir = w::icon_rect(rect.left(), cy, 14.0);
                match icon {
                    Some(ic) => icons::paint(ui, ic, ir, fg),
                    None => egui::Spinner::new().size(14.0).color(fg).paint_at(ui, ir),
                }
                let sg = w::galley(ui, SHORTCUTS, regular(12.0), p.text3);
                let sw = sg.size().x;
                let show_shortcuts = rect.width() > sw + 360.0;
                if show_shortcuts {
                    w::text_at(ui.painter(), sg, rect.right() - sw, cy);
                }
                let max = rect.width() - 22.0 - if show_shortcuts { sw + 16.0 } else { 0.0 };
                let g = w::galley_trunc(ui, &text, regular(12.0), p.text, max);
                w::text_at(ui.painter(), g, rect.left() + 22.0, cy);
            });
    }

    // =======================================================================
    // Panneau de paramètres (gauche)
    // =======================================================================

    fn sidebar(&mut self, ctx: &egui::Context, p: &'static Palette) {
        egui::SidePanel::left("sidebar")
            .exact_width(300.0)
            .resizable(false)
            .frame(Frame::none().fill(p.sidebar))
            .show(ctx, |ui| {
                egui::TopBottomPanel::top("sidebar_head")
                    .frame(Frame::none().fill(p.sidebar).inner_margin(Margin { left: 16.0, right: 12.0, top: 12.0, bottom: 12.0 }))
                    .show_inside(ui, |ui| self.sidebar_head(ui, p));
                egui::TopBottomPanel::bottom("sidebar_foot")
                    .frame(Frame::none().fill(p.sidebar).inner_margin(Margin { left: 16.0, right: 16.0, top: 12.0, bottom: 16.0 }))
                    .show_inside(ui, |ui| self.sidebar_foot(ui, p));
                egui::CentralPanel::default()
                    .frame(Frame::none().fill(p.sidebar))
                    .show_inside(ui, |ui| {
                        egui::ScrollArea::vertical().id_salt("sidebar_scroll").auto_shrink(false).show(ui, |ui| {
                            Frame::none()
                                .inner_margin(Margin { left: 16.0, right: 16.0, top: 14.0, bottom: 14.0 })
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    self.sidebar_body(ui, p);
                                });
                        });
                    });
            });
    }

    fn sidebar_head(&mut self, ui: &mut Ui, p: &'static Palette) {
        // L'en-tête sert aussi de poignée pour déplacer la fenêtre.
        window_drag(ui, ui.max_rect().expand2(vec2(16.0, 12.0)), "drag_sidebar");
        ui.style_mut().interaction.selectable_labels = false;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let (r, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
            w::paint_logo(ui.painter(), r, p.accent);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                w::label(ui, "NetScan", semibold(15.0), p.text);
                w::label(ui, "Scanner réseau IP", regular(11.0), p.text3);
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (icon, tip) = if self.s.dark_mode {
                    (&icons::SUN, "Passer au thème clair")
                } else {
                    (&icons::MOON, "Passer au thème sombre")
                };
                let r = Button::new(Kind::Secondary, "").icon(icon).icon_size(16.0).size(32.0, 32.0).show(ui, p);
                if r.on_hover_text(tip).clicked() {
                    self.toggle_theme = true;
                }
            });
        });
    }

    fn sidebar_body(&mut self, ui: &mut Ui, p: &'static Palette) {
        let running = self.scan.is_some();
        let range_st = self.range_status();
        let ports_st = self.ports_status();
        let full_w = ui.available_width();
        ui.spacing_mut().item_spacing.y = 6.0;

        if running {
            lock_banner(ui, p);
            ui.add_space(10.0);
        }

        ui.scope(|ui| {
            // Les champs verrouillés s'estompent vers le fond du panneau.
            ui.visuals_mut().widgets.noninteractive.weak_bg_fill = p.sidebar;
            ui.add_enabled_ui(!running, |ui| {
                // --- Plage IP ---
                w::field_label(ui, p, "Plage IP");
                let out = w::input(
                    ui,
                    p,
                    Input {
                        text: &mut self.s.range,
                        id: "range",
                        hint: "192.168.1.0/24, 10.0.0.1-50",
                        width: full_w,
                        height: 34.0,
                        mono: true,
                        error: range_st.is_err(),
                        search: false,
                        clearable: false,
                        highlight: false,
                    },
                );
                if out.response.changed() {
                    self.message = None;
                }
                if out.submitted {
                    self.want_start = true;
                }
                match &range_st {
                    Ok(n) => hint_line(ui, p, Some((&icons::CHECK, p.ok)), &format!("{} à analyser", plural(*n, "adresse", "adresses")), p.text3),
                    Err(e) => hint_line(ui, p, Some((&icons::ALERT_CIRCLE, p.err)), e, p.err),
                }
                ui.add_space(10.0);

                // --- Réseaux de ce PC ---
                w::field_label(ui, p, "Réseaux de ce PC");
                let mut picked: Option<String> = None;
                let mut refresh = false;
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let current = self
                        .nets
                        .iter()
                        .find(|n| n.cidr() == self.s.range.trim() || n.host_range() == self.s.range.trim());
                    let selected_text = match current {
                        Some(n) => RichText::new(format!("{} — {}", n.cidr(), n.name)).font(regular(13.0)).color(p.text),
                        None => RichText::new("Choisir un réseau…").font(regular(13.0)).color(p.text),
                    };
                    let nets = &self.nets;
                    combo(ui, p, "nets", full_w - 40.0, 34.0, selected_text, |ui| {
                        if nets.is_empty() {
                            w::label(ui, "Aucune interface IPv4 détectée", regular(12.5), p.text3);
                        }
                        for n in nets {
                            let mut job = LayoutJob::default();
                            job.append(&n.cidr(), 0.0, TextFormat::simple(mono(12.5), p.text));
                            job.append(&format!(" — {}", n.name), 0.0, TextFormat::simple(regular(13.0), p.text));
                            let is_sel = current.is_some_and(|c| c.cidr() == n.cidr());
                            let r = ui
                                .selectable_label(is_sel, job)
                                .on_hover_text(format!("Adresse de ce PC : {}", n.ip));
                            if r.clicked() {
                                picked = Some(n.cidr());
                            }
                        }
                    });
                    let r = Button::new(Kind::Secondary, "").icon(&icons::REFRESH).icon_size(15.0).size(34.0, 34.0).show(ui, p);
                    if r.on_hover_text("Rafraîchir la liste des réseaux").clicked() {
                        refresh = true;
                    }
                });
                if let Some(r) = picked {
                    self.s.range = r;
                    self.message = None;
                }
                if refresh {
                    self.nets = scanner::local_networks();
                    self.message = Some((
                        MsgKind::Info,
                        format!("{} détecté(s).", plural(self.nets.len(), "réseau", "réseaux")),
                    ));
                }
                ui.add_space(10.0);

                // --- Ports TCP ---
                let current_preset = preset_name(&self.s.ports);
                let mut chosen: Option<&'static str> = None;
                ui.horizontal(|ui| {
                    w::field_label(ui, p, "Ports TCP");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let gw = w::galley(ui, current_preset, regular(12.0), p.text2).size().x;
                        ui.scope(|ui| {
                            ui.visuals_mut().widgets.inactive.weak_bg_fill = p.surface;
                            ui.visuals_mut().widgets.inactive.bg_stroke = stroke(1.0, p.border);
                            combo(
                                ui,
                                p,
                                "presets",
                                gw + 40.0,
                                26.0,
                                RichText::new(current_preset).font(regular(12.0)).color(p.text2),
                                |ui| {
                                    for (name, list) in PORT_PRESETS {
                                        if ui.selectable_label(*name == current_preset, *name).on_hover_text(*list).clicked() {
                                            chosen = Some(list);
                                        }
                                    }
                                },
                            );
                        });
                    });
                });
                if let Some(list) = chosen {
                    self.s.ports = list.to_string();
                    self.message = None;
                }
                let out = w::input(
                    ui,
                    p,
                    Input {
                        text: &mut self.s.ports,
                        id: "ports",
                        hint: "Vide = ping seul",
                        width: full_w,
                        height: 34.0,
                        mono: true,
                        error: ports_st.is_err(),
                        search: false,
                        clearable: false,
                        highlight: false,
                    },
                );
                if out.response.changed() {
                    self.message = None;
                }
                if out.submitted {
                    self.want_start = true;
                }
                // Liste plus longue que le champ : on la montre en entier au survol.
                if self.s.ports.len() > 30 && !out.response.has_focus() {
                    let full = self.s.ports.split(',').map(str::trim).collect::<Vec<_>>().join(", ");
                    out.response.on_hover_text(full);
                }
                match &ports_st {
                    Ok(0) => hint_line(ui, p, None, "Aucun port : ping seul", p.text3),
                    Ok(n) => hint_line(ui, p, None, &format!("{} · vide = ping seul", plural(*n, "port", "ports")), p.text3),
                    Err(e) => hint_line(ui, p, Some((&icons::ALERT_CIRCLE, p.err)), e, p.err),
                }
                ui.add_space(10.0);

                // --- Timeout / Threads ---
                let col_w = ((full_w - 16.0) / 2.0).floor();
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    let mut t = self.s.timeout_ms as f64;
                    ui.allocate_ui_with_layout(vec2(col_w, 44.0), Layout::top_down(Align::Min), |ui| {
                        ui.set_width(col_w);
                        slider_block(ui, p, "Timeout", " ms", &mut t, 50.0..=5000.0, 50.0);
                    });
                    self.s.timeout_ms = t.round() as u32;
                    let mut th = self.s.threads as f64;
                    ui.allocate_ui_with_layout(vec2(col_w, 44.0), Layout::top_down(Align::Min), |ui| {
                        ui.set_width(col_w);
                        slider_block(ui, p, "Threads", "", &mut th, 1.0..=256.0, 1.0);
                    });
                    self.s.threads = th.round() as usize;
                });
                ui.add_space(10.0);

                // --- Détection ---
                let y = ui.cursor().top();
                ui.painter().hline(ui.max_rect().x_range(), y, stroke(1.0, p.border));
                ui.add_space(12.0);
                w::field_label(ui, p, "Détection");
                ui.add_space(4.0);
                option_row(ui, p, &mut self.s.resolve_names, "Résoudre les noms (DNS + NetBIOS)", None);
                ui.add_space(4.0);
                option_row(ui, p, &mut self.s.arp_discovery, "Découverte ARP (réseau local)", Some("trouve les hôtes qui ignorent le ping"));
                ui.add_space(4.0);
                option_row(ui, p, &mut self.s.tcp_discovery, "Découverte TCP (hôtes sans ping)", Some("sonde les ports des adresses muettes"));
            });
        });
    }

    fn sidebar_foot(&mut self, ui: &mut Ui, p: &'static Palette) {
        let running = self.scan.is_some();
        let can = self.range_status().is_ok() && self.ports_status().is_ok();
        let width = ui.available_width();
        let button = if running {
            Button::new(Kind::Danger, if self.stopping { "Arrêt en cours…" } else { "Arrêter le scan" })
                .icon(&icons::STOP)
                .kbd("Échap")
                .enabled(!self.stopping)
        } else {
            Button::new(Kind::Primary, "Lancer le scan").icon(&icons::PLAY).kbd("F5").enabled(can)
        };
        let resp = button.size(width, 40.0).font(semibold(14.0)).show(ui, p);
        let resp = if !running && !can {
            resp.on_hover_text("Corrigez la plage IP ou la liste de ports pour lancer le scan.")
        } else {
            resp
        };
        if resp.clicked() {
            if running {
                self.stop_scan();
            } else {
                self.want_start = true;
            }
        }
    }

    // =======================================================================
    // Zone principale
    // =======================================================================

    fn main_area(&mut self, ui: &mut Ui, p: &'static Palette, acts: &mut Vec<Act>) {
        ui.spacing_mut().item_spacing = vec2(12.0, 12.0);
        self.stats(ui, p);
        self.progress(ui, p);
        self.toolbar(ui, p, acts);

        let rect = ui.available_rect_before_wrap();
        let selected = self.selected_host().cloned();
        let (table_rect, panel_rect) = if selected.is_some() && rect.width() > DETAILS_W + 360.0 {
            (
                Rect::from_min_max(rect.min, pos2(rect.right() - DETAILS_W - 12.0, rect.bottom())),
                Some(Rect::from_min_max(pos2(rect.right() - DETAILS_W, rect.top()), rect.max)),
            )
        } else {
            (rect, None)
        };
        let wide = panel_rect.is_none();
        ui.allocate_new_ui(UiBuilder::new().max_rect(table_rect), |ui| self.table(ui, p, acts, wide));
        if let (Some(h), Some(pr)) = (selected, panel_rect) {
            ui.allocate_new_ui(UiBuilder::new().max_rect(pr), |ui| self.details(ui, p, &h, acts));
        }
    }

    fn stats(&self, ui: &mut Ui, p: &'static Palette) {
        let width = ui.available_width();
        let cw = ((width - 36.0) / 4.0).floor();
        let (row, _) = ui.allocate_exact_size(vec2(width, 72.0), Sense::hover());
        let up = self.up_count();
        let ports: usize = self.results.iter().map(|h| h.open_ports.len()).sum();
        let total = if self.total > 0 {
            fmt_thousands(self.total as u64)
        } else {
            match &self.range_cache.1 {
                Ok(n) => fmt_thousands(*n as u64),
                Err(_) => "—".into(),
            }
        };
        let cards = [
            ("Adresses analysées", fmt_thousands(self.results.len() as u64), format!("/ {total}"), false),
            ("Hôtes actifs", up.to_string(), if up > 0 { "en ligne".into() } else { String::new() }, up > 0),
            ("Ports ouverts", ports.to_string(), if up > 0 { "au total".into() } else { String::new() }, false),
            ("Durée écoulée", secs_fr(self.elapsed), "s".into(), false),
        ];
        for (i, (label, value, sub, dot)) in cards.iter().enumerate() {
            let x = row.left() + i as f32 * (cw + 12.0);
            let cw = if i == 3 { row.right() - x } else { cw };
            let r = Rect::from_min_size(pos2(x, row.top()), vec2(cw, 72.0));
            paint_stat(ui, p, r, label, value, sub, *dot);
        }
    }

    fn progress(&self, ui: &mut Ui, p: &'static Palette) {
        let width = ui.available_width();
        let (row, _) = ui.allocate_exact_size(vec2(width, 20.0), Sense::hover());
        let painter = ui.painter();
        let cy = row.center().y;
        let track = Rect::from_min_max(pos2(row.left(), cy - 3.0), pos2(row.right() - 56.0, cy + 3.0));
        painter.rect_filled(track, 3.0, p.track);
        let running = self.scan.is_some();
        if self.total > 0 {
            let frac = (self.results.len() as f32 / self.total as f32).clamp(0.0, 1.0);
            let color = if running {
                p.accent
            } else if self.end == Some(ScanEnd::Cancelled) {
                p.warn
            } else {
                p.ok
            };
            if frac > 0.0 {
                let fill = Rect::from_min_size(track.min, vec2((track.width() * frac).max(6.0), 6.0));
                painter.rect_filled(fill, 3.0, color);
            }
            let g = w::galley(ui, format!("{} %", (frac * 100.0).floor() as u32), regular(12.0), p.text2);
            w::text_at(painter, g.clone(), row.right() - g.size().x, cy);
        }
    }

    fn toolbar(&mut self, ui: &mut Ui, p: &'static Palette, acts: &mut Vec<Act>) {
        let has_rows = !self.view.is_empty();
        let running = self.scan.is_some();
        let can_clear = !self.results.is_empty() && !running;
        let width = ui.available_width();
        let filter_on = !self.filter.trim().is_empty();
        ui.allocate_ui_with_layout(vec2(width, 34.0), Layout::right_to_left(Align::Center), |ui| {
            ui.set_min_size(vec2(width, 34.0));
            ui.spacing_mut().item_spacing.x = 8.0;
            let r = Button::new(Kind::Secondary, "").icon(&icons::TRASH).size(30.0, 30.0).enabled(can_clear).show(ui, p);
            if r.on_hover_text("Effacer les résultats").clicked() {
                self.clear_results();
            }
            let r = Button::new(Kind::Secondary, "Exporter CSV").icon(&icons::DOWNLOAD).enabled(has_rows).show(ui, p);
            if r.on_hover_text("Exporter les lignes affichées (séparateur « ; », compatible Excel)").clicked() {
                self.export_csv();
            }
            let r = Button::new(Kind::Secondary, "Copier").icon(&icons::COPY).enabled(has_rows).show(ui, p);
            if r.on_hover_text("Copier le tableau affiché, prêt à coller dans Excel").clicked() {
                let n = self.view.len();
                acts.push(Act::Copy(
                    self.view_as_tsv(),
                    format!("Tableau copié dans le presse-papiers : {}, prêt à coller dans Excel.", plural(n, "ligne", "lignes")),
                ));
            }
            ui.add_space(4.0);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                let out = w::input(
                    ui,
                    p,
                    Input {
                        text: &mut self.filter,
                        id: "filter",
                        hint: "Filtrer : IP, nom, MAC, port, service",
                        width: 280.0,
                        height: 34.0,
                        mono: false,
                        error: false,
                        search: true,
                        clearable: true,
                        highlight: filter_on,
                    },
                );
                if out.cleared {
                    self.filter.clear();
                }
                if out.cleared || out.response.changed() {
                    self.view_dirty = true;
                }
                if w::checkbox(ui, p, &mut self.s.show_down, "Afficher les inactifs").changed() {
                    self.view_dirty = true;
                }
                let count = self.count_label();
                ui.add(Label::new(RichText::new(count).font(regular(12.0)).color(p.text3)).truncate());
            });
        });
    }

    // -- Tableau ------------------------------------------------------------

    fn table(&self, ui: &mut Ui, p: &'static Palette, acts: &mut Vec<Act>, wide: bool) {
        let rect = ui.max_rect();
        ui.painter().rect_filled(rect, 8.0, p.surface);
        let inner = rect.shrink(1.0);
        let cols = layout_columns(inner.left(), inner.width(), wide);

        // En-tête
        let header = Rect::from_min_size(inner.min, vec2(inner.width(), 32.0));
        let painter = ui.painter();
        painter.rect_filled(header, Rounding { nw: 7.0, ne: 7.0, sw: 0.0, se: 0.0 }, p.surface2);
        painter.hline(header.x_range(), header.bottom() - 0.5, stroke(1.0, p.border));
        let cy = header.center().y;
        for c in &cols {
            let key = c.kind.sort_key();
            let sorted = self.sort == key;
            let hit = Rect::from_min_size(pos2(c.x - 6.0, header.top()), vec2(c.w + 12.0, 32.0));
            let resp = ui.interact(hit, ui.id().with(("col", c.kind)), Sense::click());
            let color = if sorted { p.accent_text } else if resp.hovered() { p.text } else { p.text2 };
            let g = w::galley(ui, c.kind.title(), semibold(12.0), color);
            let gw = g.size().x;
            let full = gw + if sorted { 16.0 } else { 0.0 };
            let x = if c.kind == ColKind::Rtt { c.x + c.w - full } else { c.x };
            w::text_at(ui.painter(), g, x, cy);
            if sorted {
                let ic = if self.sort_asc { &icons::CHEVRON_UP } else { &icons::CHEVRON_DOWN_BOLD };
                icons::paint(ui, ic, w::icon_rect(x + gw + 4.0, cy, 12.0), color);
            }
            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                acts.push(Act::Sort(key));
            }
        }

        // Corps
        let body = Rect::from_min_max(pos2(inner.left(), header.bottom()), inner.max);
        let running = self.scan.is_some();
        ui.allocate_new_ui(UiBuilder::new().max_rect(body), |ui| {
            ui.set_clip_rect(body.intersect(ui.clip_rect()));
            if self.view.is_empty() && !running {
                self.empty_state(ui, p, acts, body);
                return;
            }
            ui.spacing_mut().item_spacing.y = 0.0;
            let n = self.view.len() + usize::from(running);
            let mut area = egui::ScrollArea::vertical().id_salt("rows").auto_shrink(false);
            if let Some(k) = self.scroll_to {
                let id = ui.make_persistent_id("rows");
                let cur = egui::scroll_area::State::load(ui.ctx(), id).map_or(0.0, |s| s.offset.y);
                let (top, bottom) = (k as f32 * 32.0, k as f32 * 32.0 + 32.0);
                if top < cur {
                    area = area.vertical_scroll_offset(top);
                } else if bottom > cur + body.height() {
                    area = area.vertical_scroll_offset(bottom - body.height());
                }
            }
            area.show_rows(ui, 32.0, n, |ui, range| {
                for i in range {
                    if i < self.view.len() {
                        self.row(ui, p, &cols, &self.results[self.view[i]], acts);
                    } else {
                        self.scanning_row(ui, p);
                    }
                }
            });
        });
        ui.painter().rect_stroke(rect.shrink(0.5), 8.0, stroke(1.0, p.border));
    }

    fn row(&self, ui: &mut Ui, p: &'static Palette, cols: &[Col], h: &HostResult, acts: &mut Vec<Act>) {
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::click());
        let up = h.is_up();
        let change = self.changes.get(&h.ip).copied();
        let gone = change == Some(Change::Gone);
        // Un hôte disparu garde son nom, sa MAC et son fabricant, en grisé.
        let known = up || gone;
        if ui.is_rect_visible(rect) {
            let selected = self.selected == Some(h.ip);
            let painter = ui.painter();
            if selected {
                painter.rect_filled(rect, 0.0, p.selected);
            } else if up && (resp.hovered() || resp.context_menu_opened()) {
                painter.rect_filled(rect, 0.0, p.hover);
            }
            painter.hline(rect.x_range(), rect.bottom() - 0.5, stroke(1.0, p.row_line));
            if selected {
                painter.rect_stroke(rect.shrink(0.5), 0.0, stroke(1.0, p.selected_border));
            }
            let cy = rect.center().y;
            let main = if up { p.text } else { p.text3 };
            for c in cols {
                let cell = Rect::from_min_max(pos2(c.x, rect.top()), pos2(c.x + c.w, rect.bottom()));
                let cp = painter.with_clip_rect(cell.intersect(painter.clip_rect()));
                match c.kind {
                    ColKind::Status => {
                        cp.circle_filled(pos2(c.x + 4.0, cy), 4.0, if up { p.ok } else if gone { p.warn } else { p.idle });
                        let (t, col) = match h.detection {
                            Some(d) => (d.label(), p.text2),
                            None if gone => ("Disparu", p.warn),
                            None => ("Inactif", p.text3),
                        };
                        w::text_at(&cp, w::galley(ui, t, regular(12.0), col), c.x + 15.0, cy);
                    }
                    ColKind::Ip => {
                        w::text_at(&cp, w::galley(ui, h.ip.to_string(), mono(13.0), main), c.x, cy);
                    }
                    ColKind::Name => {
                        let (t, col) = match (&h.hostname, known) {
                            (Some(n), true) => (n.as_str(), main),
                            _ => ("—", p.text3),
                        };
                        // Badge « Nouveau » : absent du scan précédent.
                        let mut max_w = c.w;
                        if change == Some(Change::New) {
                            let bg = w::galley(ui, "Nouveau", semibold(11.0), p.accent_text);
                            let bw = bg.size().x + 12.0;
                            let br = Rect::from_min_size(pos2(c.x + c.w - bw, cy - 9.0), vec2(bw, 18.0));
                            cp.rect_filled(br, 4.0, p.accent_soft);
                            w::text_at(&cp, bg, br.left() + 6.0, cy);
                            max_w -= bw + 8.0;
                        }
                        w::text_at(&cp, w::galley_trunc(ui, t, regular(13.0), col, max_w), c.x, cy);
                    }
                    ColKind::Mac => {
                        let (t, col) = match (h.mac_string(), known) {
                            (Some(m), true) => (m, if up { p.text2 } else { p.text3 }),
                            _ => ("—".to_string(), p.text3),
                        };
                        w::text_at(&cp, w::galley(ui, t, mono(12.5), col), c.x, cy);
                    }
                    ColKind::Vendor => {
                        let (t, col) = match (h.vendor(), known) {
                            (Some(v), true) => (v, if up { p.text2 } else { p.text3 }),
                            _ => ("—", p.text3),
                        };
                        w::text_at(&cp, w::galley_trunc(ui, t, regular(12.5), col, c.w), c.x, cy);
                    }
                    ColKind::Rtt => {
                        let t = match (h.rtt_ms, up) {
                            (Some(0), true) => "<1 ms".to_string(),
                            (Some(v), true) => format!("{v} ms"),
                            _ => "—".to_string(),
                        };
                        let col = if h.rtt_ms.is_some() && up { p.text } else { p.text3 };
                        let g = w::galley(ui, t, regular(12.5), col);
                        let gw = g.size().x;
                        w::text_at(&cp, g, c.x + c.w - gw, cy);
                    }
                    ColKind::Ports => paint_ports_cell(ui, &cp, p, h, c, cy),
                    ColKind::Time => {
                        let t = h.scanned_at.get(11..19).unwrap_or("");
                        w::text_at(&cp, w::galley(ui, t, regular(12.0), p.text3), c.x, cy);
                    }
                }
            }
        }
        if up {
            if resp.clicked() {
                acts.push(Act::Select(h.ip));
            } else if resp.secondary_clicked() {
                acts.push(Act::MenuTarget(h.ip));
            }
            resp.context_menu(|ui| host_menu(ui, p, h, acts));
            if resp.context_menu_opened() {
                self.menu_open.set(true);
            }
        } else if gone {
            resp.on_hover_text("Actif au scan précédent, ne répond plus.");
        }
    }

    fn scanning_row(&self, ui: &mut Ui, p: &'static Palette) {
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::hover());
        let cy = rect.center().y;
        egui::Spinner::new().size(14.0).color(p.accent_text).paint_at(ui, w::icon_rect(rect.left() + 12.0, cy, 14.0));
        let current = self
            .targets
            .get(self.results.len())
            .or(self.targets.last())
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let painter = ui.painter();
        let mut x = rect.left() + 34.0;
        x += w::text_at(painter, w::galley(ui, "Analyse de ", regular(12.0), p.text3), x, cy);
        x += w::text_at(painter, w::galley(ui, current, mono(12.0), p.text3), x, cy);
        w::text_at(painter, w::galley(ui, " … les hôtes actifs s'ajoutent au fil de l'eau", regular(12.0), p.text3), x, cy);
    }

    fn empty_state(&self, ui: &mut Ui, p: &'static Palette, acts: &mut Vec<Act>, body: Rect) {
        ui.allocate_new_ui(UiBuilder::new().max_rect(body).layout(Layout::top_down(Align::Center)), |ui| {
            ui.add_space(((body.height() - 170.0) / 2.0).max(16.0));
            ui.spacing_mut().item_spacing.y = 10.0;
            if self.results.is_empty() {
                let (r, _) = ui.allocate_exact_size(Vec2::splat(56.0), Sense::hover());
                w::paint_empty_logo(ui.painter(), r, p);
                w::label(ui, "Aucun résultat pour l'instant", semibold(16.0), p.text);
                centered_text(ui, "Saisissez une plage IP à gauche ou choisissez un réseau de ce PC, puis lancez le scan.", 360.0, p.text3);
                let parts_w = w::galley(ui, "F5", regular(12.0), p.text2).size().x
                    + w::galley(ui, "Entrée", regular(12.0), p.text2).size().x
                    + w::galley(ui, "Lancer", regular(12.0), p.text3).size().x
                    + w::galley(ui, "dans le champ Plage IP", regular(12.0), p.text3).size().x
                    + 24.0 + 8.0 * 3.0 + 12.0;
                ui.allocate_ui_with_layout(vec2(parts_w, 22.0), Layout::left_to_right(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    w::kbd(ui, p, "F5");
                    w::label(ui, "Lancer", regular(12.0), p.text3);
                    ui.add_space(4.0);
                    w::kbd(ui, p, "Entrée");
                    w::label(ui, "dans le champ Plage IP", regular(12.0), p.text3);
                });
                return;
            }

            // Résultats présents mais rien à afficher
            let hidden = self.results.len() - self.up_count();
            let (r, _) = ui.allocate_exact_size(Vec2::splat(48.0), Sense::hover());
            ui.painter().circle(r.center(), 23.5, p.surface2, stroke(1.0, p.border));
            let filter = self.filter.trim();
            if !filter.is_empty() {
                icons::paint(ui, &icons::SEARCH_X, Rect::from_center_size(r.center(), Vec2::splat(22.0)), p.text3);
                w::label(ui, format!("Aucun hôte ne correspond à « {filter} »"), semibold(16.0), p.text);
                let mut text = "Le filtre cherche dans l'IP, le nom, la MAC, les ports et les services.".to_string();
                if !self.s.show_down && hidden > 0 {
                    text.push_str(&format!(" {} masqués.", plural(hidden, "hôte inactif est", "hôtes inactifs sont")).replace(" est masqués", " est masqué"));
                }
                centered_text(ui, &text, 400.0, p.text3);
                let b1 = w::galley(ui, "Effacer le filtre", regular(13.0), p.text).size().x + 24.0;
                let b2 = w::galley(ui, "Inclure les inactifs", regular(13.0), p.text).size().x + 24.0;
                let show_b2 = !self.s.show_down;
                let total_w = b1 + if show_b2 { b2 + 8.0 } else { 0.0 };
                ui.allocate_ui_with_layout(vec2(total_w, 32.0), Layout::left_to_right(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if Button::new(Kind::Secondary, "Effacer le filtre").font(regular(13.0)).size(b1, 32.0).show(ui, p).clicked() {
                        acts.push(Act::ClearFilter);
                    }
                    if show_b2 && Button::new(Kind::Link, "Inclure les inactifs").font(regular(13.0)).size(b2, 32.0).show(ui, p).clicked() {
                        acts.push(Act::ShowInactive);
                    }
                });
            } else {
                icons::paint(ui, &icons::INFO, Rect::from_center_size(r.center(), Vec2::splat(22.0)), p.text3);
                w::label(ui, "Aucun hôte actif", semibold(16.0), p.text);
                centered_text(
                    ui,
                    &format!("Aucune des {} n'a répondu. Essayez la découverte ARP / TCP ou un timeout plus long.", plural(self.results.len(), "adresse analysée", "adresses analysées")),
                    400.0,
                    p.text3,
                );
                let b = w::galley(ui, "Afficher les inactifs", regular(13.0), p.text).size().x + 24.0;
                ui.allocate_ui_with_layout(vec2(b, 32.0), Layout::left_to_right(Align::Center), |ui| {
                    if Button::new(Kind::Link, "Afficher les inactifs").font(regular(13.0)).size(b, 32.0).show(ui, p).clicked() {
                        acts.push(Act::ShowInactive);
                    }
                });
            }
        });
    }

    // -- Panneau de détails -------------------------------------------------

    fn details(&self, ui: &mut Ui, p: &'static Palette, h: &HostResult, acts: &mut Vec<Act>) {
        let rect = ui.max_rect();
        ui.painter().rect_filled(rect, 8.0, p.surface);
        let inner = rect.shrink(1.0);
        let det = h.detection.unwrap_or(Detection::Ping);

        ui.allocate_new_ui(UiBuilder::new().max_rect(inner), |ui| {
            ui.set_clip_rect(inner.intersect(ui.clip_rect()));
            Frame::none()
                .inner_margin(Margin { left: 15.0, right: 11.0, top: 11.0, bottom: 12.0 })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 6.0;
                    ui.horizontal(|ui| {
                        let new = if self.changes.get(&h.ip) == Some(&Change::New) { " · nouveau" } else { "" };
                        w::status_pill(ui, p, &format!("Actif · {}{new}", det.label()));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let r = Button::new(Kind::Ghost, "").icon(&icons::X).size(28.0, 28.0).show(ui, p);
                            if r.on_hover_text("Fermer (Échap)").clicked() {
                                acts.push(Act::Deselect);
                            }
                        });
                    });
                    let title = h.hostname.clone().unwrap_or_else(|| "Nom non résolu".into());
                    let title_color = if h.hostname.is_some() { p.text } else { p.text3 };
                    ui.add(Label::new(RichText::new(title).font(semibold(16.0)).color(title_color)).wrap());
                    w::label(ui, h.ip.to_string(), mono(14.0), p.text2);
                });
            let y = ui.cursor().top() - 0.5;
            w::hline(ui, inner, y, p.border);

            egui::ScrollArea::vertical().id_salt("details_scroll").auto_shrink(false).show(ui, |ui| {
                Frame::none()
                    .inner_margin(Margin { left: 15.0, right: 15.0, top: 8.0, bottom: 15.0 })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let ip = h.ip.to_string();
                        let mac = h.mac_string();
                        field_row(ui, p, "Adresse IP", &ip, true, Some((ip.clone(), format!("Adresse IP copiée : {ip}"))), acts);
                        match &h.hostname {
                            Some(n) => field_row(ui, p, "Nom d'hôte", n, false, Some((n.clone(), format!("Nom d'hôte copié : {n}"))), acts),
                            None => field_row(ui, p, "Nom d'hôte", "—", false, None, acts),
                        }
                        match &mac {
                            Some(m) => field_row(ui, p, "Adresse MAC", m, true, Some((m.clone(), format!("Adresse MAC copiée : {m}"))), acts),
                            None => field_row(ui, p, "Adresse MAC", "—", true, None, acts),
                        }
                        field_row(ui, p, "Fabricant", h.vendor().unwrap_or("—"), false, None, acts);
                        let rtt = match h.rtt_ms {
                            Some(0) => "<1 ms".to_string(),
                            Some(v) => format!("{v} ms"),
                            None => "—".to_string(),
                        };
                        field_row(ui, p, "Latence", &rtt, false, None, acts);
                        let how = match det {
                            Detection::Ping => "Ping (ICMP)",
                            Detection::Arp => "ARP (réseau local)",
                            Detection::Tcp => "TCP (sans ping)",
                        };
                        field_row(ui, p, "Détection", how, false, None, acts);
                        field_row(ui, p, "Analysé le", &date_fr(&h.scanned_at), false, None, acts);

                        ui.add_space(14.0);
                        w::field_label(ui, p, &format!("Ports ouverts ({})", h.open_ports.len()));
                        ui.add_space(8.0);
                        if h.open_ports.is_empty() {
                            w::label(ui, "Aucun port ouvert parmi ceux testés.", regular(12.5), p.text3);
                        } else {
                            ui.horizontal_wrapped(|ui| {
                                ui.spacing_mut().item_spacing = vec2(4.0, 4.0);
                                for &port in &h.open_ports {
                                    w::port_badge(ui, p, &scanner::port_badge_label(port));
                                }
                            });
                        }

                        ui.add_space(14.0);
                        w::field_label(ui, p, "Actions");
                        ui.add_space(8.0);
                        details_actions(ui, p, h, acts);
                    });
            });
        });
        ui.painter().rect_stroke(rect.shrink(0.5), 8.0, stroke(1.0, p.border));
    }
}

impl eframe::App for NetScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        let _ = self.range_status();
        let _ = self.ports_status();
        self.handle_keys(ctx);
        if std::mem::take(&mut self.want_start) {
            self.start_scan(ctx);
        }
        if self.scan.is_some() || self.rescan.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        self.track_window(ctx);
        if self.view_dirty {
            self.rebuild_view();
        }

        let p = Palette::get(self.s.dark_mode);
        let mut acts = Vec::new();
        self.menu_open.set(false);
        self.status_bar(ctx, p);
        self.sidebar(ctx, p);
        title_bar(ctx, p);
        egui::CentralPanel::default()
            .frame(Frame::none().fill(p.bg).inner_margin(Margin { left: 16.0, right: 16.0, top: 4.0, bottom: 16.0 }))
            .show(ctx, |ui| self.main_area(ui, p, &mut acts));
        resize_handles(ctx);
        #[cfg(debug_assertions)]
        if self.script.as_ref().is_some_and(|s| s.pending()) {
            crate::demo::keep_alive(ctx);
        }

        self.scroll_to = None;
        for a in acts {
            self.apply_act(ctx, a);
        }
        // Menu contextuel refermé : la ligne visée devient la sélection.
        if self.menu_target.is_some() && !self.menu_open.get() {
            self.selected = self.menu_target.take();
            ctx.request_repaint();
        }
        if std::mem::take(&mut self.toggle_theme) {
            self.s.dark_mode = !self.s.dark_mode;
            theme::apply(ctx, self.s.dark_mode);
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.s);
    }

    #[cfg(debug_assertions)]
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if let Some(script) = &mut self.script {
            script.inject(raw_input);
            if script.pending() {
                crate::demo::keep_alive(ctx);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fenêtre sans barre de titre : déplacement, boutons, redimensionnement
// ---------------------------------------------------------------------------

/// Remet la fenêtre comme à la dernière fermeture : taille, position (si l'écran est
/// toujours branché), puis agrandissement.
fn restore_window(ctx: &egui::Context, s: &Settings) {
    use egui::ViewportCommand as Cmd;
    if let Some([w, h]) = s.win_size {
        ctx.send_viewport_cmd(Cmd::InnerSize(vec2(w.max(960.0), h.max(560.0))));
    }
    if let Some([x, y]) = s.win_pos {
        let ppp = ctx.native_pixels_per_point().unwrap_or(1.0);
        if crate::win::point_on_screen(((x + 120.0) * ppp) as i32, ((y + 16.0) * ppp) as i32) {
            ctx.send_viewport_cmd(Cmd::OuterPosition(pos2(x, y)));
        }
    }
    if s.maximized {
        ctx.send_viewport_cmd(Cmd::Maximized(true));
    }
}

const TITLE_H: f32 = 32.0;
const CAPTION_W: f32 = 46.0;

fn is_maximized(ctx: &egui::Context) -> bool {
    ctx.input(|i| i.viewport().maximized.unwrap_or(false))
}

/// Zone qui déplace la fenêtre (glisser) ou l'agrandit (double-clic).
/// À appeler avant les widgets qu'elle contient, pour qu'ils restent cliquables.
fn window_drag(ui: &Ui, rect: Rect, id: &str) {
    let resp = ui.interact(rect, ui.id().with(id), Sense::click_and_drag());
    if resp.double_clicked() {
        let maximized = is_maximized(ui.ctx());
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
    } else if resp.drag_started_by(egui::PointerButton::Primary) {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Caption {
    Minimize,
    Maximize,
    Close,
}

/// Bandeau du haut, de la couleur du fond : uniquement réduire / agrandir / fermer.
fn title_bar(ctx: &egui::Context, p: &'static Palette) {
    egui::TopBottomPanel::top("titlebar")
        .exact_height(TITLE_H)
        .show_separator_line(false)
        .frame(Frame::none().fill(p.bg))
        .show(ctx, |ui| {
            let rect = ui.max_rect();
            window_drag(ui, rect, "drag_title");
            let maximized = is_maximized(ctx);
            let mut x = rect.right();
            for kind in [Caption::Close, Caption::Maximize, Caption::Minimize] {
                x -= CAPTION_W;
                let r = Rect::from_min_size(pos2(x, rect.top()), vec2(CAPTION_W, TITLE_H));
                if caption_button(ui, p, r, kind, maximized).clicked() {
                    ctx.send_viewport_cmd(match kind {
                        Caption::Minimize => egui::ViewportCommand::Minimized(true),
                        Caption::Maximize => egui::ViewportCommand::Maximized(!maximized),
                        Caption::Close => egui::ViewportCommand::Close,
                    });
                }
            }
        });
}

fn caption_button(ui: &Ui, p: &Palette, rect: Rect, kind: Caption, maximized: bool) -> egui::Response {
    let resp = ui.interact(rect, ui.id().with(("caption", kind as u8)), Sense::click());
    let down = resp.is_pointer_button_down_on();
    let hot = resp.hovered() || down;
    let (bg, fg) = match (kind, hot) {
        (_, false) => (p.bg, p.text2),
        (Caption::Close, true) => {
            let red = egui::Color32::from_rgb(0xC4, 0x2B, 0x1C);
            (if down { w::lerp_color(red, p.bg, 0.25) } else { red }, egui::Color32::WHITE)
        }
        (_, true) => (w::lerp_color(p.bg, p.text, if down { 0.14 } else { 0.08 }), p.text),
    };
    let painter = ui.painter();
    if hot {
        painter.rect_filled(rect, 0.0, bg);
    }
    let c = pos2(rect.center().x.round(), rect.center().y.round());
    let line = stroke(1.0, fg);
    match kind {
        Caption::Minimize => {
            painter.hline(c.x - 5.0..=c.x + 5.0, c.y + 0.5, line);
        }
        Caption::Maximize if maximized => {
            let back = Rect::from_min_size(pos2(c.x - 2.5, c.y - 5.5), Vec2::splat(8.0));
            let front = Rect::from_min_size(pos2(c.x - 5.5, c.y - 2.5), Vec2::splat(8.0));
            painter.rect_stroke(back, 1.5, line);
            painter.rect(front, 1.5, bg, line);
        }
        Caption::Maximize => {
            painter.rect_stroke(Rect::from_center_size(pos2(c.x + 0.5, c.y + 0.5), Vec2::splat(10.0)), 1.5, line);
        }
        Caption::Close => {
            let line = stroke(1.1, fg);
            painter.line_segment([pos2(c.x - 4.5, c.y - 4.5), pos2(c.x + 5.5, c.y + 5.5)], line);
            painter.line_segment([pos2(c.x + 5.5, c.y - 4.5), pos2(c.x - 4.5, c.y + 5.5)], line);
        }
    }
    resp.on_hover_text(match kind {
        Caption::Minimize => "Réduire",
        Caption::Maximize if maximized => "Restaurer",
        Caption::Maximize => "Agrandir",
        Caption::Close => "Fermer",
    })
}

/// Bords et coins de la fenêtre : redimensionnement (la bordure Windows a disparu avec la barre).
fn resize_handles(ctx: &egui::Context) {
    use egui::{CursorIcon as C, ResizeDirection as D};
    if is_maximized(ctx) {
        return;
    }
    const E: f32 = 4.0;
    const K: f32 = 8.0;
    let s = ctx.screen_rect();
    let (l, r, t, b) = (s.left(), s.right(), s.top(), s.bottom());
    let zones = [
        (Rect::from_min_max(pos2(l + K, t), pos2(r - K, t + E)), D::North, C::ResizeNorth),
        (Rect::from_min_max(pos2(l + K, b - E), pos2(r - K, b)), D::South, C::ResizeSouth),
        (Rect::from_min_max(pos2(l, t + K), pos2(l + E, b - K)), D::West, C::ResizeWest),
        (Rect::from_min_max(pos2(r - E, t + K), pos2(r, b - K)), D::East, C::ResizeEast),
        (Rect::from_min_max(pos2(l, t), pos2(l + K, t + K)), D::NorthWest, C::ResizeNorthWest),
        (Rect::from_min_max(pos2(r - K, t), pos2(r, t + K)), D::NorthEast, C::ResizeNorthEast),
        (Rect::from_min_max(pos2(l, b - K), pos2(l + K, b)), D::SouthWest, C::ResizeSouthWest),
        (Rect::from_min_max(pos2(r - K, b - K), pos2(r, b)), D::SouthEast, C::ResizeSouthEast),
    ];
    // Appelé en fin d'image : le curseur de redimensionnement l'emporte sur celui des widgets.
    let (pos, pressed, held) = ctx.input(|i| (i.pointer.hover_pos(), i.pointer.primary_pressed(), i.pointer.primary_down()));
    let Some(pos) = pos else { return };
    if let Some((_, dir, cursor)) = zones.into_iter().find(|z| z.0.contains(pos)) {
        if pressed {
            ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
        }
        if pressed || !held {
            ctx.set_cursor_icon(cursor);
        }
    }
}

// ---------------------------------------------------------------------------
// Fonctions d'interface
// ---------------------------------------------------------------------------

fn combo(ui: &mut Ui, p: &'static Palette, id: &str, width: f32, height: f32, selected: RichText, add: impl FnOnce(&mut Ui)) {
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = height;
        ui.spacing_mut().button_padding = vec2(10.0, if height > 30.0 { 8.0 } else { 4.0 });
        egui::ComboBox::from_id_salt(id)
            .width(width)
            .height(320.0)
            .selected_text(selected)
            .icon(move |ui, rect, _visuals, _open, _above| {
                icons::paint(ui, &icons::CHEVRON_DOWN, Rect::from_center_size(rect.center(), Vec2::splat(14.0)), p.text3);
            })
            .show_ui(ui, |ui| {
                ui.spacing_mut().button_padding = vec2(10.0, 7.0);
                ui.spacing_mut().item_spacing.y = 2.0;
                add(ui);
            });
    });
}

fn hint_line(ui: &mut Ui, p: &Palette, icon: Option<(&Icon, egui::Color32)>, text: &str, color: egui::Color32) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        if let Some((ic, c)) = icon {
            let (r, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
            icons::paint(ui, ic, w::icon_rect(r.left(), r.center().y, 14.0), c);
        }
        ui.add(Label::new(RichText::new(text).font(regular(12.0)).color(color)).wrap());
    });
    let _ = p;
}

fn lock_banner(ui: &mut Ui, p: &Palette) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(width, 28.0), Sense::hover());
    let painter = ui.painter();
    painter.rect(rect.shrink(0.5), 6.0, p.surface2, stroke(1.0, p.border));
    icons::paint(ui, &icons::LOCK, w::icon_rect(rect.left() + 10.0, rect.center().y, 14.0), p.text2);
    let g = w::galley(ui, "Paramètres verrouillés pendant le scan", regular(12.0), p.text2);
    w::text_at(painter, g, rect.left() + 32.0, rect.center().y);
}

/// Libellé + valeur modifiable (clic pour saisir, glisser pour ajuster) + curseur.
fn slider_block(ui: &mut Ui, p: &Palette, title: &str, suffix: &str, value: &mut f64, range: std::ops::RangeInclusive<f64>, step: f64) {
    ui.spacing_mut().item_spacing.y = 6.0;
    ui.horizontal(|ui| {
        w::field_label(ui, p, title);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.style_mut().drag_value_text_style = egui::TextStyle::Monospace;
            ui.style_mut().text_styles.insert(egui::TextStyle::Monospace, mono(12.0));
            ui.spacing_mut().button_padding = vec2(5.0, 1.0);
            ui.spacing_mut().interact_size = vec2(34.0, 20.0);
            ui.visuals_mut().override_text_color = Some(p.text);
            let field = egui::DragValue::new(value)
                .range(range.clone())
                .speed(step)
                .max_decimals(0)
                .suffix(suffix)
                .update_while_editing(false);
            ui.add(field).on_hover_text("Cliquer pour saisir une valeur");
        });
    });
    w::slider(ui, p, value, range, step);
}

fn option_row(ui: &mut Ui, p: &Palette, on: &mut bool, title: &str, slow: Option<&str>) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        ui.vertical(|ui| {
            ui.add_space(1.0);
            w::switch(ui, p, on);
        });
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            let r = ui.add(Label::new(RichText::new(title).font(regular(13.0)).color(p.text)).sense(Sense::click()));
            if r.clicked() {
                *on = !*on;
            }
            if let Some(hint) = slow {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = vec2(6.0, 2.0);
                    w::slow_badge(ui, p);
                    ui.add(Label::new(RichText::new(hint).font(regular(11.5)).color(p.text3)));
                });
            }
        });
    });
}

fn paint_stat(ui: &Ui, p: &Palette, r: Rect, label: &str, value: &str, sub: &str, dot: bool) {
    let painter = ui.painter();
    painter.rect(r.shrink(0.5), 8.0, p.surface, stroke(1.0, p.border));
    let lg = w::galley(ui, label, regular(12.0), p.text3);
    painter.galley(pos2(r.left() + 14.0, r.top() + 11.0), lg, p.text3);
    let vg = w::galley(ui, value, semibold(22.0), p.text);
    let vh = vg.size().y;
    let vy = r.bottom() - 9.0 - vh;
    let mut x = r.left() + 14.0;
    if dot {
        painter.circle_filled(pos2(x + 4.0, vy + vh * 0.55), 4.0, p.ok);
        x += 14.0;
    }
    let vw = vg.size().x;
    painter.galley(pos2(x, vy), vg, p.text);
    if !sub.is_empty() {
        let sg = w::galley(ui, sub, regular(12.0), p.text3);
        let sy = vy + vh * 0.78 - sg.size().y * 0.78;
        painter.galley(pos2(x + vw + 6.0, sy), sg, p.text3);
    }
}

fn paint_ports_cell(ui: &Ui, painter: &egui::Painter, p: &Palette, h: &HostResult, c: &Col, cy: f32) {
    if !h.is_up() || h.open_ports.is_empty() {
        w::text_at(painter, w::galley(ui, "—", regular(12.5), p.text3), c.x, cy);
        return;
    }
    let labels: Vec<String> = h.open_ports.iter().map(|&port| scanner::port_badge_label(port)).collect();
    let mut x = c.x;
    let right = c.x + c.w;
    let mut shown = 0;
    for (k, l) in labels.iter().enumerate() {
        let bw = w::galley(ui, l.as_str(), mono(11.5), p.badge_text).size().x + 12.0;
        let remaining_after = labels.len() - k - 1;
        let reserve = if remaining_after > 0 {
            w::galley(ui, format!("+{remaining_after}"), regular(11.5), p.text3).size().x + 6.0
        } else {
            0.0
        };
        if k > 0 && x + bw > right - reserve {
            break;
        }
        x += w::paint_port_badge(ui, painter, p, l, x, cy) + 4.0;
        shown += 1;
    }
    if shown < labels.len() {
        let g = w::galley(ui, format!("+{}", labels.len() - shown), regular(11.5), p.text3);
        w::text_at(painter, g, x + 2.0, cy);
    }
}

fn field_row(ui: &mut Ui, p: &Palette, key: &str, value: &str, is_mono: bool, copy: Option<(String, String)>, acts: &mut Vec<Act>) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(width, 28.0), Sense::hover());
    let cy = rect.center().y;
    let painter = ui.painter();
    painter.hline(rect.x_range(), rect.bottom() - 0.5, stroke(1.0, p.row_line));
    w::text_at(painter, w::galley(ui, key, regular(12.0), p.text3), rect.left(), cy);
    let vx = rect.left() + 100.0;
    let vmax = rect.right() - vx - if copy.is_some() { 30.0 } else { 0.0 };
    let font = if is_mono { mono(12.5) } else { regular(12.5) };
    let color = if value == "—" { p.text3 } else { p.text };
    w::text_at(painter, w::galley_trunc(ui, value, font, color, vmax), vx, cy);
    if let Some((text, msg)) = copy {
        let br = Rect::from_center_size(pos2(rect.right() - 12.0, cy), Vec2::splat(24.0));
        let r = ui.interact(br, ui.id().with(("copy", key)), Sense::click());
        if r.hovered() {
            ui.painter().rect_filled(br, 4.0, p.surface2);
        }
        let ic_color = if r.hovered() { p.text2 } else { p.text3 };
        icons::paint(ui, &icons::COPY, Rect::from_center_size(br.center(), Vec2::splat(13.0)), ic_color);
        if r.on_hover_text(format!("Copier : {key}")).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            acts.push(Act::Copy(text, msg));
        }
    }
}

fn web_urls(h: &HostResult) -> Vec<String> {
    WEB_PORTS
        .iter()
        .filter(|(port, _)| h.open_ports.contains(port))
        .map(|&(port, scheme)| {
            if port == 80 || port == 443 {
                format!("{scheme}://{}", h.ip)
            } else {
                format!("{scheme}://{}:{port}", h.ip)
            }
        })
        .collect()
}

/// Boutons d'action du panneau de détails (grille de 2 colonnes).
fn details_actions(ui: &mut Ui, p: &Palette, h: &HostResult, acts: &mut Vec<Act>) {
    enum Item {
        Do(&'static Icon, &'static str, Act),
        Web(Vec<String>),
    }
    let urls = web_urls(h);
    let mut items = Vec::new();
    if !urls.is_empty() {
        items.push(Item::Web(urls));
    }
    if h.open_ports.contains(&3389) {
        items.push(Item::Do(&icons::MONITOR, "Bureau distant", Act::Launch(Launch::Rdp(h.ip))));
    }
    if h.open_ports.contains(&445) || h.open_ports.contains(&139) {
        items.push(Item::Do(&icons::FOLDER, "Partages SMB", Act::Launch(Launch::Smb(h.ip))));
    }
    if h.open_ports.contains(&22) {
        items.push(Item::Do(&icons::TERMINAL, "SSH", Act::Launch(Launch::Ssh(h.ip))));
    }
    items.push(Item::Do(&icons::ACTIVITY, "Ping continu", Act::Launch(Launch::PingT(h.ip))));
    items.push(Item::Do(&icons::ROUTE, "Traceroute", Act::Launch(Launch::Tracert(h.ip))));
    if let Some(mac) = h.mac {
        items.push(Item::Do(&icons::POWER, "Wake-on-LAN", Act::Launch(Launch::Wol(mac))));
    }
    items.push(Item::Do(&icons::REFRESH, "Rescanner", Act::Rescan(h.ip)));

    let cw = ((ui.available_width() - 6.0) / 2.0).floor();
    let mut it = items.into_iter().peekable();
    while it.peek().is_some() {
        let pair: Vec<Item> = it.by_ref().take(2).collect();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            for item in pair {
                match item {
                    Item::Do(icon, label, act) => {
                        let r = Button::new(Kind::Secondary, label).icon(icon).left().size(cw, 32.0).show(ui, p);
                        if r.clicked() {
                            acts.push(act);
                        }
                    }
                    Item::Web(urls) => {
                        let r = Button::new(Kind::Secondary, "Navigateur").icon(&icons::GLOBE).left().size(cw, 32.0).show(ui, p);
                        if urls.len() == 1 {
                            let r = r.on_hover_text(urls[0].as_str());
                            if r.clicked() {
                                acts.push(Act::Launch(Launch::Url(urls[0].clone())));
                            }
                        } else {
                            let popup_id = ui.make_persistent_id("web_popup");
                            if r.clicked() {
                                ui.memory_mut(|m| m.toggle_popup(popup_id));
                            }
                            egui::popup::popup_below_widget(ui, popup_id, &r, egui::PopupCloseBehavior::CloseOnClick, |ui| {
                                ui.set_min_width(220.0);
                                ui.spacing_mut().item_spacing.y = 0.0;
                                for url in &urls {
                                    if w::menu_item_mono(ui, p, url).clicked() {
                                        acts.push(Act::Launch(Launch::Url(url.clone())));
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });
        ui.add_space(6.0);
    }
}

/// Menu contextuel d'un hôte (clic droit).
fn host_menu(ui: &mut Ui, p: &'static Palette, h: &HostResult, acts: &mut Vec<Act>) {
    ui.set_min_width(256.0);
    ui.spacing_mut().item_spacing = vec2(8.0, 0.0);

    fn item(ui: &mut Ui, p: &Palette, icon: Option<&Icon>, text: &str, right: Option<(&str, bool)>, act: Act, acts: &mut Vec<Act>) {
        if w::menu_item(ui, p, icon, text, right).clicked() {
            acts.push(act);
            ui.close_menu();
        }
    }

    let title = match &h.hostname {
        Some(n) => format!("{} · {}", h.ip, n),
        None => h.ip.to_string(),
    };
    w::menu_title(ui, p, &title);
    item(ui, p, Some(&icons::COPY), "Copier l'adresse IP", Some(("Ctrl+C", false)), Act::Copy(h.ip.to_string(), format!("Adresse IP copiée : {}", h.ip)), acts);
    if let Some(n) = &h.hostname {
        item(ui, p, None, "Copier le nom d'hôte", None, Act::Copy(n.clone(), format!("Nom d'hôte copié : {n}")), acts);
    }
    if let Some(m) = h.mac_string() {
        item(ui, p, None, "Copier l'adresse MAC", None, Act::Copy(m.clone(), format!("Adresse MAC copiée : {m}")), acts);
    }
    item(ui, p, None, "Copier la ligne", Some(("Ctrl+Maj+C", false)), Act::Copy(h.export_fields().join("\t"), "Ligne copiée dans le presse-papiers.".into()), acts);

    let urls = web_urls(h);
    let rdp = h.open_ports.contains(&3389);
    let smb = h.open_ports.contains(&445) || h.open_ports.contains(&139);
    let ssh = h.open_ports.contains(&22);
    if !urls.is_empty() || rdp || smb || ssh {
        w::menu_separator(ui, p);
    }
    match urls.len() {
        0 => {}
        1 => item(ui, p, Some(&icons::GLOBE), "Ouvrir dans le navigateur", None, Act::Launch(Launch::Url(urls[0].clone())), acts),
        _ => {
            ui.scope(|ui| {
                ui.spacing_mut().button_padding = vec2(10.0, 7.0);
                ui.spacing_mut().item_spacing.x = 10.0;
                ui.menu_image_text_button(icons::image(&icons::GLOBE, p.text3, 14.0), "Ouvrir dans le navigateur", |ui| {
                    ui.set_min_width(220.0);
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for url in &urls {
                        if w::menu_item_mono(ui, p, url).clicked() {
                            acts.push(Act::Launch(Launch::Url(url.clone())));
                            ui.close_menu();
                        }
                    }
                });
            });
        }
    }
    if rdp {
        item(ui, p, Some(&icons::MONITOR), "Bureau à distance (RDP)", None, Act::Launch(Launch::Rdp(h.ip)), acts);
    }
    if smb {
        let path = format!(r"\\{}", h.ip);
        item(ui, p, Some(&icons::FOLDER), "Partages SMB", Some((&path, true)), Act::Launch(Launch::Smb(h.ip)), acts);
    }
    if ssh {
        item(ui, p, Some(&icons::TERMINAL), "Ouvrir en SSH", None, Act::Launch(Launch::Ssh(h.ip)), acts);
    }
    w::menu_separator(ui, p);
    item(ui, p, Some(&icons::ACTIVITY), "Ping continu", None, Act::Launch(Launch::PingT(h.ip)), acts);
    item(ui, p, Some(&icons::ROUTE), "Traceroute", None, Act::Launch(Launch::Tracert(h.ip)), acts);
    item(ui, p, Some(&icons::REFRESH), "Rescanner cet hôte", None, Act::Rescan(h.ip), acts);
    if let Some(mac) = h.mac {
        w::menu_separator(ui, p);
        item(ui, p, Some(&icons::POWER), "Wake-on-LAN", None, Act::Launch(Launch::Wol(mac)), acts);
    }
}

fn centered_text(ui: &mut Ui, text: &str, max_w: f32, color: egui::Color32) {
    let width = max_w.min(ui.available_width());
    ui.allocate_ui_with_layout(vec2(width, 0.0), Layout::top_down(Align::Center), |ui| {
        ui.set_max_width(width);
        ui.add(Label::new(RichText::new(text).font(regular(13.0)).color(color)).wrap());
    });
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

fn matches_filter(h: &HostResult, f: &str) -> bool {
    h.ip.to_string().contains(f)
        || h.hostname.as_deref().is_some_and(|n| n.to_lowercase().contains(f))
        || h.mac_string().is_some_and(|m| m.to_lowercase().contains(f))
        || h.vendor().is_some_and(|v| v.to_lowercase().contains(f))
        || h.ports_string().to_lowercase().contains(f)
        || h.detection.is_some_and(|d| d.label().to_lowercase() == f)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", fmt_thousands(n as u64), if n > 1 { many } else { one })
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn secs_fr(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f32()).replace('.', ",")
}

/// « 2026-11-13 14:31:58 » → « 13/11/2026 à 14:31:58 ».
fn date_fr(s: &str) -> String {
    match (s.get(0..4), s.get(5..7), s.get(8..10), s.get(11..19)) {
        (Some(y), Some(m), Some(d), Some(t)) => format!("{d}/{m}/{y} à {t}"),
        _ => s.to_string(),
    }
}

fn preset_name(ports: &str) -> &'static str {
    let Ok(current) = scanner::parse_ports(ports) else { return "Personnalisé" };
    PORT_PRESETS
        .iter()
        .find(|(_, list)| scanner::parse_ports(list).is_ok_and(|v| v == current))
        .map_or("Personnalisé", |(name, _)| *name)
}

fn launch(program: &str, args: &[&str]) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd.spawn().map(|_| ())
}

/// Ouvre une nouvelle console qui exécute la commande.
fn console(args: &[&str]) -> std::io::Result<()> {
    let mut full = vec!["/C", "start", "", "cmd", "/K"];
    full.extend_from_slice(args);
    launch("cmd", &full)
}

/// Icône de la fenêtre.
pub fn app_icon() -> egui::IconData {
    egui::IconData {
        rgba: crate::icon::logo_rgba(64),
        width: 64,
        height: 64,
    }
}
