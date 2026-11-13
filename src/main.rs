// Pas de console noire derrière la fenêtre en version release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
#[cfg(debug_assertions)]
mod demo;
mod history;
mod icon;
mod icons;
mod scanner;
mod theme;
mod widgets;
mod win;

use eframe::egui;

/// Usage : `NetScan.exe [plage] [--start]`
/// ex. `NetScan.exe 192.168.1.0/24 --start` pré-remplit la plage et lance le scan.
fn main() -> eframe::Result<()> {
    let mut cli_range = None;
    let mut autostart = false;
    for arg in std::env::args().skip(1) {
        match arg.to_lowercase().as_str() {
            "--start" | "-s" | "/start" => autostart = true,
            _ => cli_range = Some(arg),
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NetScan")
            .with_inner_size([1240.0, 728.0])
            .with_min_inner_size([960.0, 560.0])
            // Pas de barre de titre Windows : l'app dessine ses propres boutons de fenêtre.
            .with_decorations(false)
            .with_icon(app::app_icon()),
        // L'app mémorise elle-même taille, position et état « agrandi » (voir app.rs).
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "NetScan",
        options,
        Box::new(move |cc| Ok(Box::new(app::NetScanApp::new(cc, cli_range, autostart)))),
    )
}
