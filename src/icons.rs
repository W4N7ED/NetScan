//! Icônes Lucide (tracés repris du design), rendues en SVG puis teintées.

use eframe::egui::{self, Color32, Rect, Ui};

pub struct Icon {
    pub uri: &'static str,
    pub svg: &'static str,
}

macro_rules! stroke_icon {
    ($name:ident, $file:literal, $width:literal, $paths:literal) => {
        pub const $name: Icon = Icon {
            uri: concat!("bytes://netscan/", $file, ".svg"),
            svg: concat!(
                r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width=""##,
                $width,
                r#"" stroke-linecap="round" stroke-linejoin="round">"#,
                $paths,
                "</svg>"
            ),
        };
    };
}

macro_rules! fill_icon {
    ($name:ident, $file:literal, $paths:literal) => {
        pub const $name: Icon = Icon {
            uri: concat!("bytes://netscan/", $file, ".svg"),
            svg: concat!(
                r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#ffffff">"##,
                $paths,
                "</svg>"
            ),
        };
    };
}

stroke_icon!(COPY, "copy", "1.9", r#"<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M4 16a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2"/>"#);
stroke_icon!(DOWNLOAD, "download", "1.9", r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>"#);
stroke_icon!(TRASH, "trash", "1.9", r#"<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>"#);
stroke_icon!(SEARCH, "search", "2", r#"<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>"#);
stroke_icon!(SEARCH_X, "search-x", "1.75", r#"<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/><path d="m8.5 8.5 5 5M13.5 8.5l-5 5"/>"#);
stroke_icon!(X, "x", "2.2", r#"<path d="M18 6 6 18M6 6l12 12"/>"#);
stroke_icon!(CHECK, "check", "2.2", r#"<path d="M20 6 9 17l-5-5"/>"#);
stroke_icon!(CHECK_BOLD, "check-bold", "3.4", r#"<path d="M20 6 9 17l-5-5"/>"#);
stroke_icon!(ALERT_CIRCLE, "alert-circle", "2", r#"<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>"#);
stroke_icon!(INFO, "info", "2", r#"<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>"#);
stroke_icon!(CHECK_CIRCLE, "check-circle", "2", r#"<circle cx="12" cy="12" r="10"/><path d="m8.5 12 2.5 2.5 4.5-5"/>"#);
stroke_icon!(WARNING, "warning", "2", r#"<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4M12 17h.01"/>"#);
stroke_icon!(X_CIRCLE, "x-circle", "2", r#"<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/>"#);
stroke_icon!(LOCK, "lock", "1.9", r#"<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#);
stroke_icon!(REFRESH, "refresh", "1.9", r#"<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>"#);
stroke_icon!(CHEVRON_DOWN, "chevron-down", "2", r#"<path d="m6 9 6 6 6-6"/>"#);
stroke_icon!(CHEVRON_UP, "chevron-up", "2.4", r#"<path d="m18 15-6-6-6 6"/>"#);
stroke_icon!(CHEVRON_DOWN_BOLD, "chevron-down-bold", "2.4", r#"<path d="m6 9 6 6 6-6"/>"#);
stroke_icon!(SUN, "sun", "1.9", r#"<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>"#);
stroke_icon!(MOON, "moon", "1.9", r#"<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>"#);
stroke_icon!(CLOCK, "clock", "2.6", r#"<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>"#);
stroke_icon!(GLOBE, "globe", "1.9", r#"<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>"#);
stroke_icon!(MONITOR, "monitor", "1.9", r#"<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>"#);
stroke_icon!(FOLDER, "folder", "1.9", r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#);
stroke_icon!(TERMINAL, "terminal", "1.9", r#"<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>"#);
stroke_icon!(ACTIVITY, "activity", "1.9", r#"<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>"#);
stroke_icon!(ROUTE, "route", "1.9", r#"<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>"#);
stroke_icon!(POWER, "power", "1.9", r#"<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>"#);
fill_icon!(PLAY, "play", r#"<path d="M7 4.5v15a1 1 0 0 0 1.5.86l12.5-7.5a1 1 0 0 0 0-1.72L8.5 3.64A1 1 0 0 0 7 4.5Z"/>"#);
fill_icon!(STOP, "stop", r#"<rect x="5" y="5" width="14" height="14" rx="2.5"/>"#);

/// Image egui de l'icône (pour les widgets qui en attendent une).
pub fn image(icon: &Icon, color: Color32, size: f32) -> egui::Image<'static> {
    egui::Image::from_bytes(icon.uri, icon.svg.as_bytes())
        .tint(color)
        .fit_to_exact_size(egui::Vec2::splat(size))
}

/// Dessine l'icône dans `rect`, teintée de `color`.
pub fn paint(ui: &Ui, icon: &Icon, rect: Rect, color: Color32) {
    egui::Image::from_bytes(icon.uri, icon.svg.as_bytes())
        .tint(color)
        .paint_at(ui, rect);
}
