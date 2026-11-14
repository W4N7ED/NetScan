//! Tokens du design (Claude Design) : palettes claire / sombre, polices, style egui.

use eframe::egui::{
    self, epaint::Shadow, style::WidgetVisuals, Color32, FontFamily, FontId, Margin, Rounding,
    Stroke, Theme, Vec2,
};

pub fn stroke(width: f32, color: Color32) -> Stroke {
    Stroke::new(width, color)
}

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub bg: Color32,
    pub sidebar: Color32,
    pub surface: Color32,
    pub surface2: Color32,
    pub menu: Color32,
    pub hover: Color32,
    pub selected: Color32,
    pub selected_border: Color32,
    pub row_line: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub input: Color32,
    pub text: Color32,
    pub text2: Color32,
    pub text3: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_text: Color32,
    pub accent_soft: Color32,
    pub on_accent: Color32,
    pub ok: Color32,
    pub ok_soft: Color32,
    pub warn: Color32,
    pub warn_soft: Color32,
    pub err: Color32,
    pub err_soft: Color32,
    pub err_fill: Color32,
    pub idle: Color32,
    pub track: Color32,
    pub badge: Color32,
    pub badge_text: Color32,
}

pub const LIGHT: Palette = Palette {
    dark: false,
    bg: hex(0xEEF0F3),
    sidebar: hex(0xF7F8FA),
    surface: hex(0xFFFFFF),
    surface2: hex(0xF4F5F7),
    menu: hex(0xFFFFFF),
    hover: hex(0xF1F4F8),
    selected: hex(0xE7EFFC),
    selected_border: hex(0x9DBDF2),
    row_line: hex(0xEEF0F3),
    border: hex(0xE1E4E9),
    border_strong: hex(0xCBD0D7),
    input: hex(0xFFFFFF),
    text: hex(0x15181C),
    text2: hex(0x454C56),
    text3: hex(0x69717C),
    accent: hex(0x1E63D6),
    accent_hover: hex(0x1A56BC),
    accent_text: hex(0x1A5BC7),
    accent_soft: hex(0xE8F0FC),
    on_accent: hex(0xFFFFFF),
    ok: hex(0x14773A),
    ok_soft: hex(0xE3F3E8),
    warn: hex(0x8F5600),
    warn_soft: hex(0xFBF0DC),
    err: hex(0xC02626),
    err_soft: hex(0xFBE7E7),
    err_fill: hex(0xC02626),
    idle: hex(0x8A929C),
    track: hex(0xE3E7EC),
    badge: hex(0xEFF2F5),
    badge_text: hex(0x38404A),
};

pub const DARK: Palette = Palette {
    dark: true,
    bg: hex(0x0F1114),
    sidebar: hex(0x14171B),
    surface: hex(0x181B20),
    surface2: hex(0x1E2228),
    menu: hex(0x1E2228),
    hover: hex(0x22272E),
    selected: hex(0x1A2A45),
    selected_border: hex(0x3D68B0),
    row_line: hex(0x22262D),
    border: hex(0x2A2F37),
    border_strong: hex(0x3A414B),
    input: hex(0x111418),
    text: hex(0xE8EBEF),
    text2: hex(0xB4BBC5),
    text3: hex(0x8D96A2),
    accent: hex(0x2F6FDB),
    accent_hover: hex(0x3B7BE6),
    accent_text: hex(0x7AAAF7),
    accent_soft: hex(0x1B2B47),
    on_accent: hex(0xFFFFFF),
    ok: hex(0x4CC27A),
    ok_soft: hex(0x13301F),
    warn: hex(0xE3A63B),
    warn_soft: hex(0x33270F),
    err: hex(0xF27171),
    err_soft: hex(0x3A1B1D),
    err_fill: hex(0xC93838),
    idle: hex(0x6B7480),
    track: hex(0x2A3038),
    badge: hex(0x242A32),
    badge_text: hex(0xC7CDD5),
};

impl Palette {
    pub fn get(dark: bool) -> &'static Palette {
        if dark {
            &DARK
        } else {
            &LIGHT
        }
    }
}

// ---------------------------------------------------------------------------
// Polices : Segoe UI (texte), Segoe UI Semibold (titres), Consolas (IP, MAC, ports)
// ---------------------------------------------------------------------------

pub const SEMIBOLD: &str = "semibold";
const CONSOLAS_DROP: f32 = 0.22;

pub fn regular(size: f32) -> FontId {
    FontId::proportional(size)
}
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}
pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

pub fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let default_prop = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let default_mono = fonts.families.get(&FontFamily::Monospace).cloned().unwrap_or_default();

    // `drop` : décalage vers le bas, en fraction de la taille de police.
    let mut load = |name: &str, path: &str, drop: f32| -> bool {
        match std::fs::read(path) {
            Ok(bytes) => {
                let tweak = egui::FontTweak { y_offset_factor: drop, ..Default::default() };
                fonts.font_data.insert(name.to_owned(), egui::FontData::from_owned(bytes).tweak(tweak));
                true
            }
            Err(_) => false,
        }
    };
    let has_regular = load("segoe", r"C:\Windows\Fonts\segoeui.ttf", 0.0);
    let has_semibold = load("segoe-sb", r"C:\Windows\Fonts\seguisb.ttf", 0.0);
    // Consolas a une ligne moins haute que Segoe UI : sans ce décalage, les IP, MAC et
    // ports paraissent 3 px plus haut que le texte voisin.
    let has_mono = load("consolas", r"C:\Windows\Fonts\consola.ttf", CONSOLAS_DROP);
    let has_symbol = load("segoe-sym", r"C:\Windows\Fonts\seguisym.ttf", 0.0);

    let mut prop: Vec<String> = Vec::new();
    if has_regular {
        prop.push("segoe".into());
    }
    prop.extend(default_prop);
    if has_symbol {
        prop.push("segoe-sym".into());
    }

    let mut semi: Vec<String> = Vec::new();
    if has_semibold {
        semi.push("segoe-sb".into());
    }
    semi.extend(prop.iter().cloned());

    let mut monos: Vec<String> = Vec::new();
    if has_mono {
        monos.push("consolas".into());
    }
    monos.extend(default_mono);
    if has_symbol {
        monos.push("segoe-sym".into());
    }

    fonts.families.insert(FontFamily::Proportional, prop);
    fonts.families.insert(FontFamily::Name(SEMIBOLD.into()), semi);
    fonts.families.insert(FontFamily::Monospace, monos);
    ctx.set_fonts(fonts);
}

// ---------------------------------------------------------------------------
// Style egui (pour les widgets natifs : listes déroulantes, menus, info-bulles…)
// ---------------------------------------------------------------------------

pub fn apply(ctx: &egui::Context, dark: bool) {
    ctx.set_theme(if dark { Theme::Dark } else { Theme::Light });
    ctx.style_mut_of(Theme::Dark, |s| style(s, &DARK));
    ctx.style_mut_of(Theme::Light, |s| style(s, &LIGHT));
}

fn style(s: &mut egui::Style, p: &Palette) {
    use egui::TextStyle::*;
    s.text_styles = [
        (Small, regular(12.0)),
        (Body, regular(13.0)),
        (Button, regular(13.0)),
        (Heading, semibold(16.0)),
        (Monospace, mono(13.0)),
    ]
    .into();
    s.spacing.item_spacing = Vec2::new(8.0, 6.0);
    s.spacing.button_padding = Vec2::new(10.0, 5.0);
    s.spacing.menu_margin = Margin::same(4.0);
    s.spacing.menu_width = 256.0;
    s.spacing.interact_size.y = 26.0;

    s.visuals = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let v = &mut s.visuals;
    let w = |fill: Color32, weak: Color32, line: Color32, fg: Color32| WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: weak,
        bg_stroke: stroke(1.0, line),
        rounding: Rounding::same(6.0),
        fg_stroke: stroke(1.0, fg),
        expansion: 0.0,
    };
    v.widgets.noninteractive = w(p.surface, p.surface, p.border, p.text);
    v.widgets.inactive = w(p.border_strong, p.input, p.border_strong, p.text);
    v.widgets.hovered = w(p.text3, p.hover, p.border_strong, p.text);
    v.widgets.active = w(p.text2, p.hover, p.accent, p.text);
    v.widgets.open = w(p.text3, p.input, p.accent, p.text);

    v.panel_fill = p.bg;
    v.window_fill = p.menu;
    v.extreme_bg_color = p.input;
    v.faint_bg_color = p.surface2;
    v.code_bg_color = p.badge;
    v.window_stroke = stroke(1.0, p.border_strong);
    v.window_rounding = Rounding::same(8.0);
    v.menu_rounding = Rounding::same(8.0);
    let shadow = Shadow {
        offset: Vec2::new(0.0, 6.0),
        blur: 20.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if p.dark { 128 } else { 38 }),
    };
    v.popup_shadow = shadow;
    v.window_shadow = shadow;
    v.hyperlink_color = p.accent_text;
    v.selection.bg_fill = p.selected;
    v.selection.stroke = stroke(1.0, p.accent_text);
    v.text_cursor.stroke = stroke(1.5, p.accent);
    v.striped = false;
}
