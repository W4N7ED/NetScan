//! Composants du design : boutons, champs, interrupteurs, curseurs, badges, menus.

use crate::icons::{self, Icon};
pub use crate::theme::stroke;
use crate::theme::{mono, regular, semibold, Palette};
use eframe::egui::{
    self, pos2, vec2, Align, Color32, CursorIcon, FontId, Galley, Id, Layout, Margin, Painter,
    Rect, Response, RichText, Sense, Shape, TextEdit, Ui, Vec2,
};
use std::ops::RangeInclusive;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgba_premultiplied(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()), l(a.a(), b.a()))
}

pub fn galley(ui: &Ui, text: impl Into<String>, font: FontId, color: Color32) -> Arc<Galley> {
    ui.painter().layout_no_wrap(text.into(), font, color)
}

/// Texte sur une ligne, tronqué avec « … » au-delà de `max_w`.
pub fn galley_trunc(ui: &Ui, text: &str, font: FontId, color: Color32, max_w: f32) -> Arc<Galley> {
    let mut job = egui::text::LayoutJob::simple_singleline(text.to_owned(), font, color);
    job.wrap = egui::text::TextWrapping::truncate_at_width(max_w.max(1.0));
    ui.fonts(|f| f.layout_job(job))
}

/// Dessine un texte centré verticalement sur `cy`, à partir de `x`. Renvoie sa largeur.
pub fn text_at(painter: &Painter, g: Arc<Galley>, x: f32, cy: f32) -> f32 {
    let size = g.size();
    painter.galley(pos2(x, (cy - size.y / 2.0).round()), g, Color32::WHITE);
    size.x
}

pub fn icon_rect(x: f32, cy: f32, size: f32) -> Rect {
    Rect::from_min_size(pos2(x, cy - size / 2.0), Vec2::splat(size))
}

pub fn label(ui: &mut Ui, text: impl Into<String>, font: FontId, color: Color32) -> Response {
    ui.label(RichText::new(text.into()).font(font).color(color))
}

/// Libellé de champ (12 px semibold, text2).
pub fn field_label(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    label(ui, text, semibold(12.0), p.text2)
}

pub fn hline(ui: &Ui, rect: Rect, y: f32, color: Color32) {
    ui.painter().hline(rect.x_range(), y, stroke(1.0, color));
}

// ---------------------------------------------------------------------------
// Boutons
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Primary,
    Danger,
    Secondary,
    Ghost,
    Link,
}

pub struct Button<'a> {
    kind: Kind,
    label: &'a str,
    icon: Option<&'a Icon>,
    icon_size: f32,
    size: Vec2,
    font: FontId,
    kbd: Option<&'a str>,
    enabled: bool,
    align_left: bool,
}

impl<'a> Button<'a> {
    pub fn new(kind: Kind, label: &'a str) -> Self {
        Self {
            kind,
            label,
            icon: None,
            icon_size: 14.0,
            size: vec2(0.0, 30.0),
            font: regular(12.5),
            kbd: None,
            enabled: true,
            align_left: false,
        }
    }
    pub fn icon(mut self, icon: &'a Icon) -> Self {
        self.icon = Some(icon);
        self
    }
    pub fn icon_size(mut self, s: f32) -> Self {
        self.icon_size = s;
        self
    }
    /// Largeur 0 = automatique.
    pub fn size(mut self, w: f32, h: f32) -> Self {
        self.size = vec2(w, h);
        self
    }
    pub fn font(mut self, f: FontId) -> Self {
        self.font = f;
        self
    }
    pub fn kbd(mut self, k: &'a str) -> Self {
        self.kbd = Some(k);
        self
    }
    pub fn enabled(mut self, e: bool) -> Self {
        self.enabled = e;
        self
    }
    pub fn left(mut self) -> Self {
        self.align_left = true;
        self
    }

    pub fn show(self, ui: &mut Ui, p: &Palette) -> Response {
        let filled = matches!(self.kind, Kind::Primary | Kind::Danger);
        let (fill, fill_hover, line, fg) = match (self.kind, self.enabled) {
            (Kind::Primary | Kind::Danger, false) => (p.surface2, p.surface2, p.border, p.text3),
            (Kind::Primary, true) => (p.accent, p.accent_hover, p.accent, p.on_accent),
            (Kind::Danger, true) => {
                let hover = lerp_color(p.err_fill, Color32::BLACK, 0.12);
                (p.err_fill, hover, p.err_fill, Color32::WHITE)
            }
            (Kind::Secondary, e) => (p.surface, p.hover, p.border_strong, if e { p.text } else { p.text3 }),
            (Kind::Ghost, _) => (Color32::TRANSPARENT, p.surface2, Color32::TRANSPARENT, p.text3),
            (Kind::Link, _) => (Color32::TRANSPARENT, p.hover, Color32::TRANSPARENT, p.accent_text),
        };

        let text_g = (!self.label.is_empty()).then(|| galley(ui, self.label, self.font.clone(), fg));
        let kbd_color = if filled && self.enabled { Color32::from_white_alpha(115) } else { p.border_strong };
        let kbd_g = self.kbd.map(|k| galley(ui, k, regular(11.0), fg.gamma_multiply(0.92)));

        let icon_w = if self.icon.is_some() { self.icon_size } else { 0.0 };
        let gap = if self.icon.is_some() && text_g.is_some() { 6.0 } else { 0.0 };
        let text_w = text_g.as_ref().map_or(0.0, |g| g.size().x);
        let content_w = icon_w + gap + text_w;
        let pad = 10.0;
        let w = if self.size.x > 0.0 { self.size.x } else { content_w + 2.0 * pad };

        let sense = if self.enabled { Sense::click() } else { Sense::hover() };
        let (rect, resp) = ui.allocate_exact_size(vec2(w, self.size.y), sense);
        if ui.is_rect_visible(rect) {
            let active = self.enabled && (resp.hovered() || resp.is_pointer_button_down_on());
            let painter = ui.painter();
            if resp.has_focus() {
                painter.rect_stroke(rect.expand(2.0), 8.0, stroke(2.0, p.accent));
            }
            painter.rect(
                rect.shrink(0.5),
                6.0,
                if active { fill_hover } else { fill },
                stroke(1.0, line),
            );
            let cy = rect.center().y;
            let mut x = if self.align_left { rect.left() + pad } else { (rect.center().x - content_w / 2.0).round() };
            if let Some(ic) = self.icon {
                icons::paint(ui, ic, icon_rect(x, cy, icon_w), fg);
                x += icon_w + gap;
            }
            if let Some(g) = text_g {
                text_at(painter, g, x, cy);
            }
            if let Some(kg) = kbd_g {
                let kw = kg.size().x + 10.0;
                let kr = Rect::from_min_size(pos2(rect.right() - 10.0 - kw, cy - 9.0), vec2(kw, 18.0));
                painter.rect_stroke(kr, 4.0, stroke(1.0, kbd_color));
                text_at(painter, kg, kr.left() + 5.0, cy);
            }
        }
        if self.enabled {
            resp.on_hover_cursor(CursorIcon::PointingHand)
        } else {
            resp
        }
    }
}

// ---------------------------------------------------------------------------
// Champ de saisie
// ---------------------------------------------------------------------------

pub struct Input<'a> {
    pub text: &'a mut String,
    pub id: &'a str,
    pub hint: &'a str,
    pub width: f32,
    pub height: f32,
    pub mono: bool,
    pub error: bool,
    pub search: bool,
    pub clearable: bool,
    /// Bordure accent (filtre actif).
    pub highlight: bool,
}

pub struct InputOutput {
    pub response: Response,
    pub submitted: bool,
    pub cleared: bool,
}

pub fn input(ui: &mut Ui, p: &Palette, cfg: Input) -> InputOutput {
    let enabled = ui.is_enabled();
    let show_clear = cfg.clearable && !cfg.text.is_empty() && enabled;
    let left = if cfg.search { 32.0 } else { 10.0 };
    let right = if show_clear { 34.0 } else if !enabled { 30.0 } else { 10.0 };
    let inner_w = (cfg.width - left - right).max(10.0);
    let font = if cfg.mono { mono(13.0) } else { regular(13.0) };
    let bg_idx = ui.painter().add(Shape::Noop);

    let te = TextEdit::singleline(cfg.text)
        .id(Id::new(cfg.id))
        .frame(false)
        .margin(Margin::ZERO)
        .font(font)
        .text_color(p.text)
        .hint_text(RichText::new(cfg.hint).font(regular(13.0)).color(p.text3))
        .vertical_align(Align::Center)
        .desired_width(inner_w)
        .min_size(vec2(inner_w, cfg.height));

    let ir = ui.allocate_ui_with_layout(vec2(cfg.width, cfg.height), Layout::left_to_right(Align::Center), |ui| {
        ui.set_min_size(vec2(cfg.width, cfg.height));
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(left);
        let resp = ui.add_sized(vec2(inner_w, cfg.height), te);
        let mut cleared = false;
        if show_clear {
            ui.add_space(5.0);
            let (r, cr) = ui.allocate_exact_size(vec2(24.0, 24.0), Sense::click());
            ui.painter().rect_filled(r, 4.0, if cr.hovered() { p.hover } else { p.surface2 });
            icons::paint(ui, &icons::X, Rect::from_center_size(r.center(), Vec2::splat(12.0)), p.text2);
            cleared = cr.on_hover_text("Effacer").clicked();
        }
        (resp, cleared)
    });
    let rect = ir.response.rect;
    let (resp, cleared) = ir.inner;

    let focused = resp.has_focus();
    let hovered = ir.response.hovered() || resp.hovered();
    let border = if cfg.error {
        p.err
    } else if focused || cfg.highlight {
        p.accent
    } else if hovered && enabled {
        p.text3
    } else {
        p.border_strong
    };
    let mut shapes = Vec::new();
    if cfg.error {
        shapes.push(Shape::rect_filled(rect.expand(3.0), 9.0, p.err_soft));
    } else if focused {
        shapes.push(Shape::rect_filled(rect.expand(3.0), 9.0, p.accent_soft));
    }
    shapes.push(Shape::rect_filled(rect, 6.0, p.input));
    shapes.push(Shape::rect_stroke(rect.shrink(0.5), 6.0, stroke(1.0, border)));
    ui.painter().set(bg_idx, Shape::Vec(shapes));

    let cy = rect.center().y;
    if cfg.search {
        icons::paint(ui, &icons::SEARCH, icon_rect(rect.left() + 10.0, cy, 15.0), p.text3);
    }
    if !enabled {
        icons::paint(ui, &icons::LOCK, icon_rect(rect.right() - 24.0, cy, 14.0), p.text3);
    }

    let submitted = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    InputOutput { response: resp, submitted, cleared }
}

// ---------------------------------------------------------------------------
// Interrupteur, case à cocher, curseur
// ---------------------------------------------------------------------------

pub fn switch(ui: &mut Ui, p: &Palette, on: &mut bool) -> Response {
    let (rect, mut resp) = ui.allocate_exact_size(vec2(34.0, 18.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_with_time(resp.id, *on, 0.12);
    let painter = ui.painter();
    let track = lerp_color(p.track, p.accent, t);
    let border = lerp_color(p.border_strong, p.accent, t);
    painter.rect(rect.shrink(0.5), 9.0, track, stroke(1.0, border));
    let x = egui::lerp(rect.left() + 9.0..=rect.right() - 9.0, t);
    painter.circle_filled(pos2(x, rect.center().y), 6.0, lerp_color(p.text3, Color32::WHITE, t));
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

pub fn checkbox(ui: &mut Ui, p: &Palette, checked: &mut bool, text: &str) -> Response {
    let g = galley(ui, text, regular(13.0), p.text2);
    let (rect, mut resp) = ui.allocate_exact_size(vec2(15.0 + 6.0 + g.size().x, 22.0), Sense::click());
    if resp.clicked() {
        *checked = !*checked;
        resp.mark_changed();
    }
    let hovered = resp.hovered();
    let b = Rect::from_min_size(pos2(rect.left(), rect.center().y - 7.5), Vec2::splat(15.0));
    let painter = ui.painter();
    if *checked {
        painter.rect_filled(b, 3.0, if hovered { p.accent_hover } else { p.accent });
        icons::paint(ui, &icons::CHECK_BOLD, b.shrink(2.5), Color32::WHITE);
    } else {
        painter.rect(b.shrink(0.5), 3.0, p.input, stroke(1.0, if hovered { p.text3 } else { p.border_strong }));
    }
    text_at(painter, g, b.right() + 6.0, rect.center().y);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

pub fn slider(ui: &mut Ui, p: &Palette, value: &mut f64, range: RangeInclusive<f64>, step: f64) -> Response {
    let (min, max) = (*range.start(), *range.end());
    let (rect, mut resp) = ui.allocate_exact_size(vec2(ui.available_width(), 16.0), Sense::click_and_drag());
    let x0 = rect.left() + 7.0;
    let x1 = rect.right() - 7.0;
    let snap = |v: f64| (((v - min) / step).round() * step + min).clamp(min, max);

    let mut new = *value;
    if let Some(pos) = resp.interact_pointer_pos() {
        let t = ((pos.x - x0) / (x1 - x0)).clamp(0.0, 1.0) as f64;
        new = snap(min + t * (max - min));
    }
    if resp.has_focus() {
        ui.input(|i| {
            if i.key_pressed(egui::Key::ArrowLeft) || i.key_pressed(egui::Key::ArrowDown) {
                new = snap(*value - step);
            }
            if i.key_pressed(egui::Key::ArrowRight) || i.key_pressed(egui::Key::ArrowUp) {
                new = snap(*value + step);
            }
        });
    }
    if new != *value {
        *value = new;
        resp.mark_changed();
    }

    let t = ((*value - min) / (max - min)).clamp(0.0, 1.0) as f32;
    let hx = x0 + t * (x1 - x0);
    let cy = rect.center().y;
    let painter = ui.painter();
    painter.rect_filled(Rect::from_min_max(pos2(rect.left(), cy - 2.0), pos2(rect.right(), cy + 2.0)), 2.0, p.track);
    painter.rect_filled(Rect::from_min_max(pos2(rect.left(), cy - 2.0), pos2(hx, cy + 2.0)), 2.0, p.accent);
    let active = resp.hovered() || resp.dragged();
    if resp.has_focus() {
        painter.circle_filled(pos2(hx, cy), 10.0, p.accent_soft);
    }
    painter.circle(pos2(hx, cy), 7.0, if active { p.accent_hover } else { p.accent }, stroke(2.0, p.surface));
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------
// Badges, pastilles, touches
// ---------------------------------------------------------------------------

/// Badge de port dessiné à la main (tableau). Renvoie sa largeur.
pub fn paint_port_badge(ui: &Ui, painter: &Painter, p: &Palette, text: &str, x: f32, cy: f32) -> f32 {
    let g = galley(ui, text, mono(11.5), p.badge_text);
    let w = g.size().x + 12.0;
    painter.rect_filled(Rect::from_min_size(pos2(x, cy - 10.0), vec2(w, 20.0)), 4.0, p.badge);
    text_at(painter, g, x + 6.0, cy);
    w
}

pub fn port_badge(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    let g = galley(ui, text, mono(12.0), p.badge_text);
    let (rect, resp) = ui.allocate_exact_size(vec2(g.size().x + 14.0, 22.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, p.badge);
    text_at(ui.painter(), g, rect.left() + 7.0, rect.center().y);
    resp
}

/// Pastille « ● Actif · Ping ».
pub fn status_pill(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    let g = galley(ui, text, semibold(12.0), p.ok);
    let (rect, resp) = ui.allocate_exact_size(vec2(8.0 + 7.0 + 6.0 + g.size().x + 9.0, 22.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 11.0, p.ok_soft);
    painter.circle_filled(pos2(rect.left() + 11.5, rect.center().y), 3.5, p.ok);
    text_at(painter, g, rect.left() + 21.0, rect.center().y);
    resp
}

/// Badge « ⏱ plus lent ».
pub fn slow_badge(ui: &mut Ui, p: &Palette) -> Response {
    let g = galley(ui, "plus lent", semibold(11.0), p.warn);
    let (rect, resp) = ui.allocate_exact_size(vec2(5.0 + 10.0 + 3.0 + g.size().x + 5.0, 16.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, p.warn_soft);
    icons::paint(ui, &icons::CLOCK, icon_rect(rect.left() + 5.0, rect.center().y, 10.0), p.warn);
    text_at(ui.painter(), g, rect.left() + 18.0, rect.center().y);
    resp
}

/// Touche de clavier (« F5 », « Entrée »).
pub fn kbd(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    let g = galley(ui, text, regular(12.0), p.text2);
    let (rect, resp) = ui.allocate_exact_size(vec2(g.size().x + 12.0, 20.0), Sense::hover());
    ui.painter().rect(rect.shrink(0.5), 4.0, p.surface, stroke(1.0, p.border_strong));
    text_at(ui.painter(), g, rect.left() + 6.0, rect.center().y);
    resp
}

// ---------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------

pub fn menu_title(ui: &mut Ui, p: &Palette, text: &str) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(w, 26.0), Sense::hover());
    let g = galley_trunc(ui, text, mono(11.5), p.text3, w - 20.0);
    text_at(ui.painter(), g, rect.left() + 10.0, rect.center().y);
}

pub fn menu_separator(ui: &mut Ui, p: &Palette) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(w, 9.0), Sense::hover());
    ui.painter().hline(rect.left() + 6.0..=rect.right() - 6.0, rect.center().y, stroke(1.0, p.border));
}

/// Élément de menu : icône 14, libellé 13, indication à droite (raccourci, chemin).
pub fn menu_item(ui: &mut Ui, p: &Palette, icon: Option<&Icon>, text: &str, right: Option<(&str, bool)>) -> Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, 30.0), Sense::click());
    let painter = ui.painter();
    if resp.hovered() {
        painter.rect_filled(rect, 5.0, p.hover);
    }
    let cy = rect.center().y;
    if let Some(ic) = icon {
        icons::paint(ui, ic, icon_rect(rect.left() + 10.0, cy, 14.0), p.text3);
    }
    let mut right_w = 0.0;
    if let Some((r, is_mono)) = right {
        let font = if is_mono { mono(11.5) } else { regular(11.5) };
        let g = galley(ui, r, font, p.text3);
        right_w = g.size().x + 12.0;
        text_at(painter, g.clone(), rect.right() - 10.0 - g.size().x, cy);
    }
    let g = galley_trunc(ui, text, regular(13.0), p.text, w - 34.0 - 10.0 - right_w);
    text_at(painter, g, rect.left() + 34.0, cy);
    resp
}

/// Élément de menu en police à chasse fixe (URL), sans icône.
pub fn menu_item_mono(ui: &mut Ui, p: &Palette, text: &str) -> Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, 30.0), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 5.0, p.hover);
    }
    let g = galley_trunc(ui, text, mono(12.5), p.text, w - 20.0);
    text_at(ui.painter(), g, rect.left() + 10.0, rect.center().y);
    resp
}

// ---------------------------------------------------------------------------
// Logo
// ---------------------------------------------------------------------------

const DOTS: [(f32, f32); 9] = [
    (9.0, 9.0),
    (16.0, 9.0),
    (23.0, 9.0),
    (9.0, 16.0),
    (16.0, 16.0),
    (23.0, 16.0),
    (9.0, 23.0),
    (16.0, 23.0),
    (23.0, 23.0),
];

/// Logo NetScan : carré accent, grille de points, anneau de « cible ».
pub fn paint_logo(painter: &Painter, rect: Rect, accent: Color32) {
    const OPACITY: [f32; 9] = [1.0, 0.4, 1.0, 0.4, 1.0, 0.4, 0.4, 0.4, 1.0];
    let s = rect.width() / 32.0;
    painter.rect_filled(rect, 8.0 * s, accent);
    for (i, (x, y)) in DOTS.iter().enumerate() {
        painter.circle_filled(rect.min + vec2(x * s, y * s), 2.4 * s, Color32::WHITE.gamma_multiply(OPACITY[i]));
    }
    painter.circle_stroke(rect.min + vec2(23.0 * s, 23.0 * s), 5.6 * s, stroke(1.8 * s, Color32::WHITE));
}

/// Illustration de l'état vide (grille grise, un point accent).
pub fn paint_empty_logo(painter: &Painter, rect: Rect, p: &Palette) {
    const OPACITY: [f32; 9] = [1.0, 0.45, 0.45, 0.45, 1.0, 0.45, 0.45, 0.45, 1.0];
    let s = rect.width() / 32.0;
    painter.rect(rect.shrink(0.5), 8.0 * s, p.surface2, stroke(1.0, p.border));
    for (i, (x, y)) in DOTS.iter().enumerate() {
        let color = if i == 8 { p.accent } else { p.idle.gamma_multiply(OPACITY[i]) };
        painter.circle_filled(rect.min + vec2(x * s, y * s), 2.2 * s, color);
    }
}
