//! Outil de test (builds de débogage uniquement) : rejoue des clics et touches
//! décrits dans la variable d'environnement `NETSCAN_SCRIPT`, pour vérifier
//! l'interface sans toucher à la souris.
//!
//! Format : `secondes:action:arguments` séparés par `;`
//! ex. `9:click:450,227;10:rclick:450,259;11:move:520,433;12:key:Escape`

use eframe::egui::{self, Event, Key, Modifiers, PointerButton, Pos2, RawInput};
use std::time::Instant;

enum Step {
    Move(Pos2),
    Button(PointerButton, Pos2, bool),
    Key(Key),
}

pub struct Script {
    start: Instant,
    steps: Vec<(f64, Step)>,
    next: usize,
}

impl Script {
    pub fn from_env() -> Option<Self> {
        let src = std::env::var("NETSCAN_SCRIPT").ok()?;
        let mut steps = Vec::new();
        for part in src.split(';').filter(|s| !s.trim().is_empty()) {
            let mut it = part.trim().splitn(3, ':');
            let t: f64 = it.next()?.parse().ok()?;
            let action = it.next()?;
            let arg = it.next().unwrap_or("");
            let pos = || {
                let (x, y) = arg.split_once(',')?;
                Some(Pos2::new(x.trim().parse().ok()?, y.trim().parse().ok()?))
            };
            match action {
                "move" => steps.push((t, Step::Move(pos()?))),
                "click" | "rclick" => {
                    let b = if action == "click" { PointerButton::Primary } else { PointerButton::Secondary };
                    let p = pos()?;
                    steps.push((t, Step::Move(p)));
                    steps.push((t + 0.05, Step::Button(b, p, true)));
                    steps.push((t + 0.15, Step::Button(b, p, false)));
                }
                "key" => {
                    let k = Key::from_name(arg)?;
                    steps.push((t, Step::Key(k)));
                }
                _ => {}
            }
        }
        steps.sort_by(|a, b| a.0.total_cmp(&b.0));
        Some(Self { start: Instant::now(), steps, next: 0 })
    }

    pub fn pending(&self) -> bool {
        self.next < self.steps.len()
    }

    pub fn inject(&mut self, raw: &mut RawInput) {
        let now = self.start.elapsed().as_secs_f64();
        while self.next < self.steps.len() && self.steps[self.next].0 <= now {
            match &self.steps[self.next].1 {
                Step::Move(p) => raw.events.push(Event::PointerMoved(*p)),
                Step::Button(button, pos, pressed) => raw.events.push(Event::PointerButton {
                    pos: *pos,
                    button: *button,
                    pressed: *pressed,
                    modifiers: Modifiers::NONE,
                }),
                Step::Key(key) => {
                    for pressed in [true, false] {
                        raw.events.push(Event::Key {
                            key: *key,
                            physical_key: None,
                            pressed,
                            repeat: false,
                            modifiers: Modifiers::NONE,
                        });
                    }
                }
            }
            self.next += 1;
        }
    }
}

#[allow(dead_code)]
pub fn keep_alive(ctx: &egui::Context) {
    ctx.request_repaint_after(std::time::Duration::from_millis(16));
}
