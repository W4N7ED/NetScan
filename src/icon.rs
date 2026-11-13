// Logo NetScan (carré bleu, grille de points, anneau de cible), partagé entre
// l'application (icône de fenêtre) et build.rs (icône de l'exe).
// Ce fichier ne doit dépendre de rien : il est inclus tel quel par build.rs.

/// Pixels RGBA (non prémultipliés) du logo, anticrénelé par suréchantillonnage 4×4.
pub fn logo_rgba(size: u32) -> Vec<u8> {
    const SS: u32 = 4;
    const ACCENT: [f32; 3] = [30.0, 99.0, 214.0];
    const DOTS: [(f32, f32, f32); 9] = [
        (9.0, 9.0, 1.0),
        (16.0, 9.0, 0.4),
        (23.0, 9.0, 1.0),
        (9.0, 16.0, 0.4),
        (16.0, 16.0, 1.0),
        (23.0, 16.0, 0.4),
        (9.0, 23.0, 0.4),
        (16.0, 23.0, 0.4),
        (23.0, 23.0, 1.0),
    ];

    // Coordonnées du dessin : carré de 32 × 32 (comme le SVG du design).
    let scale = size as f32 / 32.0;
    let inside = |u: f32, v: f32| {
        let cx = u.clamp(8.0, 24.0);
        let cy = v.clamp(8.0, 24.0);
        (u - cx).powi(2) + (v - cy).powi(2) <= 64.0
    };

    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let mut acc = [0f32; 3];
            let mut covered = 0u32;
            for sy in 0..SS {
                for sx in 0..SS {
                    let u = (x as f32 + (sx as f32 + 0.5) / SS as f32) / scale;
                    let v = (y as f32 + (sy as f32 + 0.5) / SS as f32) / scale;
                    if !inside(u, v) {
                        continue;
                    }
                    let mut c = ACCENT;
                    for (dx, dy, op) in DOTS {
                        if ((u - dx).powi(2) + (v - dy).powi(2)).sqrt() <= 2.4 {
                            for ch in c.iter_mut() {
                                *ch += (255.0 - *ch) * op;
                            }
                        }
                    }
                    let ring = ((u - 23.0).powi(2) + (v - 23.0).powi(2)).sqrt();
                    if (ring - 5.6).abs() <= 0.9 {
                        c = [255.0, 255.0, 255.0];
                    }
                    for i in 0..3 {
                        acc[i] += c[i];
                    }
                    covered += 1;
                }
            }
            if covered > 0 {
                let i = ((y * size + x) * 4) as usize;
                let k = covered as f32;
                out[i] = (acc[0] / k) as u8;
                out[i + 1] = (acc[1] / k) as u8;
                out[i + 2] = (acc[2] / k) as u8;
                out[i + 3] = (255.0 * k / (SS * SS) as f32) as u8;
            }
        }
    }
    out
}
