// Intègre l'icône et les informations de version dans NetScan.exe.

include!("src/icon.rs");

/// Fichier .ico (images BMP 32 bits) aux tailles demandées.
fn make_ico(sizes: &[u32]) -> Vec<u8> {
    let mut images = Vec::new();
    for &s in sizes {
        let rgba = logo_rgba(s);
        let mut img = Vec::new();
        // BITMAPINFOHEADER (hauteur doublée : image + masque)
        img.extend_from_slice(&40u32.to_le_bytes());
        img.extend_from_slice(&(s as i32).to_le_bytes());
        img.extend_from_slice(&((s * 2) as i32).to_le_bytes());
        img.extend_from_slice(&1u16.to_le_bytes());
        img.extend_from_slice(&32u16.to_le_bytes());
        img.extend_from_slice(&[0u8; 24]);
        // Pixels BGRA, de bas en haut
        for y in (0..s).rev() {
            for x in 0..s {
                let i = ((y * s + x) * 4) as usize;
                img.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
            }
        }
        // Masque AND (inutilisé avec l'alpha, mais requis)
        let row = ((s + 31) / 32 * 4) as usize;
        img.extend(std::iter::repeat(0u8).take(row * s as usize));
        images.push((s, img));
    }

    let mut ico = Vec::new();
    ico.extend_from_slice(&[0, 0, 1, 0]);
    ico.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (s, img) in &images {
        let dim = if *s >= 256 { 0 } else { *s as u8 };
        ico.extend_from_slice(&[dim, dim, 0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(img.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for (_, img) in &images {
        ico.extend_from_slice(img);
    }
    ico
}

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico = out.join("netscan.ico");
    std::fs::write(&ico, make_ico(&[16, 24, 32, 48, 64, 256])).unwrap();

    let mut res = winresource::WindowsResource::new();
    res.set_icon(ico.to_str().unwrap());
    res.set("FileDescription", "NetScan - Scanner réseau IP");
    res.set("ProductName", "NetScan");
    if let Err(e) = res.compile() {
        println!("cargo:warning=Icône de l'exe non intégrée : {e}");
    }
}
