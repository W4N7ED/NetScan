# NetScan — Scanner réseau IP (Rust)

Version graphique de `Scan-Network.ps1`, en un seul exécutable Windows (aucun runtime à installer, aucun droit administrateur requis).

## Fonctionnalités

| | |
|---|---|
| **Plages IP** | `192.168.1.0-254`, `192.168.1.1-192.168.1.50`, `192.168.1.0/24`, IP seule, ou plusieurs séparées par des virgules (max. 65 536 adresses) |
| **Réseaux détectés** | liste des interfaces locales → remplit la plage en un clic |
| **Détection** | ping ICMP, **ARP** (trouve les PC Windows qui bloquent le ping sur le même segment), **TCP** (un port ouvert suffit) |
| **Infos par hôte** | nom (DNS inverse, puis NetBIOS), adresse MAC, **fabricant** (registre IEEE embarqué), latence, ports TCP ouverts |
| **Suivi entre deux scans** | le dernier scan est rechargé au lancement ; au scan suivant, les appareils **nouveaux** et **disparus** sont signalés (taper `nouveau` ou `disparu` dans le filtre pour les isoler) |
| **Ports** | liste libre (`22,80,8000-8100`) + préréglages (Web, Windows/AD, Bases de données, 1-1024…) |
| **Tableau** | résultats en direct, tri par colonne, filtre texte (IP, nom, MAC, fabricant, port, service), affichage des inactifs |
| **Actions** (clic droit ou panneau de détails) | ouvrir http/https, RDP, partages SMB, SSH, ping continu, traceroute, Wake-on-LAN, rescanner un seul hôte, copier IP/nom/MAC |
| **Export** | CSV (séparateur `;`, compatible Excel, colonnes du script PowerShell + `Detection` et `Vendor`) ou copie collable dans Excel |
| **Clavier** | F5 lancer · Entrée (dans Plage IP / Ports) lancer · Échap arrêter, fermer le menu ou désélectionner · ↑/↓ changer d'hôte · Ctrl+C copier l'IP · Ctrl+Maj+C copier la ligne |
| **Confort** | thème clair/sombre (celui de Windows au premier lancement), réglages mémorisés, fenêtre sans barre de titre qui retrouve sa taille, sa position et son état agrandi |

Les réglages et le dernier scan sont enregistrés dans `%APPDATA%\NetScan\data` (`app.ron`, `last_scan.tsv`).

Interface : design « NetScan · egui » réalisé avec Claude Design (tokens de couleurs, typographie Segoe UI / Consolas, icônes Lucide).

## Utilisation

Double-cliquer sur `NetScan.exe`, ou en ligne de commande :

```
NetScan.exe 192.168.1.0/24 --start
```

(`--start` lance le scan immédiatement ; pratique dans un raccourci.)

## Compilation

Prérequis : [Rust](https://rustup.rs) + Visual Studio Build Tools (charge de travail C++).

```
cargo build --release
```

L'exécutable est produit dans `target\release\NetScan.exe`.

> Si le dossier du projet a un chemin très long (> 260 caractères avec `target\...`),
> l'éditeur de liens échoue (LNK1104). Il suffit alors de définir un dossier de sortie court :
> `set CARGO_TARGET_DIR=C:\build\netscan`

Tests : `cargo test` (analyse des plages, ports, messages d'erreur, fabricants, enregistrement du dernier scan) — `cargo test -- --ignored --nocapture` lance un vrai scan des 20 premières adresses du réseau local.

En build de débogage, la variable `NETSCAN_SCRIPT` rejoue des clics et touches pour tester l'interface sans souris
(ex. `13:rclick:450,279;16:key:Escape`, voir `src/demo.rs`). Les coordonnées sont en points depuis le coin
haut-gauche de la fenêtre ; la première ligne du tableau est centrée sur y = 247. Ce code n'est pas compilé en release.

## Structure

- `src/scanner.rs` — moteur : analyse des plages, ping (API Windows `IcmpSendEcho`), ARP (`SendARP`), DNS/NetBIOS, ports TCP, pool de threads
- `src/app.rs` — fenêtre principale : panneau de paramètres, statistiques, tableau, détails, menu contextuel, barre d'état, boutons de fenêtre
- `src/history.rs` — dernier scan enregistré sur disque, comparaison nouveaux / disparus
- `src/win.rs` — thème de Windows, présence d'un écran (restauration de la fenêtre)
- `src/widgets.rs` — composants du design (boutons, champs, interrupteurs, curseurs, badges, éléments de menu, logo)
- `src/theme.rs` — tokens du design (palettes claire/sombre), polices, style egui
- `src/icons.rs` — icônes Lucide en SVG, teintées à l'affichage
- `src/icon.rs` + `build.rs` — logo dessiné par le code et intégré à l'exe
- `src/demo.rs` — rejeu de clics pour les tests (débogage uniquement)
