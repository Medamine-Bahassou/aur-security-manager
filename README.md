<p align="center">
  <img src="logo.png" alt="AUR Security Manager" width="200" />
</p>

<h1 align="center">AUR Security Manager</h1>

<p align="center">
  <strong>A Tkinter GUI for yay/AUR with PKGBUILD Security Analysis</strong>
</p>

<p align="center">
  Search, review, and install AUR packages with safety analysis — all from a
  modern desktop interface.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License" />
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey" alt="Platform Linux | Windows" />
</p>

---

## ✨ Features

- **Search the AUR** — Query the official AUR RPC API by package name.
- **PKGBUILD Viewer** — Fetch and display any package's PKGBUILD with syntax-friendly styling.
- **Security Analysis** — Scan PKGBUILDs for dangerous patterns:
  - Destructive commands (`rm -rf /`, `dd if=...`, `mkfs`, etc.)
  - Remote code execution / pipe-to-shell
  - Obfuscation, base64, and encoded payloads
  - Persistence mechanisms (systemd services, cron, sshd)
  - Network exfiltration
  - Cryptominer signatures
  - Reverse shells
  - Setuid binaries
  - Typosquatting detection
- **Safety Gate** — Installation is blocked for critical-severity packages; high-severity requires explicit risk acceptance.
- **Malware Blacklist** — Cross-references packages against a curated database of historically malicious AUR packages with severity, reason, and incident date.
- **Remote Blacklist Sync** — Fetches live malware blocklists from remote URLs on startup.
- **Terminal Install Window** — Runs `yay -S` in a real-time terminal-like popup with coloured output.
- **Install Cancellation** — Cancel an in-progress installation at any time.

## 🖼️ Screenshots

<p align="center">
  <em>(Screenshots coming soon)</em>
</p>

## 📦 Requirements

- **Python 3.8+** (stdlib only: `tkinter`, `urllib`, `json`, `re`, `subprocess`, `threading`)
- [`yay`](https://github.com/Jguer/yay) — AUR helper (must be installed and on `PATH` for installation)
- [`pacman`](https://archlinux.org/pacman/) — Arch Linux package manager

### Python packages (optional — improves appearance)

| Package | Purpose | Installation |
|---------|---------|-------------|
| [`sv_ttk`](https://pypi.org/project/sv-ttk/) | Sun Valley theme for a modern look | `pip install sv-ttk` |
| [`darkdetect`](https://pypi.org/project/darkdetect/) | Automatic dark mode detection | `pip install darkdetect` |
| [`pywinstyles`](https://pypi.org/project/pywinstyles/) | Dark title bar on Windows 10/11 | `pip install pywinstyles` |

## 🚀 Usage

```bash
python aur_security_manager.py
```

1. **Search** — Enter a package name and click *Search AUR*.
2. **Review** — Select a package to fetch its PKGBUILD and run the security analyser.
3. **Analyse** — The *Security Findings* tab shows all flagged patterns with severity and line numbers.
4. **Install** — Click *Install with yay*. The safety gate will block or warn about dangerous packages.
5. **Monitor** — A terminal-like window shows real-time `yay` output. Cancel anytime.

## ⚙️ How It Works

### Danger Formula Engine

The analyser applies a rule-based engine that learns signatures from known-malicious AUR packages and re-applies them to any package the user tries to install. Each rule matches specific patterns in the PKGBUILD and assigns a severity score:

| Severity | Score Range | Behaviour |
|----------|-------------|-----------|
| Info | 1–10 | Informational finding |
| Low | 11–25 | Minor concern |
| Medium | 26–50 | Suspicious pattern |
| High | 51–75 | Dangerous — requires explicit confirmation |
| Critical | 76–100 | Blocked automatically |

### Safety Gate Flow

```
User clicks "Install with yay"
  ├── Critical severity → ❌ Blocked (must install manually)
  ├── High severity     → ⚠️  "I accept the risk" dialog required
  └── Below high        → ✅ Final confirmation → yay install
```

## 📜 Malware References

The analyser includes a curated database (updated as of July 2024) covering real AUR malware incidents:

- **July 2018** — Cryptominer delivered via `.install` hook (Acidanthera)
- **November 2022** — `post_install` SSH backdoor persistence
- **Discord typo-squats** — Packages mimicking popular Discord clients
- And many more historical incidents with CVE-style entries and mitigation notes

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `yay` not found | Install yay: `sudo pacman -S --needed git base-devel && git clone https://aur.archlinux.org/yay.git && cd yay && makepkg -si` |
| Theme doesn't look modern | Install `sv-ttk`: `pip install sv-ttk` |
| Dark title bar not working (Windows) | Install `pywinstyles`: `pip install pywinstyles` |

## 👤 Author

**MedAmine-Bahassou**
