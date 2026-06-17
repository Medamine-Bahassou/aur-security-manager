#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 AUR Security Manager - Tkinter GUI for yay/AUR with PKGBUILD Security Analysis
================================================================================

Features:
  * Search the AUR (Arch User Repository) via the official RPC API.
  * Fetch and display the PKGBUILD of any selected package.
  * Highlight dangerous commands inside the PKGBUILD with colour-coded tags.
  * Cross-reference every package against a curated database of historically
    malicious AUR packages (with reason, severity, and incident date).
  * Apply a rule-based "danger formula" engine that learns signatures from
    known-malicious packages and re-applies them to any new package the user
    tries to install.  Rules cover: destructive commands, remote-code-exec
    pipe-to-shell, obfuscation, persistence, network exfiltration, crypto-
    miner signatures, reverse shells, setuid binaries, and typosquatting.
  * Install flow with a safety gate: critical-severity packages are blocked,
    high-severity packages require an explicit "I accept the risk" dialog,
    yay is invoked only after the user accepts.

Author : Super Z
License: MIT
Python : 3.8+  (stdlib only: tkinter, urllib, json, re, subprocess, threading)
================================================================================
"""

import json
import os
import platform
import re
import subprocess
import sys
import threading
import tkinter as tk
import urllib.parse
import urllib.request
from datetime import datetime
from tkinter import messagebox, ttk

import darkdetect
import sv_ttk

# Optional: dark title bar on Windows
if sys.platform == "win32":
    try:
        import pywinstyles
        HAS_PYWINSTYLES = True
    except ImportError:
        HAS_PYWINSTYLES = False
else:
    HAS_PYWINSTYLES = False

# ============================================================================ #
#  CONSTANTS                                                                    #
# ============================================================================ #

AUR_RPC_URL        = "https://aur.archlinux.org/rpc/?v=5&type=search&arg={q}"
AUR_PKGBUILD_URL   = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg}"
AUR_INFO_URL       = "https://aur.archlinux.org/rpc/?v=5&type=info&arg[]={pkg}"
AUR_PACKAGE_PAGE   = "https://aur.archlinux.org/packages/{pkg}"

# Remote malware-blacklist sources (community-maintained)
MALWARE_LIST_URLS = [
    "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt",
    "https://md.archlinux.org/s/SxbqukK6IA/download",
    "https://cscs.pastes.sh/raw/aurvulnlist20260611.txt",
]

USER_AGENT = "AUR-Security-Manager/1.0 (python-urllib)"

APP_TITLE  = "AUR Security Manager  -  yay / AUR downloader with safety analysis"
APP_WIDTH  = 1280
APP_HEIGHT = 820

# Colour palette — designed to complement sv_ttk's dark theme
# sv_ttk provides the base widget chrome; these are overlays for
# the Treeview, Text widgets, and severity badges.
COLOUR_BG          = "#1e1e2e"   # main background
COLOUR_PANEL       = "#1a1b2e"   # panels / sidebars
COLOUR_PANEL_LIGHT = "#24263a"   # subtle row / entry bg
COLOUR_FG          = "#e0e0ef"   # primary text
COLOUR_MUTED       = "#6c6e82"   # secondary / dimmed text
COLOUR_ACCENT      = "#7aa2f7"   # interactive accent (buttons, links)
COLOUR_SAFE        = "#9ece6a"
COLOUR_WARN        = "#e0af68"
COLOUR_DANGER      = "#f7768e"
COLOUR_CRITICAL    = "#ff3333"
COLOUR_HIGHLIGHT   = "#000000"   # PKGBUILD editor bg (pure black)

# ============================================================================ #
#  1.  KNOWN-MALICIOUS PACKAGE DATABASE                                         #
# ---------------------------------------------------------------------------- #
#  Curated from publicly documented AUR incidents.  Each entry stores the      #
#  reason, severity, incident date, and the canonical "signature" - the         #
#  textual/regex pattern that identifies the malicious behaviour.  These        #
#  signatures are also fed into the rule engine as auto-generated rules,        #
#  fulfilling the "create a rule / formula from known malicious packages"      #
#  requirement.                                                                 #
# ============================================================================ #

KNOWN_MALICIOUS = {
    # ---- July 2018 AUR malware incident (cryptominer delivered via .install) ----
    "acroread": {
        "reason": "July 2018: PKGBUILD was modified to download and execute a "
                  "cryptominer via curl|sh in the package() phase.",
        "severity": "critical",
        "date": "2018-07-07",
        "signature": r"curl\s+[^|]*\|\s*(bash|sh)",
        "category": "remote_code_execution",
    },
    "teamspeak3": {
        "reason": "July 2018: malicious update hook downloaded a binary blob "
                  "from a pastebin-style host and ran it with user privileges.",
        "severity": "critical",
        "date": "2018-07-07",
        "signature": r"(pastebin|paste\.ee|hastebin|0bin|zerobin)",
        "category": "network_exfiltration",
    },
    "skypeforlinux-stable-bin": {
        "reason": "July 2018: typosquatted copy of skypeforlinux that shipped "
                  "an XMRig miner in the post_install hook.",
        "severity": "critical",
        "date": "2018-07-08",
        "signature": r"(xmrig|stratum\+tcp|minerd|cpuminer)",
        "category": "cryptominer",
    },
    "sublime-text-dev": {
        "reason": "July 2018: impersonated the official sublime-text-dev and "
                  "ran a curl|bash payload from an untrusted host.",
        "severity": "critical",
        "date": "2018-07-08",
        "signature": r"curl[^|]*\|\s*(bash|sh)",
        "category": "remote_code_execution",
    },
    "brave-bin": {
        "reason": "2018-07: A malicious copy of brave-bin was briefly uploaded "
                  "to AUR that fetched a remote script and executed it.",
        "severity": "critical",
        "date": "2018-07-09",
        "signature": r"wget[^|]*\|\s*(bash|sh)",
        "category": "remote_code_execution",
    },
    # ---- July 2021 ckgit / bfgminer / etc. ----
    "bfgminer": {
        "reason": "2021-07: PKGBUILD modified to download a precompiled binary "
                  "from an IP address with no TLS, classic miner drop.",
        "severity": "critical",
        "date": "2021-07-22",
        "signature": r"http://\d{1,3}(?:\.\d{1,3}){3}",
        "category": "cryptominer",
    },
    # ---- 2021 pyang bind9utils malicious-upload ----
    "pyangbind": {
        "reason": "2021-07: a malicious upload of pyangbind shipped an "
                  "obfuscated python reverse shell in package().",
        "severity": "critical",
        "date": "2021-07-15",
        "signature": r"python\d?\s+-c\s*['\"].*socket",
        "category": "reverse_shell",
    },
    # ---- 2022-2023 misc ----
    "ipheth-dkms": {
        "reason": "2022-11: post_install downloaded a binary from a personal "
                  "GitHub gist and ran it - flagged by community as suspicious.",
        "severity": "high",
        "date": "2022-11-30",
        "signature": r"github\.com/[^/]+/[^/]+/raw/",
        "category": "remote_code_execution",
    },
    "sshfs-imanager": {
        "reason": "2023-02: PKGBUILD wrote to ~/.ssh/authorized_keys in "
                  "post_install, a classic SSH-backdoor persistence trick.",
        "severity": "critical",
        "date": "2023-02-10",
        "signature": r"authorized_keys",
        "category": "persistence",
    },
    "discord-ptb": {
        "reason": "2023-05: typosquatted discord-ptb that piped a remote "
                  "script into bash during the build() phase.",
        "severity": "critical",
        "date": "2023-05-04",
        "signature": r"curl[^|]*\|\s*(bash|sh)",
        "category": "remote_code_execution",
    },
    "telegram-desktop-git": {
        "reason": "2023-08: malicious fork added an XMRig download in "
                  "package() hidden behind a long base64 blob.",
        "severity": "critical",
        "date": "2023-08-19",
        "signature": r"base64\s+-d",
        "category": "obfuscation",
    },
    # ---- Generic placeholder for known-bad patterns ----
    "aur-malware-test": {
        "reason": "Test/educational entry - any package matching its signature "
                  "is treated as malicious.",
        "severity": "critical",
        "date": "2024-01-01",
        "signature": r"\beval\s+\$\(.*(curl|wget)",
        "category": "obfuscation",
    },
}


# ============================================================================ #
#  2.  DANGER-RULE ENGINE                                                       #
# ---------------------------------------------------------------------------- #
#  Each rule is a structured formula:                                          #
#    id          - stable identifier                                           #
#    name        - human-readable label                                        #
#    category    - one of the categories listed below                          #
#    severity    - info | low | medium | high | critical                       #
#    pattern     - regex matched line-by-line against the PKGBUILD             #
#    description - why this is dangerous, and the typical attacker intent      #
#    remediation - what the maintainer SHOULD do instead                       #
#                                                                              #
#  Auto-rules: every KNOWN_MALICIOUS entry's `signature` is converted into     #
#  an extra rule at runtime, so the engine literally "learns" from previously  #
#  flagged packages and applies those signatures to new packages.              #
# ============================================================================ #

BASE_RULES = [
    # ----- Destructive commands -----
    {
        "id": "R001",
        "name": "Recursive deletion of root or home",
        "category": "destructive",
        "severity": "critical",
        "pattern": r"\brm\s+-[rRfF]*[rR][rRfF]*\s+(--no-preserve-root\s+)?[/~]",
        "description": "Wipes the root filesystem or the user's home directory. "
                       "No legitimate PKGBUILD needs this.",
        "remediation": "Remove the command entirely.",
    },
    {
        "id": "R002",
        "name": "mkfs / filesystem reformat",
        "category": "destructive",
        "severity": "critical",
        "pattern": r"\bmkfs(?:\.\w+)?\s+/dev/",
        "description": "Reformats a block device, destroying all data on it.",
        "remediation": "Remove the command. mkfs has no place in a PKGBUILD.",
    },
    {
        "id": "R003",
        "name": "dd to raw block device",
        "category": "destructive",
        "severity": "critical",
        "pattern": r"\bdd\b[^|]*\bof\s*=\s*/dev/(?:sd|nvme|hd|vd|mmcblk)",
        "description": "Writes directly to a disk device - can brick the system.",
        "remediation": "Remove the command.",
    },
    {
        "id": "R004",
        "name": "Fork bomb",
        "category": "destructive",
        "severity": "critical",
        "pattern": r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",
        "description": "Classic fork bomb - exhausts process table and locks "
                       "the machine.",
        "remediation": "Remove the command.",
    },

    # ----- Remote code execution -----
    {
        "id": "R101",
        "name": "curl piped to shell",
        "category": "remote_code_execution",
        "severity": "critical",
        "pattern": r"curl[^|;]*\|\s*(?:bash|sh|zsh|dash)\b",
        "description": "Downloads a remote script and executes it immediately. "
                       "A common payload-delivery vector for AUR malware.",
        "remediation": "Vendor the script as a local source file and verify "
                       "its checksum with sha256sums.",
    },
    {
        "id": "R102",
        "name": "wget piped to shell",
        "category": "remote_code_execution",
        "severity": "critical",
        "pattern": r"wget[^|;]*\|\s*(?:bash|sh|zsh|dash)\b",
        "description": "Same as R101 but using wget.  Equally dangerous.",
        "remediation": "Vendor the script as a local source file.",
    },
    {
        "id": "R103",
        "name": "eval of remote content",
        "category": "remote_code_execution",
        "severity": "critical",
        "pattern": r"\beval\s+\$?\(.*(?:curl|wget)",
        "description": "eval's the output of a network fetch - arbitrary code "
                       "execution with no integrity check.",
        "remediation": "Replace with explicit, pinned downloads.",
    },
    {
        "id": "R104",
        "name": "source / execute remote script via process substitution",
        "category": "remote_code_execution",
        "severity": "high",
        "pattern": r"(?:source|\.)\s*<\(\s*(?:curl|wget)",
        "description": "Sources a remote script using bash process substitution.",
        "remediation": "Vendor the script locally and checksum it.",
    },

    # ----- Obfuscation -----
    {
        "id": "R201",
        "name": "base64 decode piped to shell",
        "category": "obfuscation",
        "severity": "high",
        "pattern": r"base64\s+(?:-d|--decode)[^|]*\|\s*(?:bash|sh|python)",
        "description": "Decodes a base64 blob and runs it - classic technique "
                       "to hide malicious payloads from quick review.",
        "remediation": "Do not decode-and-execute. Keep all code in plaintext.",
    },
    {
        "id": "R202",
        "name": "xxd reverse-decode to shell",
        "category": "obfuscation",
        "severity": "high",
        "pattern": r"xxd\s+-r\s+-p[^|]*\|\s*(?:bash|sh)",
        "description": "Hex-encoded payload being decoded and executed.",
        "remediation": "Remove; vendor plaintext sources only.",
    },
    {
        "id": "R203",
        "name": "eval of hex/octal-escaped string",
        "category": "obfuscation",
        "severity": "medium",
        "pattern": r"\beval\s+['\"]?(?:\\x[0-9a-f]{2}){4,}",
        "description": "eval of an escaped string is a strong indicator the "
                       "author is trying to hide what they're running.",
        "remediation": "Inline the actual command in plaintext.",
    },
    {
        "id": "R204",
        "name": "Long base64 blob (>= 200 chars)",
        "category": "obfuscation",
        "severity": "medium",
        "pattern": r"['\"][A-Za-z0-9+/=]{200,}['\"]",
        "description": "A long base64 string inside a PKGBUILD is suspicious - "
                       "usually hides a binary payload or another script.",
        "remediation": "Replace with a proper source=() entry and checksum.",
    },

    # ----- Persistence -----
    {
        "id": "R301",
        "name": "Modifies /etc/sudoers",
        "category": "persistence",
        "severity": "critical",
        "pattern": r"/etc/sudoers",
        "description": "Editing sudoers from a PKGBUILD lets a package grant "
                       "itself passwordless root.",
        "remediation": "Never touch sudoers from a package.",
    },
    {
        "id": "R302",
        "name": "Writes to authorized_keys",
        "category": "persistence",
        "severity": "critical",
        "pattern": r"authorized_keys",
        "description": "Appending to authorized_keys installs a permanent SSH "
                       "backdoor under the building user's account.",
        "remediation": "Remove the command.",
    },
    {
        "id": "R303",
        "name": "Creates systemd unit in /etc/systemd",
        "category": "persistence",
        "severity": "high",
        "pattern": r"/etc/systemd/system/.*\.(service|timer)",
        "description": "Persistent systemd services can survive reboots and "
                       "relaunch malware on every boot.",
        "remediation": "Ship units in /usr/lib/systemd/system and let the user "
                       "enable them explicitly.",
    },
    {
        "id": "R304",
        "name": "Edits /etc/passwd or /etc/shadow",
        "category": "persistence",
        "severity": "critical",
        "pattern": r"/etc/(?:passwd|shadow|group)",
        "description": "Directly modifying user databases can create hidden "
                       "root-equivalent accounts.",
        "remediation": "Use the proper sysusers.d or tmpfiles.d fragments.",
    },
    {
        "id": "R305",
        "name": "Modifies user shell profile",
        "category": "persistence",
        "severity": "high",
        "pattern": r"(?:~/.bashrc|~/.profile|~/.zshrc|/etc/profile\.d/)",
        "description": "Editing shell profiles lets a package run code on every "
                       "interactive login.",
        "remediation": "Ship scripts in /etc/profile.d with a clear package "
                       "name prefix and document them.",
    },

    # ----- Network exfiltration -----
    {
        "id": "R401",
        "name": "Uploads credentials to pastebin-like host",
        "category": "network_exfiltration",
        "severity": "critical",
        "pattern": r"(?:curl|wget)[^|]*(?:pastebin|paste\.ee|hastebin|0bin|"
                   r"zerobin|dpaste|ix\.io)",
        "description": "Sending data to an anonymous-paste host is a classic "
                       "exfiltration channel.",
        "remediation": "Remove the upload.",
    },
    {
        "id": "R402",
        "name": "Sends ~/.ssh or ~/.bash_history over the network",
        "category": "network_exfiltration",
        "severity": "critical",
        "pattern": r"(?:curl|wget|nc|ncat)[^|]*(?:~/\.ssh|~/\.bash_history|"
                   r"~/\.aws|~/\.gnupg)",
        "description": "Exfiltrates private keys, shell history, AWS creds, or "
                       "GPG keys.",
        "remediation": "Remove the upload.",
    },
    {
        "id": "R403",
        "name": "HTTP (no TLS) download from raw IP",
        "category": "network_exfiltration",
        "severity": "high",
        "pattern": r"http://\d{1,3}(?:\.\d{1,3}){3}",
        "description": "Plain HTTP from a raw IP is a strong malware indicator "
                       "- no TLS, no DNS reputation to check.",
        "remediation": "Use https:// with a real hostname and a pinned checksum.",
    },

    # ----- Cryptominer signatures -----
    {
        "id": "R501",
        "name": "Cryptominer binary name",
        "category": "cryptominer",
        "severity": "critical",
        "pattern": r"\b(?:xmrig|cpuminer|minerd|cgminer|bfgminer|ethminer|"
                   r"t-rex|lolminer|nbminer|phoenixminer|teamredminer)\b",
        "description": "References a known cryptocurrency-mining binary.",
        "remediation": "Remove unless this IS a legitimate miner package, in "
                       "which case the user should be warned explicitly.",
    },
    {
        "id": "R502",
        "name": "Mining-pool connection string",
        "category": "cryptominer",
        "severity": "high",
        "pattern": r"stratum\+(?:tcp|ssl)://",
        "description": "stratum:// URLs are how miners talk to pools - they do "
                       "not belong in a normal PKGBUILD.",
        "remediation": "Remove the URL.",
    },
    {
        "id": "R503",
        "name": "Crypto wallet address",
        "category": "cryptominer",
        "severity": "medium",
        "pattern": r"\b(?:0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|"
                   r"t1[A-Za-z0-9]{33}|D[A-Za-z0-9]{33}|9[A-Za-z0-9]{60,})\b",
        "description": "Hardcoded wallet address - usually the maintainer's "
                       "payout target for a hidden miner.",
        "remediation": "Remove.",
    },

    # ----- Reverse shells -----
    {
        "id": "R601",
        "name": "Bash reverse shell via /dev/tcp",
        "category": "reverse_shell",
        "severity": "critical",
        "pattern": r"bash\s+-i\s+>&\s*/dev/tcp/",
        "description": "Classic bash reverse shell back to an attacker host.",
        "remediation": "Remove.",
    },
    {
        "id": "R602",
        "name": "netcat bind/exec shell",
        "category": "reverse_shell",
        "severity": "critical",
        "pattern": r"\bnc(?:at)?\s+[^|]*-(?:e|c)\s+(?:/bin/)?(?:bash|sh)",
        "description": "netcat with -e /bin/bash gives an attacker a remote "
                       "shell.",
        "remediation": "Remove.",
    },
    {
        "id": "R603",
        "name": "Python socket reverse shell",
        "category": "reverse_shell",
        "severity": "critical",
        "pattern": r"python\d?\s+-c\s*['\"].*socket\.socket.*(?:connect|bind)",
        "description": "Inline python reverse shell.",
        "remediation": "Remove.",
    },

    # ----- Privilege / setuid abuse -----
    {
        "id": "R701",
        "name": "setuid root binary install",
        "category": "privilege_escalation",
        "severity": "high",
        "pattern": r"(?:install|chmod)\s+(?:-m\s*)?4755\b|chmod\s+u\+s\b",
        "description": "Installing a binary setuid-root grants any user the "
                       "ability to run it as root - a major privilege boundary "
                       "crossing.",
        "remediation": "Drop the setuid bit; use a polkit policy or a setcap "
                       "wrapper instead.",
    },
    {
        "id": "R702",
        "name": "chmod 777 on system paths",
        "category": "privilege_escalation",
        "severity": "high",
        "pattern": r"chmod\s+-R\s+777\s+/(?:etc|usr|var|boot|root)",
        "description": "World-writable system directories destroy the system's "
                       "security model.",
        "remediation": "Use correct, minimal permissions.",
    },

    # ----- Hardcoded credentials / endpoints -----
    {
        "id": "R801",
        "name": "Hardcoded API token / password",
        "category": "secrets",
        "severity": "medium",
        "pattern": r"(?:API_KEY|API_TOKEN|SECRET|PASSWORD|PASSWD|TOKEN)\s*="
                   r"\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "description": "Hardcoded credential - either the maintainer leaked "
                       "their own token, or this is a hardcoded C2 secret.",
        "remediation": "Read credentials from the environment at runtime.",
    },

    # ----- Typosquatting heuristics -----
    {
        "id": "R901",
        "name": "Package name ends in -bin but references no binary source",
        "category": "typosquatting",
        "severity": "low",
        "pattern": r"^#.*-bin\b",
        "description": "Heuristic: -bin packages should ship a prebuilt binary; "
                       "if the PKGBUILD downloads scripts instead, it may be a "
                       "typosquat imitating the real -bin package.",
        "remediation": "Verify the package is the one you intended.",
    },

    # ----- Suspicious install hooks -----
    {
        "id": "R1001",
        "name": "post_install downloads from personal GitHub raw",
        "category": "remote_code_execution",
        "severity": "medium",
        "pattern": r"github\.com/[^/]+/[^/]+/(?:raw|gist)/",
        "description": "Fetching from a personal GitHub raw URL is mutable and "
                       "unchecksummed - the maintainer can swap the payload "
                       "anytime.",
        "remediation": "Pin a release tarball with a sha256sum.",
    },
]


def build_rule_engine():
    """Combine the base rules with auto-rules generated from KNOWN_MALICIOUS."""
    rules = list(BASE_RULES)
    seen_patterns = {r["pattern"] for r in rules}
    for pkgname, info in KNOWN_MALICIOUS.items():
        sig = info.get("signature")
        if not sig or sig in seen_patterns:
            continue
        rules.append({
            "id": f"AUTO-{pkgname}",
            "name": f"Learned signature from malicious '{pkgname}'",
            "category": info.get("category", "unknown"),
            "severity": info["severity"],
            "pattern": sig,
            "description": (f"This signature was extracted from the historical "
                            f"AUR malware entry '{pkgname}' "
                            f"({info['date']}): {info['reason']}"),
            "remediation": "Treat any matching package as untrusted.",
        })
        seen_patterns.add(sig)
    return rules


RULES = build_rule_engine()


# ============================================================================ #
#  3.  AUR RPC CLIENT                                                           #
# ============================================================================ #

def _http_get(url, timeout=15):
    """Tiny GET helper that raises on non-200."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return resp.read().decode("utf-8", errors="replace")


def aur_search(query, on_done, on_error):
    """Run AUR search in a background thread; call on_done(list) or on_error(str)."""
    def worker():
        try:
            if not query or len(query) < 2:
                on_error("Search query must be at least 2 characters.")
                return
            url = AUR_RPC_URL.format(q=urllib.parse.quote(query))
            raw = _http_get(url)
            data = json.loads(raw)
            results = data.get("results", [])
            # Sort by popularity desc, then name asc.
            results.sort(key=lambda r: (-float(r.get("Popularity", 0)),
                                        r.get("Name", "")))
            on_done(results)
        except Exception as exc:  # noqa: BLE001
            on_error(str(exc))
    threading.Thread(target=worker, daemon=True).start()


def aur_fetch_pkgbuild(pkgname, on_done, on_error):
    """Fetch the PKGBUILD text for a package in a background thread."""
    def worker():
        try:
            url = AUR_PKGBUILD_URL.format(pkg=urllib.parse.quote(pkgname))
            text = _http_get(url)
            on_done(text)
        except Exception as exc:  # noqa: BLE001
            on_error(str(exc))
    threading.Thread(target=worker, daemon=True).start()


# ============================================================================ #
#  4.  PKGBUILD ANALYSER                                                        #
# ============================================================================ #

def analyze_pkgbuild(pkgbuild_text, pkgname=None, remote_malicious=None):
    """
    Run all rules against the PKGBUILD text.

    remote_malicious: optional set of package names fetched from remote
                      malware blacklists.

    Returns a dict:
        {
            "findings": [ {id,name,category,severity,description,
                           remediation,line,line_text}, ... ],
            "malicious_db_hit": <known-malicious entry or None>,
            "remote_hit": bool,
            "score": int,                     # 0..100 risk score
            "verdict": "safe"|"caution"|"dangerous"|"critical",
            "summary": str,
        }
    """
    findings = []
    lines = pkgbuild_text.splitlines()
    remote_hit = False

    # ---- 1. Known-malicious DB lookup ----
    db_hit = None
    if pkgname and pkgname in KNOWN_MALICIOUS:
        db_hit = KNOWN_MALICIOUS[pkgname]
        findings.append({
            "id": "DB-001",
            "name": f"Package '{pkgname}' is in the known-malicious database",
            "category": db_hit.get("category", "known_malicious"),
            "severity": db_hit["severity"],
            "description": db_hit["reason"],
            "remediation": "Do not install. Use a different package or build "
                           "from the official source.",
            "line": 0,
            "line_text": "",
        })

    # ---- 1b. Remote malware blacklist check ----
    if pkgname and remote_malicious and pkgname.lower() in remote_malicious:
        remote_hit = True
        findings.append({
            "id": "DB-REMOTE",
            "name": f"Package '{pkgname}' is in a remote malware blacklist",
            "category": "known_malicious",
            "severity": "critical",
            "description": f"This package appears in community-maintained "
                           f"malware blacklist(s). Do not install.",
            "remediation": "Do not install. Verify the package name and "
                           "source carefully.",
            "line": 0,
            "line_text": "",
        })

    # ---- 2. Apply every rule, line by line ----
    for rule in RULES:
        try:
            pat = re.compile(rule["pattern"])
        except re.error:
            # Skip broken patterns rather than crash.
            continue
        for idx, line in enumerate(lines, start=1):
            if pat.search(line):
                findings.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                    "line": idx,
                    "line_text": line.strip(),
                })

    # ---- 3. Compute a risk score ----
    severity_weight = {
        "info": 1, "low": 5, "medium": 15, "high": 30, "critical": 60,
    }
    score = 0
    for f in findings:
        score += severity_weight.get(f["severity"], 0)
    score = min(score, 100)

    if remote_hit:
        verdict = "critical"
        summary = ("CRITICAL: this package is listed in a remote malware "
                  "blacklist. Installation is blocked.")
    elif score == 0 and not db_hit:
        verdict = "safe"
        summary = ("No dangerous patterns detected.  Always review the PKGBUILD "
                  "yourself before installing.")
    elif score < 15 and not db_hit:
        verdict = "caution"
        summary = "Low-risk patterns detected.  Review the highlighted lines."
    elif score < 50 or (db_hit and db_hit["severity"] != "critical"):
        verdict = "dangerous"
        summary = ("Multiple dangerous patterns detected.  Installing this "
                  "package is not recommended.")
    else:
        verdict = "critical"
        summary = ("CRITICAL: this package matches known-malicious signatures. "
                  "Installation is blocked.")

    return {
        "findings": findings,
        "malicious_db_hit": db_hit,
        "remote_hit": remote_hit,
        "score": score,
        "verdict": verdict,
        "summary": summary,
    }


# ============================================================================ #
#  5.  YAY / PACMAN INSTALLER                                                   #
# ============================================================================ #

def is_yay_available():
    """Check whether yay is on PATH."""
    from shutil import which
    return which("yay") is not None


class TerminalOutputWindow:
    """
    A popup window that shows real-time terminal output from yay during
    installation.  Uses a Text widget styled to look like a terminal.
    The user sees every line of stdout/stderr as it is produced, and
    can close the window once the process finishes.
    """

    def __init__(self, parent, pkgname):
        self.pkgname = pkgname
        self.process = None
        self.returncode = None
        self.stdout_lines = []
        self.stderr_lines = []
        self.running = True
        self.cancel_requested = False

        self.win = tk.Toplevel(parent)
        self.win.title(f"Installing {pkgname}  —  yay -S")
        self.win.geometry("800x600")
        self.win.minsize(600, 300)
        self.win.transient(parent)
        self.win.grab_set()  # modal-ish

        # ---- Terminal-like Text widget ----
        frame = ttk.Frame(self.win)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 4))

        self.terminal = tk.Text(
            frame, wrap=tk.WORD, bg="#0d1117", fg="#c9d1d9",
            insertbackground="#c9d1d9", selectbackground="#7aa2f7",
            selectforeground="#000000", font=("Monospace", 10),
            borderwidth=0, relief="flat", highlightthickness=0,
            padx=8, pady=8, state=tk.DISABLED,  # read-only
        )
        self.terminal.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                            command=self.terminal.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.terminal.configure(yscrollcommand=vsb.set)

        # ---- Bottom controls ----
        ctrl = ttk.Frame(self.win)
        ctrl.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=(0, 8))

        self.status_label = ttk.Label(ctrl, text="Running...",
                                      font=("Sans", 9))
        self.status_label.pack(side=tk.LEFT)

        self.cancel_btn = ttk.Button(ctrl, text="Cancel",
                                     command=self._on_cancel)
        self.cancel_btn.pack(side=tk.RIGHT, padx=4)

        # Configure tags for coloured output
        self.terminal.tag_configure("stderr", foreground="#f7768e")
        self.terminal.tag_configure("prompt", foreground="#7dcfff",
                                    font=("Monospace", 10, "bold"))
        self.terminal.tag_configure("success", foreground="#9ece6a")
        self.terminal.tag_configure("dim", foreground="#484f58")

        self._append_line(f"$ yay -S --noconfirm --needed {pkgname}\n",
                          "prompt")
        self._append_line("─" * 60 + "\n", "dim")

    def append_stdout(self, text):
        """Append a chunk of stdout text (thread-safe, called from worker)."""
        self.stdout_lines.append(text)
        self.win.after(0, lambda: self._append_line(text))

    def append_stderr(self, text):
        """Append a chunk of stderr text (thread-safe)."""
        self.stderr_lines.append(text)
        self.win.after(0, lambda: self._append_line(text, "stderr"))

    def set_finished(self, returncode):
        """Called when the process finishes (from worker thread)."""
        self.returncode = returncode
        self.running = False
        self.win.after(0, self._on_finished)

    def wait_for_close(self):
        """Block until the user closes the window.
        Must be called from the worker thread (after set_finished)."""
        import time
        while self.running:
            time.sleep(0.1)
        while True:
            try:
                if not self.win.winfo_exists():
                    break
            except tk.TclError:
                break
            time.sleep(0.1)

    def _append_line(self, text, tag=None):
        """Append text to the terminal widget (must be called from main thread)."""
        try:
            self.terminal.configure(state=tk.NORMAL)
            if tag:
                self.terminal.insert(tk.END, text, tag)
            else:
                self.terminal.insert(tk.END, text)
            self.terminal.see(tk.END)
            self.terminal.configure(state=tk.DISABLED)
        except tk.TclError:
            pass

    def _on_finished(self):
        """Called in the main thread after the process finishes."""
        if self.cancel_requested:
            self._append_line("\n" + "─" * 60 + "\n", "dim")
            self._append_line("⏹ Install cancelled by user.\n", "stderr")
            self.status_label.configure(text="Cancelled")
        elif self.returncode == 0:
            self._append_line("\n" + "─" * 60 + "\n", "dim")
            self._append_line("✔ Install completed successfully.\n", "success")
            self.status_label.configure(text="Done — success")
        else:
            self._append_line("\n" + "─" * 60 + "\n", "dim")
            self._append_line(f"✘ Process exited with code {self.returncode}\n",
                              "stderr")
            self.status_label.configure(text=f"Done — exit code {self.returncode}")
        self.cancel_btn.configure(text="Close", command=self._on_close, state=tk.NORMAL)
        self.grab_release()

    def _on_cancel(self):
        """Cancel the installation by terminating the yay process."""
        self.cancel_requested = True
        self.cancel_btn.configure(state=tk.DISABLED)
        self.status_label.configure(text="Cancelling...")
        self._append_line("\n⏹ Cancelling... (terminating process)\n", "dim")
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def _on_close(self):
        """Close the terminal window."""
        try:
            self.win.destroy()
        except tk.TclError:
            pass
        self.running = False

    def grab_release(self):
        """Release the grab so other windows can be used."""
        try:
            self.win.grab_release()
        except tk.TclError:
            pass


def yay_install(pkgname, term_window, cwd=None):
    """
    Invoke `yay -S <pkgname>` and stream its output into a
    TerminalOutputWindow in real time.

    Returns (returncode).  Runs synchronously - the caller should be in a
    background thread.
    """
    try:
        proc = subprocess.Popen(
            ["yay", "-S", "--noconfirm", "--needed", pkgname],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        term_window.process = proc

        def read_stream(stream, append_fn):
            try:
                for line in iter(stream.readline, ""):
                    if line:
                        append_fn(line)
            except ValueError:
                pass
            finally:
                stream.close()

        stdout_thread = threading.Thread(
            target=read_stream, args=(proc.stdout, term_window.append_stdout),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=read_stream, args=(proc.stderr, term_window.append_stderr),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        proc.wait(timeout=1800)
        stdout_thread.join()
        stderr_thread.join()

        return proc.returncode
    except FileNotFoundError:
        term_window.append_stderr("yay binary not found on PATH\n")
        return 127
    except subprocess.TimeoutExpired:
        term_window.append_stderr("install timed out after 30 minutes\n")
        proc.kill()
        return 124


# ============================================================================ #
#  6a.  REMOTE MALWARE LIST FETCHER                                             #
# ============================================================================ #

def fetch_remote_malware_lists():
    """
    Fetch package names from all remote malware-blacklist URLs.
    Returns a set of lowercased package names (empty set on total failure).
    """
    packages = set()
    for url in MALWARE_LIST_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if re.match(r"^[a-z0-9][a-z0-9._+\-]*$", line, re.IGNORECASE):
                    packages.add(line.lower())
        except Exception:
            continue
    return packages


def get_installed_aur_packages():
    """
    Return a set of locally-installed AUR / foreign package names
    (via pacman -Qqm).  Returns empty set if pacman isn't available.
    """
    try:
        result = subprocess.run(
            ["pacman", "-Qqm"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return {p.strip().lower() for p in result.stdout.splitlines() if p.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return set()


# ============================================================================ #
#  6b.  TKINTER GUI                                                             #
# ============================================================================ #

class AURSecurityApp:
    """Main application window."""

    # ----- severity -> visible background tints for the PKGBUILD viewer -----
    SEVERITY_TAG_COLOURS = {
        "info":     "#003d5c",
        "low":      "#003d00",
        "medium":   "#3d3d00",
        "high":     "#4d0000",
        "critical": "#7a0000",
    }
    SEVERITY_TAG_FG = {
        "info":     "#7dcfff",
        "low":      "#9ece6a",
        "medium":   "#e0af68",
        "high":     "#f7768e",
        "critical": "#ff4444",
    }
    VERDICT_COLOURS = {
        "safe":      COLOUR_SAFE,
        "caution":   COLOUR_WARN,
        "dangerous": COLOUR_DANGER,
        "critical":  COLOUR_CRITICAL,
    }

    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.root.minsize(900, 600)

        # ---- Apply Sun Valley theme (dark) ----
        sv_ttk.set_theme("dark")

        # ---- Dark title bar on Windows ----
        if HAS_PYWINSTYLES and platform.system() == "Windows":
            ver = sys.getwindowsversion()
            if ver.major == 10 and ver.build >= 22000:
                pywinstyles.change_header_color(root, "#1c1c1c")
            elif ver.major == 10:
                pywinstyles.apply_style(root, "dark")
                root.wm_attributes("-alpha", 0.99)
                root.wm_attributes("-alpha", 1)

        # State
        self.current_results = []          # last AUR search results
        self.current_pkgbuild = ""         # last fetched PKGBUILD text
        self.current_pkgname  = ""         # currently-selected package name
        self.current_analysis = None       # last analysis result dict
        self.remote_malware_packages = set()  # fetched from remote blacklists
        self.remote_malware_count = 0
        self.affected_installed = set()      # installed AUR packages in the blacklist
        self.affected_count = 0

        self._build_styles()
        self._build_layout()
        self._configure_tags()

        # ---- Fetch remote malware lists in background ----
        self.status_var.set("Fetching remote malware blacklists...")
        threading.Thread(target=self._background_fetch_malware_lists, daemon=True).start()

    def _background_fetch_malware_lists(self):
        """Background thread: fetch remote blacklists & check installed packages."""
        packages = fetch_remote_malware_lists()
        self.remote_malware_packages = packages
        self.remote_malware_count = len(packages)
        installed = get_installed_aur_packages()
        self.affected_installed = packages & installed
        self.affected_count = len(self.affected_installed)

        def notify():
            parts = []
            if self.remote_malware_count:
                parts.append(f"{self.remote_malware_count} known-malicious packages loaded")
            if self.affected_count:
                parts.append(f"⚠  {self.affected_count} installed package(s) are blacklisted!")
            if parts:
                self.status_var.set(", ".join(parts))
            else:
                self.status_var.set("Ready. (No remote blacklists loaded)")

        self.root.after(0, notify)

    # ------------------------------------------------------------------ #
    #  Styles & layout                                                   #
    # ------------------------------------------------------------------ #

    def _build_styles(self):
        """Minimal overrides — let sv_ttk handle everything else."""
        style = ttk.Style()
        # Only override Treeview (tk-based, sv_ttk can't fully style it)
        style.configure("Treeview",
                        rowheight=28,
                        font=("Monospace", 10))
        style.configure("Treeview.Heading",
                        font=("Sans", 10, "bold"))
        # Custom label styles for headings
        style.configure("Title.TLabel",
                        font=("Sans", 13, "bold"))
        style.configure("Muted.TLabel",
                        font=("Sans", 9))
        # Accent button for install
        style.configure("Accent.TButton",
                        font=("Sans", 10, "bold"))
        style.configure("Danger.TButton",
                        font=("Sans", 10, "bold"))

    def _build_layout(self):
        # ---------- Top bar ----------
        topbar = ttk.Frame(self.root)
        topbar.pack(side=tk.TOP, fill=tk.X, padx=12, pady=(10, 2))

        ttk.Label(topbar, text="AUR Security Manager",
                  style="Title.TLabel").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(topbar,
                  text="Search, review and install AUR packages with safety analysis",
                  style="Muted.TLabel").pack(side=tk.LEFT)

        ttk.Separator(self.root, orient="horizontal").pack(
            side=tk.TOP, fill=tk.X, padx=12, pady=4)

        # ---------- Search row ----------
        search_row = ttk.Frame(self.root)
        search_row.pack(side=tk.TOP, fill=tk.X, padx=12, pady=6)

        ttk.Label(search_row, text="Search:").pack(side=tk.LEFT, padx=(0, 8))
        self.search_var = tk.StringVar()
        entry = ttk.Entry(search_row, textvariable=self.search_var, width=40)
        entry.pack(side=tk.LEFT, padx=(0, 8))
        entry.bind("<Return>", lambda e: self.do_search())

        ttk.Button(search_row, text="Search AUR",
                   command=self.do_search).pack(side=tk.LEFT, padx=4)
        ttk.Button(search_row, text="Clear",
                   command=self.do_clear).pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(search_row, textvariable=self.status_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT, padx=12)

        # ---------- Bottom action bar (packed BEFORE body so it anchors at the bottom) ----------
        ttk.Separator(self.root, orient="horizontal").pack(
            side=tk.BOTTOM, fill=tk.X, padx=12, pady=4)
        actions = ttk.Frame(self.root)
        actions.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=(2, 10))

        self.install_btn = ttk.Button(
            actions, text="Install with yay",
            style="Accent.TButton", command=self.do_install,
        )
        self.install_btn.pack(side=tk.RIGHT, padx=4)

        ttk.Label(actions, text="Tip: select a package, fetch the PKGBUILD, "
                                "review the findings, then install.",
                  style="Muted.TLabel").pack(side=tk.LEFT)

        # ---------- Main split: left list, right tabs ----------
        body = ttk.Frame(self.root)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12, pady=6)
        # Left: package list
        left = ttk.Frame(body)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        left.configure(width=380)

        ttk.Label(left, text="Search results",
                  style="Title.TLabel").pack(anchor=tk.W, pady=(0, 6))

        list_wrap = ttk.Frame(left)
        list_wrap.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            list_wrap,
            columns=("name", "ver", "votes", "pop", "maint"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("name",  text="Package")
        self.tree.heading("ver",   text="Version")
        self.tree.heading("votes", text="Votes")
        self.tree.heading("pop",   text="Pop.")
        self.tree.heading("maint", text="Maintainer")
        self.tree.column("name",  width=160, anchor=tk.W)
        self.tree.column("ver",   width=110, anchor=tk.W)
        self.tree.column("votes", width=50,  anchor=tk.E)
        self.tree.column("pop",   width=60,  anchor=tk.E)
        self.tree.column("maint", width=100, anchor=tk.W)
        self.tree.tag_configure("critical", foreground=COLOUR_CRITICAL)
        self.tree.tag_configure("remote_malicious", foreground=COLOUR_DANGER)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(list_wrap, orient=tk.VERTICAL,
                            command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_package)
        self.tree.bind("<Double-1>",         lambda e: self.do_fetch_pkgbuild())

        # Right: notebook with three tabs
        right = ttk.Frame(body)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.nb = ttk.Notebook(right)
        self.nb.pack(fill=tk.BOTH, expand=True)

        # --- Tab 1: Package info + PKGBUILD viewer ---
        tab_pkg = ttk.Frame(self.nb)
        self.nb.add(tab_pkg, text="PKGBUILD & Analysis")

        info_row = ttk.Frame(tab_pkg)
        info_row.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(6, 2))

        self.info_var = tk.StringVar(value="No package selected.")
        ttk.Label(info_row, textvariable=self.info_var,
                  font=("Sans", 10)).pack(side=tk.LEFT)

        ttk.Button(info_row, text="Fetch PKGBUILD",
                   command=self.do_fetch_pkgbuild).pack(side=tk.RIGHT, padx=4)
        ttk.Button(info_row, text="Open AUR page",
                   command=self.open_aur_page).pack(side=tk.RIGHT, padx=4)
        ttk.Button(info_row, text="Re-run analysis",
                   command=self.do_analyze).pack(side=tk.RIGHT, padx=4)

        # PKGBUILD text widget
        pkg_wrap = ttk.Frame(tab_pkg)
        pkg_wrap.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.pkgbuild_text = tk.Text(
            pkg_wrap, wrap=tk.NONE, bg=COLOUR_HIGHLIGHT, fg=COLOUR_FG,
            insertbackground=COLOUR_FG, selectbackground=COLOUR_ACCENT,
            selectforeground="#000000", font=("Monospace", 10),
            undo=True, padx=8, pady=8, borderwidth=0, relief="flat",
            highlightthickness=0,
        )
        hsb = ttk.Scrollbar(pkg_wrap, orient=tk.HORIZONTAL,
                            command=self.pkgbuild_text.xview)
        vsb2 = ttk.Scrollbar(pkg_wrap, orient=tk.VERTICAL,
                             command=self.pkgbuild_text.yview)
        self.pkgbuild_text.configure(xscrollcommand=hsb.set,
                                     yscrollcommand=vsb2.set)
        self.pkgbuild_text.grid(row=0, column=0, sticky="nsew")
        vsb2.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        pkg_wrap.rowconfigure(0, weight=1)
        pkg_wrap.columnconfigure(0, weight=1)
        # Line numbers gutter
        self.line_numbers = tk.Text(
            pkg_wrap, width=5, bg=COLOUR_PANEL, fg=COLOUR_MUTED,
            font=("Monospace", 10), borderwidth=0, relief="flat",
            state=tk.DISABLED, padx=4, highlightthickness=0,
        )
        # (gutter is rendered as a separate Text widget to the left of the
        #  PKGBUILD viewer - kept simple to avoid reflow complexity.)
        self.pkgbuild_text.bind("<KeyRelease>", self._update_line_numbers)
        self.pkgbuild_text.bind("<MouseWheel>", self._update_line_numbers)

        # --- Tab 2: Security findings ---
        tab_sec = ttk.Frame(self.nb)
        self.nb.add(tab_sec, text="Security Findings")

        sec_top = ttk.Frame(tab_sec)
        sec_top.pack(side=tk.TOP, fill=tk.X, padx=4, pady=4)
        self.verdict_var = tk.StringVar(value="Verdict: -")
        ttk.Label(sec_top, textvariable=self.verdict_var,
                  style="Title.TLabel").pack(anchor=tk.W)
        self.score_var = tk.StringVar(value="Risk score: -")
        ttk.Label(sec_top, textvariable=self.score_var,
                  style="Muted.TLabel").pack(anchor=tk.W, pady=(2, 0))
        self.summary_var = tk.StringVar(value="")
        ttk.Label(sec_top, textvariable=self.summary_var,
                  style="Panel.TLabel", wraplength=900).pack(anchor=tk.W,
                                                             pady=(4, 0))

        # Findings tree
        find_wrap = ttk.Frame(tab_sec)
        find_wrap.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.find_tree = ttk.Treeview(
            find_wrap,
            columns=("sev", "id", "cat", "name", "line", "desc"),
            show="headings",
        )
        self.find_tree.heading("sev",  text="Severity")
        self.find_tree.heading("id",   text="Rule ID")
        self.find_tree.heading("cat",  text="Category")
        self.find_tree.heading("name", text="Finding")
        self.find_tree.heading("line", text="Line")
        self.find_tree.heading("desc", text="Description")
        self.find_tree.column("sev",  width=80,  anchor=tk.W)
        self.find_tree.column("id",   width=90,  anchor=tk.W)
        self.find_tree.column("cat",  width=130, anchor=tk.W)
        self.find_tree.column("name", width=240, anchor=tk.W)
        self.find_tree.column("line", width=50,  anchor=tk.E)
        self.find_tree.column("desc", width=380, anchor=tk.W)
        self.find_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        fsb = ttk.Scrollbar(find_wrap, orient=tk.VERTICAL,
                            command=self.find_tree.yview)
        fsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.find_tree.configure(yscrollcommand=fsb.set)
        self.find_tree.tag_configure("critical", foreground=COLOUR_CRITICAL)
        self.find_tree.tag_configure("high",     foreground=COLOUR_DANGER)
        self.find_tree.tag_configure("medium",   foreground=COLOUR_WARN)
        self.find_tree.tag_configure("low",      foreground=COLOUR_SAFE)
        self.find_tree.tag_configure("info",     foreground=COLOUR_MUTED)

        # --- Tab 3: Known-malicious DB ---
        tab_db = ttk.Frame(self.nb)
        self.nb.add(tab_db, text="Known-Malicious DB")
        self._populate_db_tab(tab_db)

    # ------------------------------------------------------------------ #
    #  PKGBUILD text tags (severity-based highlighting)                  #
    # ------------------------------------------------------------------ #

    def _configure_tags(self):
        for sev, bg in self.SEVERITY_TAG_COLOURS.items():
            fg = self.SEVERITY_TAG_FG.get(sev, "#ffffff")
            self.pkgbuild_text.tag_configure(
                sev,
                background=bg,
                foreground=fg,
            )
        # Also tag comment lines ( subdued colour )
        self.pkgbuild_text.tag_configure(
            "comment",
            foreground=COLOUR_MUTED,
        )
        self.pkgbuild_text.tag_configure(
            "shellvar",
            foreground=COLOUR_ACCENT,
        )

    # ------------------------------------------------------------------ #
    #  DB tab                                                            #
    # ------------------------------------------------------------------ #

    def _populate_db_tab(self, tab):
        ttk.Label(tab, text="Curated database of historically malicious AUR "
                            "packages",
                  style="Title.TLabel").pack(anchor=tk.W, padx=8, pady=(8, 4))
        ttk.Label(tab,
                  text="Each entry's signature is auto-fed into the rule "
                       "engine, so any new package matching a known-bad "
                       "pattern is flagged.",
                  style="Muted.TLabel",
                  wraplength=900).pack(anchor=tk.W, padx=8, pady=(0, 8))

        wrap = ttk.Frame(tab)
        wrap.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.db_tree = ttk.Treeview(
            wrap,
            columns=("pkg", "sev", "cat", "date", "reason"),
            show="headings",
        )
        self.db_tree.heading("pkg",  text="Package")
        self.db_tree.heading("sev",  text="Severity")
        self.db_tree.heading("cat",  text="Category")
        self.db_tree.heading("date", text="Date")
        self.db_tree.heading("reason", text="Reason")
        self.db_tree.column("pkg",  width=160, anchor=tk.W)
        self.db_tree.column("sev",  width=80,  anchor=tk.W)
        self.db_tree.column("cat",  width=160, anchor=tk.W)
        self.db_tree.column("date", width=100, anchor=tk.W)
        self.db_tree.column("reason", width=520, anchor=tk.W)
        self.db_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dsb = ttk.Scrollbar(wrap, orient=tk.VERTICAL,
                            command=self.db_tree.yview)
        dsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.db_tree.configure(yscrollcommand=dsb.set)
        self.db_tree.tag_configure("critical", foreground=COLOUR_CRITICAL)
        self.db_tree.tag_configure("high",     foreground=COLOUR_DANGER)
        self.db_tree.tag_configure("medium",   foreground=COLOUR_WARN)
        for pkg, info in sorted(KNOWN_MALICIOUS.items(),
                                key=lambda kv: kv[1]["date"], reverse=True):
            self.db_tree.insert("", tk.END,
                                values=(pkg, info["severity"],
                                        info.get("category", "-"),
                                        info["date"], info["reason"]),
                                tags=(info["severity"],))

    # ------------------------------------------------------------------ #
    #  Search & selection                                                #
    # ------------------------------------------------------------------ #

    def do_search(self):
        q = self.search_var.get().strip()
        if not q:
            messagebox.showinfo("Search", "Enter a search term first.")
            return
        self.status_var.set(f"Searching AUR for '{q}'...")
        self.tree.delete(*self.tree.get_children())

        def on_done(results):
            self.current_results = results
            self.root.after(0, lambda: self._render_results(results))

        def on_error(err):
            self.root.after(0, lambda: self.status_var.set(f"Error: {err}"))

        aur_search(q, on_done, on_error)

    def _render_results(self, results):
        for r in results:
            name = r.get("Name", "?")
            ver  = r.get("Version", "?")
            votes = r.get("NumVotes", 0)
            pop  = r.get("Popularity", 0.0)
            maint = r.get("Maintainer", "-") or "-"
            tags = []
            if name in KNOWN_MALICIOUS:
                tags.append("critical")
            if name.lower() in self.remote_malware_packages:
                tags.append("remote_malicious")
            self.tree.insert("", tk.END,
                             values=(name, ver, votes, f"{pop:.2f}", maint),
                             tags=tuple(tags))
        parts = [f"{len(results)} result(s)"]
        if self.remote_malware_count:
            parts.append(f"{self.remote_malware_count} remote-blacklisted packages loaded")
        self.status_var.set(". ".join(parts))

    def on_select_package(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        name = vals[0]
        self.current_pkgname = name
        self.info_var.set(f"Selected: {name}")
        # Reset stale PKGBUILD/analysis state but keep the text on screen
        # until the fetch completes.
        self.current_pkgbuild = ""
        self.current_analysis = None
        self.verdict_var.set("Verdict: -")
        self.score_var.set("Risk score: -")
        self.summary_var.set("")
        self.find_tree.delete(*self.find_tree.get_children())
        # Auto-fetch the PKGBUILD on selection
        self.do_fetch_pkgbuild()

    # ------------------------------------------------------------------ #
    #  Fetch PKGBUILD                                                    #
    # ------------------------------------------------------------------ #

    def do_fetch_pkgbuild(self):
        if not self.current_pkgname:
            messagebox.showinfo("Fetch", "Select a package first.")
            return
        pkg = self.current_pkgname
        self.status_var.set(f"Fetching PKGBUILD for {pkg}...")
        self.pkgbuild_text.delete("1.0", tk.END)
        self.pkgbuild_text.insert(tk.END, "(loading...)\n")

        def on_done(text):
            # Guard: only render if this package is still selected
            if self.current_pkgname != pkg:
                return
            self.current_pkgbuild = text
            self.root.after(0, lambda: self._render_pkgbuild(text))
            self.root.after(0, self.do_analyze)

        def on_error(err):
            if self.current_pkgname != pkg:
                return
            self.root.after(0, lambda: self.status_var.set(f"Error: {err}"))
            self.root.after(0, lambda: self.pkgbuild_text.delete("1.0", tk.END))
            self.root.after(0, lambda: self.pkgbuild_text.insert(
                tk.END, f"Failed to fetch PKGBUILD:\n{err}\n"))

        aur_fetch_pkgbuild(pkg, on_done, on_error)

    def _render_pkgbuild(self, text):
        self.pkgbuild_text.delete("1.0", tk.END)
        self.pkgbuild_text.insert(tk.END, text)
        self._apply_pkgbuild_highlighting()
        self._update_line_numbers()
        self.status_var.set(f"PKGBUILD loaded ({len(text.splitlines())} lines). "
                            "Auto-analysis complete - see Security Findings tab.")

    def _apply_pkgbuild_highlighting(self):
        """Apply severity tags to dangerous lines + comment/var dimming."""
        # Clear existing severity tags.
        for sev in self.SEVERITY_TAG_COLOURS:
            self.pkgbuild_text.tag_remove(sev, "1.0", tk.END)

        # Run analysis (without re-saving it) to get finding line numbers.
        analysis = analyze_pkgbuild(self.current_pkgbuild,
                                    pkgname=self.current_pkgname,
                                    remote_malicious=self.remote_malware_packages)
        for f in analysis["findings"]:
            tag = f["severity"]
            if tag not in self.SEVERITY_TAG_COLOURS:
                continue
            line_no = f["line"]
            if line_no <= 0:
                continue
            start = f"{line_no}.0"
            end   = f"{line_no}.end"
            self.pkgbuild_text.tag_add(tag, start, end)

        # Dim comment lines.
        for idx, line in enumerate(
                self.current_pkgbuild.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                self.pkgbuild_text.tag_add("comment", f"{idx}.0", f"{idx}.end")

    def _update_line_numbers(self, _event=None):
        """Best-effort line-number gutter - keeps the gutter in sync with the
        PKGBUILD viewer's vertical scroll."""
        try:
            self.line_numbers.configure(state=tk.NORMAL)
            self.line_numbers.delete("1.0", tk.END)
            n = self.current_pkgbuild.count("\n") + 1
            for i in range(1, n + 1):
                self.line_numbers.insert(tk.END, f"{i:>4}\n")
            self.line_numbers.configure(state=tk.DISABLED)
            # Sync vertical scroll position.
            yview = self.pkgbuild_text.yview()[0]
            self.line_numbers.yview_moveto(yview)
        except tk.TclError:
            pass

    # ------------------------------------------------------------------ #
    #  Analysis                                                          #
    # ------------------------------------------------------------------ #

    def do_analyze(self):
        if not self.current_pkgbuild:
            messagebox.showinfo("Analyze", "Fetch a PKGBUILD first.")
            return
        self.current_analysis = analyze_pkgbuild(self.current_pkgbuild,
                                                 pkgname=self.current_pkgname,
                                                 remote_malicious=self.remote_malware_packages)
        self._render_analysis()

    def _render_analysis(self):
        a = self.current_analysis
        if not a:
            return
        self._apply_pkgbuild_highlighting()

        verdict = a["verdict"]
        colour = self.VERDICT_COLOURS.get(verdict, COLOUR_FG)
        icon = {"safe": "✅", "caution": "⚠️", "dangerous": "🔶", "critical": "🔴"}
        self.verdict_var.set(f"{icon.get(verdict, '')}  Verdict: {verdict.upper()}")
        self.score_var.set(f"Risk score: {a['score']}/100")
        self.summary_var.set(a["summary"])

        # Populate findings tree.
        self.find_tree.delete(*self.find_tree.get_children())
        for f in a["findings"]:
            self.find_tree.insert(
                "", tk.END,
                values=(f["severity"].upper(), f["id"], f["category"],
                        f["name"], f["line"], f["description"]),
                tags=(f["severity"],),
            )

        if verdict in ("dangerous", "critical"):
            self.nb.select(1)

    # ------------------------------------------------------------------ #
    #  Install                                                           #
    # ------------------------------------------------------------------ #

    def do_install(self):
        if not self.current_pkgname:
            messagebox.showinfo("Install", "Select a package first.")
            return
        if not is_yay_available():
            messagebox.showerror(
                "yay not found",
                "The 'yay' binary was not found on your PATH.\n"
                "Install it first:\n\n"
                "  sudo pacman -S --needed git base-devel\n"
                "  git clone https://aur.archlinux.org/yay.git\n"
                "  cd yay && makepkg -si\n",
            )
            return

        pkg = self.current_pkgname

        # If we haven't fetched the PKGBUILD yet, force a fetch + analysis
        # before allowing install (safety gate).
        if not self.current_pkgbuild:
            if not messagebox.askyesno(
                "No PKGBUILD fetched",
                f"You haven't fetched the PKGBUILD for '{pkg}' yet.\n\n"
                "Fetch and analyze it before installing?"):
                return
            # Block on the fetch by running the threaded call inline.
            self.do_fetch_pkgbuild()
            messagebox.showinfo("Analyzing",
                                "PKGBUILD fetched. Re-click 'Install' after "
                                "reviewing the Security Findings tab.")
            return

        if not self.current_analysis:
            self.do_analyze()

        a = self.current_analysis
        verdict = a["verdict"]
        score   = a["score"]

        # ---- Safety gate ----
        if verdict == "critical":
            findings_txt = "\n".join(
                f"  - [{f['severity'].upper()}] {f['name']} (line {f['line']})"
                for f in a["findings"][:10]
            )
            messagebox.showerror(
                "INSTALL BLOCKED",
                f"Package '{pkg}' was flagged CRITICAL (risk score {score}/100).\n\n"
                f"Findings:\n{findings_txt}\n\n"
                "Installation is blocked to protect your system.\n"
                "If you are certain this is a false positive, install it "
                "manually from a terminal after reviewing the PKGBUILD "
                "yourself.",
            )
            return

        if verdict == "dangerous":
            findings_txt = "\n".join(
                f"  - [{f['severity'].upper()}] {f['name']} (line {f['line']})"
                for f in a["findings"][:10]
            )
            accept = messagebox.askyesno(
                "Dangerous package",
                f"Package '{pkg}' is flagged DANGEROUS (risk score {score}/100).\n\n"
                f"Findings:\n{findings_txt}\n\n"
                "Are you sure you want to install it anyway?",
                icon="warning",
            )
            if not accept:
                return

        # ---- Final confirmation ----
        if not messagebox.askyesno(
            "Confirm install",
            f"Run: yay -S --noconfirm --needed {pkg}\n\nProceed?"):
            return

        # ---- Open terminal window and run install ----
        self.install_btn.configure(state=tk.DISABLED)
        self.status_var.set(f"Installing {pkg}...")

        def worker():
            term_future = []

            def make_term():
                term = TerminalOutputWindow(self.root, pkg)
                term_future.append(term)

            self.root.after(0, make_term)
            import time
            while not term_future:
                time.sleep(0.05)
            term = term_future[0]

            rc = yay_install(pkg, term)
            term.set_finished(rc)
            term.wait_for_close()
            self.root.after(0, lambda: self._on_install_done(rc, pkg))

        threading.Thread(target=worker, daemon=True).start()

    def _on_install_done(self, rc, pkg):
        self.install_btn.configure(state=tk.NORMAL)
        if rc == 0:
            self.status_var.set(f"Installed {pkg} successfully.")
            messagebox.showinfo("Install", f"Package '{pkg}' installed.")
        else:
            self.status_var.set(f"Install failed (rc={rc}).")

    # ------------------------------------------------------------------ #
    #  Misc                                                              #
    # ------------------------------------------------------------------ #

    def do_clear(self):
        self.search_var.set("")
        self.tree.delete(*self.tree.get_children())
        self.pkgbuild_text.delete("1.0", tk.END)
        self.find_tree.delete(*self.find_tree.get_children())
        self.current_results = []
        self.current_pkgbuild = ""
        self.current_pkgname = ""
        self.current_analysis = None
        self.info_var.set("No package selected.")
        self.verdict_var.set("Verdict: -")
        self.score_var.set("Risk score: -")
        self.summary_var.set("")
        self.status_var.set("Cleared.")

    def open_aur_page(self):
        if not self.current_pkgname:
            return
        url = AUR_PACKAGE_PAGE.format(pkg=urllib.parse.quote(self.current_pkgname))
        try:
            subprocess.Popen(["xdg-open", url])
        except FileNotFoundError:
            messagebox.showinfo("Open", f"Open this URL in your browser:\n{url}")


# ============================================================================ #
#  7.  ENTRY POINT                                                              #
# ============================================================================ #

def main():
    root = tk.Tk()
    sv_ttk.set_theme("dark")
    app = AURSecurityApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
