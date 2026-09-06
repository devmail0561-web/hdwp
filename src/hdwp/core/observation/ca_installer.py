# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
CAInstaller : installe le certificat CA HDWP dans tous les navigateurs détectés.

Navigateurs/stores supportés :
- Linux : Chrome (NSS ~/.pki/nssdb), Firefox (snap et non-snap), system (update-ca-certificates)
- macOS  : Keychain login, Firefox (NSS)
- Windows: Windows Cert Store, Firefox (NSS)
"""
from __future__ import annotations

import glob
import hashlib
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger()

NICKNAME = "HDWP CA"


def ensure_certutil() -> bool:
    """
    S'assure que certutil est disponible.
    Si absent, tente de l'installer via apt (sudo -n = non-interactif, utilise le cache sudo).
    Retourne True si certutil est disponible après l'opération.
    """
    if shutil.which("certutil"):
        return True

    if platform.system() != "Linux":
        return False

    log.info("ca_installer.certutil_missing", action="trying apt install libnss3-tools")
    try:
        # -n = non-interactif : utilise le cache sudo, échoue sans prompt si pas de cache
        result = subprocess.run(
            ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends", "libnss3-tools"],
            capture_output=True, timeout=60,
        )
        if result.returncode == 0 and shutil.which("certutil"):
            log.info("ca_installer.certutil_installed")
            return True
        # Si sudo -n a échoué (pas de cache), essayer sans -n pour permettre le prompt
        result2 = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "--no-install-recommends", "libnss3-tools"],
            timeout=120,
        )
        if result2.returncode == 0:
            log.info("ca_installer.certutil_installed")
            return bool(shutil.which("certutil"))
    except Exception as exc:
        log.warning("ca_installer.certutil_install_failed", error=str(exc))

    return bool(shutil.which("certutil"))


def _cert_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _nss_has_ca(db_path: str) -> bool:
    """Vérifie si le certificat HDWP CA est déjà dans une DB NSS."""
    certutil = _find_certutil()
    if not certutil:
        return False
    result = subprocess.run(
        [certutil, "-L", "-d", db_path, "-n", NICKNAME],
        capture_output=True, timeout=5,
    )
    return result.returncode == 0


def is_ca_already_installed(ca_cert_path: Path) -> bool:
    """Retourne True si le CA est déjà installé partout (évite le sudo inutile)."""
    if not ca_cert_path.exists():
        return False

    system = platform.system()

    if system == "Linux":
        # Vérifier le store système
        dest = Path("/usr/local/share/ca-certificates/hdwp-ca.crt")
        if not dest.exists() or _cert_hash(dest) != _cert_hash(ca_cert_path):
            return False
        # Vérifier au moins une DB NSS
        dbs = _find_nss_dbs_linux()
        if dbs and not any(_nss_has_ca(db) for db in dbs.values()):
            return False
        return True

    if system == "Darwin":
        # Vérification légère : certutil présent et au moins un profil Firefox OK
        dbs = {}
        home = Path.home()
        for cert9 in glob.glob(str(home / "Library/Application Support/Firefox/Profiles/*/cert9.db")):
            profile = Path(cert9).parent
            dbs[f"sql:{profile}"] = f"sql:{profile}"
        return bool(dbs) and all(_nss_has_ca(db) for db in dbs)

    # Windows : pas de vérification légère disponible sans WinAPI
    return False


def install_ca_everywhere(ca_cert_path: Path) -> dict[str, dict[str, Any]]:
    """
    Installe le CA dans tous les navigateurs et stores détectés.
    Retourne {target_name: {"ok": bool, "message": str}}.
    """
    if not ca_cert_path.exists():
        return {"error": {"ok": False, "message": f"Certificat CA introuvable : {ca_cert_path}"}}

    # S'assurer que certutil est disponible (installe libnss3-tools si besoin)
    ensure_certutil()

    system = platform.system()
    results: dict[str, dict[str, Any]] = {}

    if system == "Linux":
        results.update(_install_linux(ca_cert_path))
    elif system == "Darwin":
        results.update(_install_macos(ca_cert_path))
    elif system == "Windows":
        results.update(_install_windows(ca_cert_path))
    else:
        results["unknown"] = {"ok": False, "message": f"Plateforme non supportée : {system}"}

    return results


# ── NSS helper (Chrome, Firefox, Chromium) ────────────────────────────────────

def _find_certutil() -> str | None:
    """Locate certutil binary."""
    found = shutil.which("certutil")
    if found:
        return found
    for alt in ["/usr/bin/certutil", "/usr/local/bin/certutil"]:
        if Path(alt).exists():
            return alt
    return None


def _install_nss(ca: Path, db_path: str, label: str) -> dict[str, Any]:
    """Install CA into an NSS database using certutil."""
    certutil = _find_certutil()
    if not certutil:
        return {
            "ok": False,
            "message": "certutil introuvable — sudo apt install libnss3-tools",
        }
    # Remove old entry silently (timeout prevents hang if NSS db is locked)
    subprocess.run([certutil, "-D", "-d", db_path, "-n", NICKNAME], capture_output=True, timeout=10)
    # Install new entry
    result = subprocess.run(
        [certutil, "-A", "-d", db_path, "-t", "CT,,", "-n", NICKNAME, "-i", str(ca)],
        capture_output=True,
        timeout=10,
    )
    if result.returncode == 0:
        return {"ok": True, "message": f"Installé dans {label}"}
    err = (result.stderr.decode("utf-8", errors="replace") or
           result.stdout.decode("utf-8", errors="replace"))
    return {"ok": False, "message": err.strip()[:120]}


def _find_nss_dbs_linux() -> dict[str, str]:
    """Return {label: nss_db_dir} for all NSS databases found on Linux."""
    dbs: dict[str, str] = {}
    home = Path.home()

    # Chrome / Electron apps (system NSS user store)
    chrome_nss = home / ".pki/nssdb"
    if (chrome_nss / "cert9.db").exists():
        dbs["Chrome"] = f"sql:{chrome_nss}"

    # Firefox — non-snap
    for cert9 in glob.glob(str(home / ".mozilla/firefox/*/cert9.db")):
        profile = Path(cert9).parent
        dbs[f"Firefox ({profile.name[:14]})"] = f"sql:{profile}"

    # Firefox — snap (two possible locations)
    for pattern in [
        str(home / "snap/firefox/*/mozilla/firefox/*/cert9.db"),
        str(home / "snap/firefox/common/.mozilla/firefox/*/cert9.db"),
    ]:
        for cert9 in glob.glob(pattern):
            profile = Path(cert9).parent
            key = f"Firefox snap ({profile.name[:14]})"
            if key not in dbs:
                dbs[key] = f"sql:{profile}"

    # Chromium
    for cert9 in glob.glob(str(home / ".config/chromium/*/cert9.db")):
        profile = Path(cert9).parent
        dbs[f"Chromium ({profile.name[:14]})"] = f"sql:{profile}"

    return dbs


# ── Linux ─────────────────────────────────────────────────────────────────────

def _install_linux(ca: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}

    # System-wide CA store
    results["Système (update-ca-certificates)"] = _install_system_linux(ca)

    # NSS databases
    for label, db_path in _find_nss_dbs_linux().items():
        results[label] = _install_nss(ca, db_path, label)

    if not _find_nss_dbs_linux():
        results["NSS (aucun profil détecté)"] = {
            "ok": False,
            "message": "Aucun profil Chrome/Firefox trouvé dans les emplacements standard",
        }

    return results


def _install_system_linux(ca: Path) -> dict[str, Any]:
    dest = Path("/usr/local/share/ca-certificates/hdwp-ca.crt")
    try:
        subprocess.run(["sudo", "cp", str(ca), str(dest)], check=True, capture_output=True, timeout=10)
        subprocess.run(["sudo", "update-ca-certificates"], check=True, capture_output=True, timeout=30)
        return {"ok": True, "message": "Installé dans le store système"}
    except subprocess.CalledProcessError as exc:
        err = exc.stderr.decode("utf-8", errors="replace").strip()[:120] if exc.stderr else str(exc)
        return {"ok": False, "message": f"sudo requis : {err or 'permission refusée'}"}
    except FileNotFoundError:
        return {"ok": False, "message": "update-ca-certificates introuvable"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "Timeout"}


# ── macOS ─────────────────────────────────────────────────────────────────────

def _install_macos(ca: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    home = Path.home()

    # Login Keychain
    keychain = home / "Library/Keychains/login.keychain-db"
    if not keychain.exists():
        keychain = home / "Library/Keychains/login.keychain"
    try:
        subprocess.run(
            ["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", str(keychain), str(ca)],
            check=True, capture_output=True, timeout=15,
        )
        results["macOS Keychain"] = {"ok": True, "message": "Installé dans le Keychain"}
    except Exception as exc:
        results["macOS Keychain"] = {"ok": False, "message": str(exc)[:120]}

    # Firefox macOS
    ff_pattern = str(home / "Library/Application Support/Firefox/Profiles/*/cert9.db")
    for cert9 in glob.glob(ff_pattern):
        profile = Path(cert9).parent
        label = f"Firefox ({profile.name[:14]})"
        results[label] = _install_nss(ca, f"sql:{profile}", label)

    return results


# ── Windows ───────────────────────────────────────────────────────────────────

def _install_windows(ca: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    home = Path.home()

    # Windows Cert Store
    try:
        subprocess.run(
            ["certutil", "-addstore", "-f", "ROOT", str(ca)],
            check=True, capture_output=True, timeout=15,
        )
        results["Windows Cert Store"] = {"ok": True, "message": "Installé dans le Windows Cert Store"}
    except Exception as exc:
        results["Windows Cert Store"] = {"ok": False, "message": str(exc)[:120]}

    # Firefox Windows
    ff_pattern = str(home / "AppData/Roaming/Mozilla/Firefox/Profiles/*/cert9.db")
    for cert9 in glob.glob(ff_pattern):
        profile = Path(cert9).parent
        label = f"Firefox ({profile.name[:14]})"
        results[label] = _install_nss(ca, f"sql:{profile}", label)

    return results
