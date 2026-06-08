import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import math
import os
import platform
import queue
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

APP_NAME = "Securo"
ROBLOX_EXE = "RobloxPlayerBeta.exe"
DETECT_LOG_TYPES = ("Direct", "Generic", "Specific", "Warning", "Recovery", "Antivirus", "Manual Review")
CONFIRMED_EXPLOIT_CATEGORIES = {
    "DotNetExecutable",
    "DotNetDLL",
    "Suspicious Net File",
    "Tampered File",
    "A3",
    "Skript Loader Trace",
}
HIGH_CONFIDENCE_CHEAT_CATEGORIES = {"S1", "DLL", "BSoD", "S2", "C3", "C4", "A"}
GENERIC_DETECTION_CATEGORIES = {
    "UPX Packer",
    "Generic Packed File",
    "A1",
    "A2",
    "X1",
    "X2",
    "L1",
    "B",
    "D",
    "F5",
    "P1",
    "P2",
    "AutoIT Usage",
    "AutoHotkey Usage",
    "Suspicious Net File",
    "Executed Suspicious File",
    "Suspicious DLL Loading",
    "Modified File Extension",
    "Generic Packed Mod",
    "Untrusted File",
}
SPECIFIC_DETECTION_CATEGORIES = {
    "Possible Roblox Exploit Execution",
    "Possible Game Instance Modification",
    "Possible DLL Injection Activity",
    "Possible FastFlag Modifications",
    "Possible Alternate Roblox Account Usage",
    "Executed-Then-Deleted Application",
    "Suspicious Archive-To-Execution Chain",
    "Suspicious External Drive Execution",
    "Packed Or Obfuscated Executable",
    "File Tampering Or Integrity Violation",
    "Generic Bypass Method",
    "Tampered File",
    "Suspicious DLL Deletion",
    "Suspicious File Deletion",
    "Suspicious File Modification",
    "Deleted Prefetch File",
    "Duplicate Prefetch Behavior",
    "Impossible Prefetch Behavior",
    "Network File Execution",
    "External Device Execution",
    "RAR File Execution",
    "RAM Suspicious Indicator",
    "Game Instance Modification",
    "ActivitiesCache Disabled",
    "Executor Keyword Match",
}
WARNING_DETECTION_CATEGORIES = {
    "Virtualization Check",
    "ActivitiesCache Disabled",
    "RUIN Mode Warning",
    "Manual Review Required",
}
EXPLOIT_FAMILY_TERMS = {
    "volt",
    "potassium",
    "xeno",
    "xenoui",
    "synapse",
    "synapse z",
    "krnl",
    "fluxus",
    "solara",
    "seliware",
    "madium",
    "cosmic",
    "velocity",
    "celery",
    "wave",
    "delta",
    "arceus",
    "jjsploit",
    "evon",
    "hydrogen",
    "electron",
    "nihon",
    "sirhurt",
    "oxygen",
    "vega",
    "macsploit",
    "opiumware",
    "skript",
    "skriptloader",
    "skript loader",
}
VIRTUALIZATION_TERMS = ("qemu", "vmware", "sandboxie", "parallels", "virtualbox", "virtual pc", "vbox")
NETWORK_PATH_PREFIXES = ("\\\\", "file://")
EXTERNAL_DRIVE_LETTERS = set("DEFGHIJKLMNOPQRSTUVWXYZ")
TRUST_DAMPEN_SIGNERS = (
    "Roblox Corporation",
    "Microsoft Corporation",
    "Microsoft Windows",
    "Intel",
    "Intel Corporation",
    "Logitech",
    "Razer",
    "Corsair",
    "SteelSeries",
    "NVIDIA Corporation",
    "Advanced Micro Devices",
    "AMD",
    "Google LLC",
    "Google",
    "Mozilla",
    "Discord Inc.",
    "Valve Corp.",
    "Valve",
    "Valve Corporation",
    "MeldaProduction",
    "Spotify",
    "Proton",
    "Python Software Foundation",
)
COMMON_DEPENDENCY_NAMES = (
    "sqlite3.dll",
    "libcrypto",
    "libssl",
    "python312.dll",
    "python3.dll",
    "libffi",
    "vcruntime",
    "msvcp140.dll",
    "api-ms-win",
    "webview2loader.dll",
    "base_library.zip",
)
LOW_SIGNAL_PATH_MARKERS = (
    "\\vstplugins\\",
    "\\otvdm",
    "\\kyotowindows\\",
    "\\roblox\\versions\\",
    "\\roblox\\downloads\\",
    "\\_internal\\",
)
MAINSTREAM_SOFTWARE_PATH_MARKERS = (
    "\\spotify\\",
    "\\google\\chrome\\",
    "\\microsoft\\edge\\",
    "\\discord\\",
    "\\razer\\",
    "\\logitech\\",
    "\\corsair\\",
    "\\steelseries\\",
    "\\steam\\",
    "\\steamapps\\",
    "\\nvidia corporation\\",
    "\\nvidia\\",
    "\\amd\\",
    "\\roblox\\",
    "\\microsoft\\",
    "\\mozilla firefox\\",
)
PROTECTED_SYSTEM_PROCESS_NAMES = {
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "csrss.exe",
    "dwm.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
}
ALLOWLIST_STRONG_BEHAVIOR_TYPES = {
    "sysmon_remote_thread",
    "sysmon_process_access",
    "suspicious_module_load",
    "persistence",
    "defender_detection",
    "modified_extension",
    "network_artifact",
    "external_device",
}
ALLOWLIST_STRONG_BEHAVIOR_CATEGORIES = {
    "Tampered File",
    "Suspicious DLL Deletion",
    "Suspicious File Deletion",
    "Suspicious File Modification",
    "Modified File Extension",
    "Executed Suspicious File",
    "Network File Execution",
    "External Device Execution",
    "Generic Bypass Method",
}
TRUSTED_CONFIRMATION_TYPES = {
    "sysmon_remote_thread",
    "sysmon_process_access",
    "suspicious_module_load",
    "persistence",
}
TRUSTED_CONFIRMATION_CATEGORIES = {
    "Tampered File",
    "Suspicious DLL Deletion",
    "Suspicious File Deletion",
    "Suspicious File Modification",
    "Modified File Extension",
    "Generic Bypass Method",
}
REAL_BEHAVIOR_EVIDENCE_TYPES = {
    "sysmon_remote_thread",
    "sysmon_process_access",
    "suspicious_module_load",
    "persistence",
    "powershell_history",
    "prefetch",
    "prefetch_execution",
    "process_execution",
    "known_cheat_artifact",
}
EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DEFAULT_API_BASE_URL = "https://securo-next.vercel.app/"
tk = None
messagebox = None


def init_tk():
    global tk, messagebox
    if tk is not None:
        return
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", app_dir()))
        if str(base) not in sys.path:
            sys.path.insert(0, str(base))
        tcl_root = base / "tcl"
        if tcl_root.exists():
            os.environ.setdefault("TCL_LIBRARY", str(tcl_root / "tcl8.6"))
            os.environ.setdefault("TK_LIBRARY", str(tcl_root / "tk8.6"))
    import tkinter as tkinter_module
    from tkinter import messagebox as messagebox_module

    tk = tkinter_module
    messagebox = messagebox_module


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resource_path(name: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", app_dir()))
    return base / name


def load_config() -> dict:
    default = resource_path("config.json")
    local = app_dir() / "config.json"
    path = local if local.exists() else default
    try:
        with path.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception:
        config = {}
    config.setdefault("api_base_url", DEFAULT_API_BASE_URL)
    config.setdefault("scan_days", 7)
    config.setdefault("scan_timeout_seconds", 900)
    config.setdefault("default_scan_profile", "standard")
    config.setdefault("scan_profiles", {})
    config.setdefault("storage_base_dir", "")
    return config


def scan_profiles() -> dict:
    return {
        "quick": {
            "scan_days": 3,
            "scan_timeout_seconds": 480,
            "max_files_scanned": 12000,
            "skip_browser_artifacts": True,
            "skip_recovery_metadata": True,
            "description": "Faster triage scan. Some slower artifact sources are skipped and listed as limitations.",
        },
        "standard": {
            "scan_days": 14,
            "scan_timeout_seconds": 1200,
            "max_files_scanned": 30000,
            "skip_browser_artifacts": False,
            "skip_recovery_metadata": False,
            "description": "Balanced scan with broad Roblox, execution, file, AV, browser, and artifact coverage.",
        },
        "deep": {
            "scan_days": 30,
            "scan_timeout_seconds": 2400,
            "max_files_scanned": 120000,
            "skip_browser_artifacts": False,
            "skip_recovery_metadata": False,
            "description": "Maximum coverage scan for stronger review. This can take significantly longer.",
        },
    }


def normalize_scan_profile(profile: str | None) -> str:
    value = str(profile or "standard").strip().lower()
    return value if value in {"quick", "standard", "deep"} else "standard"


def apply_scan_profile(config: dict, profile: str | None) -> dict:
    selected = normalize_scan_profile(profile or config.get("default_scan_profile"))
    merged = dict(config)
    for key in ("skip_browser_artifacts", "skip_recovery_metadata", "max_files_scanned", "scan_profile", "scan_profile_description"):
        merged.pop(key, None)
    profile_config = {**scan_profiles().get(selected, scan_profiles()["standard"]), **dict(config.get("scan_profiles", {}).get(selected, {}))}
    for key, value in profile_config.items():
        merged[key] = value
    merged["scan_profile"] = selected
    merged["scan_profile_description"] = profile_config.get("description", "")
    return merged


def default_storage_root() -> Path:
    user_profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
    documents = user_profile / "Documents"
    return documents / "Securo"


def storage_root(config: dict) -> Path:
    configured = str(config.get("storage_base_dir") or "").strip()
    if configured:
        return Path(os.path.expandvars(configured)).expanduser()
    return default_storage_root()


def path_starts_with(path: str, root: Path) -> bool:
    if not path or "://" in path:
        return False
    try:
        candidate = str(Path(os.path.expandvars(path)).resolve()).lower()
        base = str(root.resolve()).lower()
    except Exception:
        candidate = os.path.normcase(os.path.abspath(os.path.expandvars(path)))
        base = os.path.normcase(os.path.abspath(str(root)))
    return candidate == base or candidate.startswith(base.rstrip("\\/") + os.sep)


def securo_internal_roots(config: dict | None = None) -> list[Path]:
    roots = [app_dir()]
    frozen_internal = Path(getattr(sys, "_MEIPASS", ""))
    if str(frozen_internal):
        roots.append(frozen_internal)
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    program_files = os.environ.get("ProgramFiles", "")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "")
    for base in [local, roaming, program_files, program_files_x86]:
        if base:
            roots.append(Path(base) / APP_NAME)
    if config is not None:
        roots.append(storage_root(config))
    unique = []
    seen = set()
    for root in roots:
        if not root:
            continue
        try:
            key = str(root.resolve()).lower()
        except Exception:
            key = os.path.normcase(os.path.abspath(str(root)))
        if key not in seen:
            unique.append(root)
            seen.add(key)
    return unique


def securo_internal_path(path: str, config: dict | None = None) -> bool:
    if not path:
        return False
    lowered = str(path).lower()
    looks_like_path = bool(re.match(r"^[a-z]:[\\/]", str(path), re.I) or str(path).startswith(("\\\\", "/", "~")) or "\\" in str(path) or "/" in str(path))
    internal_names = (
        "sqlite3.dll",
        "libcrypto-3-x64.dll",
        "libssl-3-x64.dll",
        "python312.dll",
        "python3.dll",
        "vcruntime140.dll",
        "base_library.zip",
        "robloxpcactivitychecker.exe",
        "securochecker.exe",
    )
    if any(name in lowered for name in internal_names) and ("\\securo" in lowered or "\\_internal\\" in lowered):
        return True
    if not looks_like_path:
        return False
    try:
        exists_or_marked = Path(os.path.expandvars(str(path))).exists() or "\\securo" in lowered or "/securo" in lowered or "\\_internal\\" in lowered or "/_internal/" in lowered
    except OSError:
        exists_or_marked = "\\securo" in lowered or "/securo" in lowered or "\\_internal\\" in lowered or "/_internal/" in lowered
    if not exists_or_marked:
        return False
    return any(path_starts_with(path, root) for root in securo_internal_roots(config))


def internal_securo_text(text: str, config: dict | None = None) -> bool:
    lowered = str(text or "").lower()
    if not lowered:
        return False
    if any(name in lowered for name in ("sqlite3.dll", "libcrypto-3-x64.dll", "python312.dll", "vcruntime140.dll", "robloxpcactivitychecker.exe", "securochecker.exe")):
        return True
    for root in securo_internal_roots(config):
        root_text = str(root).lower()
        if root_text and root_text in lowered:
            return True
    return False


def filter_customer_timeline(timeline: list[dict], config: dict) -> list[dict]:
    return [event for event in timeline if not internal_securo_text(" ".join(str(v) for v in event.values()), config)]


def ensure_storage_dirs(config: dict) -> dict[str, Path]:
    root = storage_root(config)
    dirs = {
        "root": root,
        "reports": root / "Reports",
        "history": root / "History",
        "logs": root / "Logs",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def app_log_path(config: dict) -> Path:
    return ensure_storage_dirs(config)["logs"] / "application_logs.log"


def write_app_log(config: dict, message: str):
    try:
        path = app_log_path(config)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().isoformat(sep=" ", timespec="seconds")
        with path.open("a", encoding="utf-8") as f:
            f.write(f"{stamp} {message}\n")
    except Exception:
        pass


def open_folder(path: Path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def iso_now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def cutoff(days: int) -> dt.datetime:
    return dt.datetime.now() - dt.timedelta(days=days)


def parse_iso_event_time(value: str):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
    except ValueError:
        return None


def run_command(args, timeout=20) -> str:
    try:
        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return f"COMMAND_ERROR: {exc}"


def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def normalize_path(path: str) -> str:
    if not path:
        return ""
    path = os.path.expandvars(path.strip('" '))
    try:
        return str(Path(path).resolve())
    except Exception:
        return path


def signer_info(path: str) -> dict:
    if not path or not Path(path).exists():
        return {"status": "missing", "subject": "", "issuer": ""}
    ps = (
        "$s = Get-AuthenticodeSignature -LiteralPath "
        + json.dumps(path)
        + "; [pscustomobject]@{Status=$s.Status.ToString();Subject=$s.SignerCertificate.Subject;Issuer=$s.SignerCertificate.Issuer} | ConvertTo-Json -Compress"
    )
    out = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=15)
    try:
        data = json.loads(out)
        return {
            "status": str(data.get("Status") or ""),
            "subject": str(data.get("Subject") or ""),
            "issuer": str(data.get("Issuer") or ""),
        }
    except Exception:
        return {"status": "unknown", "subject": "", "issuer": ""}


def is_known_safe_signer(signer: dict, config: dict) -> bool:
    text = f"{signer.get('subject', '')} {signer.get('issuer', '')}"
    return any(safe.lower() in text.lower() for safe in config["known_safe_signers"])


def trusted_dampened_signer(signer: dict) -> bool:
    if (signer.get("status") or "").lower() != "valid":
        return False
    text = f"{signer.get('subject', '')} {signer.get('issuer', '')}".lower()
    return any(safe.lower() in text for safe in TRUST_DAMPEN_SIGNERS)


def common_dependency_path(path: str) -> bool:
    name = Path(path or "").name.lower()
    return any(marker in name for marker in COMMON_DEPENDENCY_NAMES)


def mainstream_software_path(path: str) -> bool:
    low = normalize_path(path).lower() if path else ""
    return any(marker in low for marker in MAINSTREAM_SOFTWARE_PATH_MARKERS)


def trusted_location_path(path: str) -> bool:
    if not path or "://" in path:
        return False
    low = normalize_path(path).lower()
    trusted_roots = [
        os.environ.get("WINDIR", "C:\\Windows"),
        os.environ.get("ProgramFiles", "C:\\Program Files"),
        os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
    ]
    return any(low.startswith(str(root).lower().rstrip("\\/") + os.sep.lower()) for root in trusted_roots if root)


def protected_system_process_name(path_or_name: str) -> bool:
    return Path(path_or_name or "").name.lower() in PROTECTED_SYSTEM_PROCESS_NAMES


def operating_system_allowlisted_path(path: str) -> bool:
    if not path or "://" in path:
        return False
    low = normalize_path(path).lower()
    windir = os.environ.get("WINDIR", "C:\\Windows").lower()
    program_files = [os.environ.get("ProgramFiles", "C:\\Program Files"), os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")]
    if low.startswith(windir.rstrip("\\/") + os.sep.lower()):
        return True
    system_roots = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\")
    if any(marker in low for marker in system_roots):
        return True
    legitimate_program_roots = ("\\microsoft\\", "\\windows defender\\", "\\microsoft edge\\", "\\roblox\\versions\\")
    return any(low.startswith(str(root).lower().rstrip("\\/") + os.sep.lower()) and any(marker in low for marker in legitimate_program_roots) for root in program_files if root)


def strong_allowlisted_behavior(finding: dict) -> bool:
    types = set(finding.get("evidence_types", []))
    categories = set(finding.get("detection_categories", []))
    if types & ALLOWLIST_STRONG_BEHAVIOR_TYPES:
        return True
    if categories & ALLOWLIST_STRONG_BEHAVIOR_CATEGORIES:
        return True
    evidence_text = " ".join(str(x) for x in finding.get("supporting_evidence", [])).lower()
    behavior_terms = ("deleted", "deletion", "tamper", "wmi", "startup", "remote thread", "process access", "loaded into roblox", "defender")
    return any(term in evidence_text for term in behavior_terms)


def trusted_confirmation_behavior(finding: dict, config: dict) -> bool:
    if known_bad_hash(finding, config):
        return True
    types = set(finding.get("evidence_types", []))
    categories = set(finding.get("detection_categories", []))
    if types & TRUSTED_CONFIRMATION_TYPES:
        return True
    if categories & TRUSTED_CONFIRMATION_CATEGORIES:
        return True
    signer_status = (finding.get("signer", {}) or {}).get("status", "").lower()
    if signer_status in {"hashmismatch", "nottrusted", "unknownerror"}:
        return True
    evidence_text = " ".join(str(x) for x in finding.get("supporting_evidence", [])).lower()
    return any(term in evidence_text for term in ("remote thread", "process access", "loaded into roblox", "tamper", "hash mismatch", "signature"))


def protected_system_confirmation_behavior(finding: dict, config: dict) -> bool:
    if known_bad_hash(finding, config):
        return True
    categories = set(finding.get("detection_categories", []))
    if categories & {"Tampered File", "Modified File Extension", "Suspicious File Modification"}:
        return True
    signer_status = (finding.get("signer", {}) or {}).get("status", "").lower()
    if signer_status in {"hashmismatch", "nottrusted", "unknownerror"}:
        return True
    evidence_text = " ".join(str(x) for x in finding.get("supporting_evidence", [])).lower()
    return any(term in evidence_text for term in ("tamper", "hash mismatch", "signature", "modified"))


def allowlisted_finding(finding: dict, config: dict) -> bool:
    path = finding.get("path", "")
    if finding.get("suppressed") or securo_internal_path(path, config):
        return True
    if protected_system_process_name(path or finding.get("name", "")):
        return True
    if common_dependency_path(path) or finding.get("common_dependency"):
        return True
    if trusted_location_path(path):
        return True
    if operating_system_allowlisted_path(path):
        return True
    if mainstream_software_path(path):
        return True
    if trusted_dampened_signer(finding.get("signer", {})) and not known_bad_hash(finding, config):
        return True
    return False


def low_signal_path(path: str) -> bool:
    low = (path or "").lower()
    return any(marker in low for marker in LOW_SIGNAL_PATH_MARKERS)


def known_bad_hash(finding: dict, config: dict) -> bool:
    digest = (finding.get("sha256") or "").lower()
    return bool(digest and digest in {str(x).lower() for x in config.get("known_bad_hashes", [])})


def real_behavioral_evidence(finding: dict) -> bool:
    types = set(finding.get("evidence_types", []))
    if types & REAL_BEHAVIOR_EVIDENCE_TYPES:
        return True
    categories = set(finding.get("detection_categories", []))
    return bool(categories & {"Suspicious startup persistence", "WMI Persistence", "Skript Loader Trace"})


def exploit_specific_artifact(finding: dict, config: dict) -> bool:
    text = " ".join([
        finding.get("name", ""),
        finding.get("path", ""),
        " ".join(finding.get("supporting_evidence", [])),
    ]).lower()
    if known_bad_hash(finding, config):
        return True
    if any(term in text for term in EXPLOIT_FAMILY_TERMS):
        return True
    if any(term in text for term in ["executor", "injector", "exploit", "dllloader", "calibration loader", "unknown updater.exe", "skript loader", "skriptloader", "skript"]):
        return True
    name = Path(finding.get("path") or finding.get("name") or "").name.lower()
    return name in {"loader.js", "rbxscriptsignal.js"}


def risky_source_path(path: str) -> bool:
    low = path.lower()
    risky = ["\\appdata\\local\\temp\\", "\\downloads\\", "\\temp\\", "\\appdata\\roaming\\"]
    return any(part in low for part in risky)


def suspicious_name(path_or_name: str, config: dict) -> bool:
    low = Path(path_or_name).name.lower()
    return any(term in low for term in config["suspicious_name_terms"])


def suspicious_text(text: str, config: dict) -> bool:
    low = (text or "").lower()
    return any(term in low for term in config["suspicious_name_terms"])


def suspicious_extension(path: str, config: dict) -> bool:
    return Path(path).suffix.lower() in set(config.get("suspicious_extensions", []))


def user_writable_path(path: str) -> bool:
    low = (path or "").lower()
    markers = [
        "\\downloads\\",
        "\\desktop\\",
        "\\documents\\",
        "\\appdata\\",
        "\\temp\\",
        "\\programdata\\",
        "\\users\\public\\",
    ]
    return any(marker in low for marker in markers)


def parse_dt(value):
    if isinstance(value, dt.datetime):
        return value
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return dt.datetime.strptime(str(value)[:26], fmt)
        except ValueError:
            pass
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
    except Exception:
        return None


def near_any_session(time_value, sessions: list[dict], minutes=30) -> bool:
    event_time = parse_dt(time_value)
    if not event_time:
        return False
    for s in sessions:
        start = parse_dt(s.get("start_time"))
        end = parse_dt(s.get("end_time")) or start
        if not start:
            continue
        if abs((event_time - start).total_seconds()) <= minutes * 60:
            return True
        if end and start <= event_time <= end + dt.timedelta(minutes=minutes):
            return True
    return False


def first_time(*values) -> str:
    parsed = [parse_dt(v) for v in values if parse_dt(v)]
    if not parsed:
        return ""
    return min(parsed).isoformat(sep=" ", timespec="seconds")


def make_finding(path: str, name: str, source: str, config: dict) -> dict:
    norm = path if "://" in (path or "") else (normalize_path(path) if path else "")
    suppressed = securo_internal_path(norm, config)
    signer = signer_info(norm) if Path(norm).suffix.lower() in [".exe", ".dll"] else {"status": "not checked", "subject": "", "issuer": ""}
    finding = {
        "name": Path(norm).name if norm else name,
        "path": norm,
        "sha256": sha256_file(norm) if Path(norm).is_file() and Path(norm).suffix.lower() in [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".zip", ".rar", ".7z"] else "",
        "signer": signer,
        "parent_process": "",
        "target_process": ROBLOX_EXE,
        "first_seen": "",
        "score": 0,
        "score_breakdown": [],
        "supporting_evidence": [],
        "evidence_types": [],
        "detection_categories": [],
        "detections": [],
        "artifact_source": source,
        "attribution_explanation": "",
        "classification": "Indicator Found",
        "confidence_level": "Possible",
        "suppressed": suppressed,
        "suppression_reason": "Internal Securo Component" if suppressed else "",
    }
    if suppressed:
        return finding
    if is_known_safe_signer(signer, config):
        add_score(finding, config["score_rules"]["known_safe_signer"], "Signed by known-safe signer")
    elif signer.get("status", "").lower() in ["notsigned", "unknown", "missing"]:
        add_score(finding, config["score_rules"]["unsigned_executable"], "Unsigned or unverifiable executable")
    if user_writable_path(norm):
        amount = config["score_rules"]["risky_source_path"]
        if low_signal_path(norm):
            amount = min(amount, 3)
        add_score(finding, amount, "Path is user-writable or commonly abused" if amount > 3 else "Path is in a known noisy/bundled location; path score dampened")
    if trusted_dampened_signer(signer):
        finding["trust_dampened"] = True
        finding["supporting_evidence"].append("Valid trusted signer; downgraded unless paired with known-bad hash or real behavioral evidence.")
    if common_dependency_path(norm):
        finding["common_dependency"] = True
        finding["supporting_evidence"].append("Common dependency/runtime file; strings alone are not enough to confirm exploitation.")
    if low_signal_path(norm):
        finding["low_signal_path"] = True
        finding["supporting_evidence"].append("Known noisy folder context; path-abuse score is dampened.")
    return finding


def file_sample(path: str, limit=2_000_000) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def add_detection(finding: dict, category: str, reason: str, risk="Medium", points=20):
    if finding.get("suppressed"):
        return
    finding.setdefault("detection_categories", [])
    finding.setdefault("detections", [])
    detection_type = detection_type_for_category(category)
    if category not in finding["detection_categories"]:
        finding["detection_categories"].append(category)
    if not any(d.get("category") == category and d.get("reason") == reason for d in finding["detections"]):
        finding["detections"].append({"category": category, "type": detection_type, "reason": reason, "risk": risk})
        add_score(finding, points, f"{category}: {reason}")
        finding["supporting_evidence"].append(reason)


def detection_type_for_category(category: str) -> str:
    if category in HIGH_CONFIDENCE_CHEAT_CATEGORIES or category in CONFIRMED_EXPLOIT_CATEGORIES:
        return "Direct"
    if category in GENERIC_DETECTION_CATEGORIES:
        return "Generic"
    if category in SPECIFIC_DETECTION_CATEGORIES:
        return "Specific"
    if category in WARNING_DETECTION_CATEGORIES:
        return "Warning"
    if category in {"ShellBag Analyzer", "Recycle Bin", "Recovered File Metadata"}:
        return "Recovery"
    if category in {"Windows Defender", "Antivirus Detection"}:
        return "Antivirus"
    return "Manual Review"


def confidence_from_score(score: int, classification: str) -> str:
    if classification == "Confirmed Exploit":
        return "Confirmed"
    if score >= 50:
        return "Likely"
    if score >= 25:
        return "Likely"
    return "Possible"


def review_required_for_type(log_type: str, classification: str) -> bool:
    return log_type in {"Warning", "Recovery", "Manual Review"} or classification not in {"Confirmed Exploit", "Trusted Safe"}


def exploit_family_match(finding: dict, config: dict) -> bool:
    terms = set(EXPLOIT_FAMILY_TERMS)
    terms.update(str(t).lower() for t in config.get("suspicious_name_terms", []))
    text = " ".join(
        [
            str(finding.get("name", "")),
            str(finding.get("path", "")),
            " ".join(str(x) for x in finding.get("supporting_evidence", [])),
        ]
    ).lower()
    return any(term and term in text for term in terms)


def already_flagged_by_detection(finding: dict) -> bool:
    categories = set(finding.get("detection_categories", []))
    types = set(finding.get("evidence_types", []))
    non_keyword_types = types - {"executor_keyword"}
    non_keyword_categories = categories - {"Executor Keyword Match"}
    return bool(non_keyword_types or non_keyword_categories)


def normalize_executor_keyword(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def executor_filename_keyword_match(finding: dict, config: dict) -> bool:
    keywords = config.get("executor_confirmation_keywords") or []
    normalized_keywords = {normalize_executor_keyword(str(keyword)) for keyword in keywords if str(keyword).strip()}
    if not normalized_keywords:
        normalized_keywords = {normalize_executor_keyword(term) for term in EXPLOIT_FAMILY_TERMS}
    candidates = []
    for value in [finding.get("name", ""), finding.get("path", "")]:
        if not value:
            continue
        filename = Path(str(value)).name
        if Path(filename).suffix.lower() == ".exe":
            candidates.append(Path(filename).stem)
    return any(normalize_executor_keyword(candidate) in normalized_keywords for candidate in candidates)


def executor_keyword_match(finding: dict, config: dict) -> bool:
    if not already_flagged_by_detection(finding):
        return False
    return executor_filename_keyword_match(finding, config)


def apply_executor_keyword_check(finding: dict, config: dict):
    if executor_keyword_match(finding, config):
        add_detection(finding, "Executor Keyword Match", "Executor-related keyword found on an already-flagged artifact", "Medium", config["score_rules"].get("suspicious_name", 10))
        finding["evidence_types"].append("executor_keyword")


def has_supporting_artifact(finding: dict) -> bool:
    return bool(finding.get("supporting_evidence") or finding.get("detections") or finding.get("sha256"))


def has_timeline_anchor(finding: dict) -> bool:
    return bool(finding.get("first_seen") or finding.get("evidence_types"))


def detection_triggered(finding: dict) -> bool:
    return bool(finding.get("detection_categories") or finding.get("detections") or finding.get("evidence_types"))


def confirmation_threshold_reached(finding: dict, config: dict) -> bool:
    return int(finding.get("score", 0) or 0) >= int(config.get("category_thresholds", {}).get("confirmed", 70))


def confirmed_verification_gate(finding: dict, config: dict) -> bool:
    if not detection_triggered(finding):
        return False
    if not has_supporting_artifact(finding):
        return False
    if protected_system_process_name(finding.get("path") or finding.get("name", "")) and not protected_system_confirmation_behavior(finding, config):
        return False
    if allowlisted_finding(finding, config) and not trusted_confirmation_behavior(finding, config):
        return False
    if not confirmation_threshold_reached(finding, config):
        return False
    if not has_timeline_anchor(finding):
        return False
    return True


def engine_detected_executor_artifact(finding: dict, config: dict) -> bool:
    if not executor_keyword_match(finding, config):
        return False
    categories = set(finding.get("detection_categories", [])) - {"Executor Keyword Match"}
    detections = [d for d in finding.get("detections", []) if d.get("category") != "Executor Keyword Match"]
    local_engine_hits = len(categories) + len(detections)
    score = int(finding.get("score", 0) or 0)
    suspicious_threshold = int(config.get("category_thresholds", {}).get("suspicious", 35))
    if local_engine_hits >= 2:
        return True
    return bool(local_engine_hits >= 1 and score >= suspicious_threshold)


def confirmed_exploit_artifact(finding: dict, config: dict) -> bool:
    categories = set(finding.get("detection_categories", []))
    if not confirmed_verification_gate(finding, config):
        return False
    if known_bad_hash(finding, config):
        return True
    if real_behavioral_evidence(finding):
        return True
    if engine_detected_executor_artifact(finding, config):
        return True
    if executor_keyword_match(finding, config) and (categories & HIGH_CONFIDENCE_CHEAT_CATEGORIES or categories & CONFIRMED_EXPLOIT_CATEGORIES):
        return True
    return False


def finding_confidence_level(finding: dict) -> str:
    if finding.get("forensic_confidence"):
        return confidence_to_legacy(finding.get("forensic_confidence", "Low"))
    if finding.get("classification") == "Confirmed Exploit":
        return "Confirmed"
    categories = set(finding.get("detection_categories", []))
    evidence_types = set(finding.get("evidence_types", []))
    evidence_count = len(categories) + len(evidence_types) + min(len(finding.get("supporting_evidence", [])), 3)
    if finding.get("classification") == "Suspicious" or evidence_count >= 3 or finding.get("score", 0) >= 50:
        return "Likely"
    return "Possible"


def inspect_file_indicators(path: str, finding: dict):
    suffix = Path(path).suffix.lower()
    if suffix not in {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".ahk", ".zip", ".rar", ".7z", ".jar"}:
        return
    data = file_sample(path)
    lower = data.lower()
    name = Path(path).name.lower()
    path_lower = (path or "").lower()

    if re.search(r"\.(jpg|png|gif|txt|pdf|docx?)\.(exe|dll|scr|bat|cmd|ps1)$", name):
        add_detection(finding, "Modified File Extension", "Executable uses a double-extension or disguised extension pattern", "High", 35)
        finding["evidence_types"].append("modified_extension")
    if path.startswith(NETWORK_PATH_PREFIXES):
        add_detection(finding, "Network File Execution", "Artifact path is on a network/remote location", "Medium", 25)
        finding["evidence_types"].append("network_artifact")
    if len(path) > 2 and path[1] == ":" and path[0].upper() in EXTERNAL_DRIVE_LETTERS:
        add_detection(finding, "External Device Execution", "Artifact path is on a removable/external-drive style letter", "Medium", 20)
        finding["evidence_types"].append("external_device")
    if suffix == ".rar" and suspicious_name(name, {"suspicious_name_terms": list(EXPLOIT_FAMILY_TERMS)}):
        add_detection(finding, "RAR File Execution", "RAR archive name matches known exploit/loader terms", "Medium", 25)
        finding["evidence_types"].append("archive_artifact")

    if suffix == ".ahk" or b"autohotkey" in lower or b"ahk2exe" in lower:
        add_detection(finding, "AutoHotkey Usage", "AutoHotkey script or compiled AHK signature found", "High", 35)
        finding["evidence_types"].append("autohotkey")
    if b"autoit" in lower or b"au3!" in lower or name.endswith(".au3"):
        add_detection(finding, "AutoIT Usage", "AutoIT script or compiled AutoIT signature found", "High", 35)
        finding["evidence_types"].append("autoit")
    if any(term in lower for term in [b"skript loader", b"skriptloader", b"skript.gg", b"skript hook", b"skript bypass"]):
        add_detection(finding, "Skript Loader Trace", "Known Skript Loader-style trace found in metadata/content", "High", 55)
        finding["evidence_types"].append("known_cheat_artifact")

    if suffix in {".exe", ".dll"} and data.startswith(b"MZ"):
        # .NET assemblies usually include CLR metadata strings in the PE.
        if b"bsjb" in lower or b"mscoree.dll" in lower or b".netframework" in lower or b"system.runtime" in lower:
            category = "DotNetDLL" if suffix == ".dll" else "DotNetExecutable"
            add_detection(finding, category, "C#/.NET assembly metadata found", "Medium", 25)
            finding["evidence_types"].append("dotnet")
        if b"upx0" in lower or b"upx1" in lower or b"upx!" in lower:
            add_detection(finding, "UPX Packer", "UPX section/signature found", "High", 35)
            finding["evidence_types"].append("packed")
        if b"vmprotect" in lower:
            add_detection(finding, "Generic Packed File", "VMProtect marker found", "High", 40)
            finding["evidence_types"].append("packed")
        if b"themida" in lower or b"winlicense" in lower:
            add_detection(finding, "Generic Packed File", "Themida/WinLicense marker found", "High", 40)
            finding["evidence_types"].append("packed")
        if shannon_entropy(data[: min(len(data), 1_000_000)]) >= 7.2 and finding.get("signer", {}).get("status", "").lower() != "valid":
            add_detection(finding, "Generic Packed File", "High entropy unsigned executable content", "High", 35)
            finding["evidence_types"].append("packed")
        if any(cat in finding.get("detection_categories", []) for cat in ["DotNetExecutable", "DotNetDLL"]) and "Generic Packed File" in finding.get("detection_categories", []):
            add_detection(finding, "Suspicious Net File", "Packed/protected .NET assembly", "High", 45)
        if finding.get("signer", {}).get("status", "").lower() in {"hashmismatch", "nottrusted", "unknownerror"}:
            add_detection(finding, "Tampered File", "Authenticode status suggests modification or trust failure", "High", 35)
        if suffix == ".dll" and user_writable_path(path) and suspicious_name(path, {"suspicious_name_terms": list(EXPLOIT_FAMILY_TERMS) + ["inject", "loader", "mapper", "hook"]}):
            add_detection(finding, "Suspicious DLL Loading", "Suspicious DLL name in a user-writable path", "High", 35)
            finding["evidence_types"].append("suspicious_dll")
        if any(term in lower for term in [b"bypass", b"anti dump", b"antidump", b"anti-debug", b"antidebug", b"hide process", b"self destruct", b"selfdelete", b"deletefile"]):
            add_detection(finding, "Generic Bypass Method", "Bypass, anti-debug, anti-forensic, or self-destruct string found", "High", 35)
            finding["evidence_types"].append("bypass_method")
        if any(term in lower for term in [b"virtualbox", b"vmware", b"qemu", b"sandboxie", b"parallels", b"virtual pc"]):
            add_detection(finding, "Virtualization Check", "Virtualization or sandbox detection string found", "Medium", 15)
            finding["evidence_types"].append("warning")
        if any(term in lower for term in [b"writeprocessmemory", b"createremotethread", b"ntcreatethreadex", b"manualmap", b"manual map", b"loadlibrary"]):
            add_detection(finding, "RAM Suspicious Indicator", "Runtime injection API/string indicator found in file content", "High", 35)
            finding["evidence_types"].append("ram_indicator")
    if ".minecraft" in path_lower or "\\mods\\" in path_lower or "minecraft" in path_lower:
        if suffix in {".jar", ".zip", ".dll", ".exe"} or any(term in lower for term in [b"mixin", b"forge", b"fabric", b"minecraft"]):
            add_detection(finding, "Game Instance Modification", "Minecraft Java/game instance modification artifact observed", "Medium", 25)
            finding["evidence_types"].append("ruin_mode")

    special_terms = {
        "A1": ["a1"],
        "A2": ["a2"],
        "A3": ["a3"],
        "X1": ["x1"],
        "X2": ["x2"],
        "L1": ["l1"],
        "B": [" bsod ", "bypass"],
        "D": ["driver"],
        "F5": ["f5"],
        "P1": ["process hollow", "hollowing"],
        "P2": ["runpe", "process replacement"],
        "S1": ["s1"],
        "DLL": [".dll", "dll inject"],
        "BSoD": ["bsod"],
        "S2": ["s2"],
        "C3": ["c3"],
        "C4": ["c4"],
        "A": ["manual map", "mapper"],
    }
    searchable = f" {name} {lower[:200000].decode('latin1', errors='ignore')} "
    for category, terms in special_terms.items():
        if any(term in searchable for term in terms):
            high_conf = category in {"S1", "DLL", "BSoD", "S2", "C3", "C4", "A"}
            add_detection(finding, category, f"{category} indicator found in file metadata/content", "High" if high_conf else "Medium", 45 if high_conf else 20)
            finding["evidence_types"].append("cheat_indicator")


def merge_findings(findings: dict, finding: dict) -> dict:
    if finding.get("suppressed"):
        return finding
    key = (finding.get("path") or finding.get("name") or "unknown").lower()
    if key not in findings:
        findings[key] = finding
        return findings[key]
    existing = findings[key]
    existing["score"] += finding.get("score", 0)
    existing["score_breakdown"].extend(finding.get("score_breakdown", []))
    existing["supporting_evidence"].extend(finding.get("supporting_evidence", []))
    existing["evidence_types"] = sorted(set(existing.get("evidence_types", []) + finding.get("evidence_types", [])))
    existing["detection_categories"] = sorted(set(existing.get("detection_categories", []) + finding.get("detection_categories", [])))
    existing.setdefault("detections", [])
    for detection in finding.get("detections", []):
        if not any(d.get("category") == detection.get("category") and d.get("reason") == detection.get("reason") for d in existing["detections"]):
            existing["detections"].append(detection)
    existing["first_seen"] = first_time(existing.get("first_seen"), finding.get("first_seen")) or existing.get("first_seen") or finding.get("first_seen")
    if not existing.get("sha256") and finding.get("sha256"):
        existing["sha256"] = finding["sha256"]
    return existing


def categorize_finding(finding: dict, config: dict) -> str:
    types = set(finding.get("evidence_types", []))
    categories = set(finding.get("detection_categories", []))
    score = finding.get("score", 0)
    trusted = trusted_dampened_signer(finding.get("signer", {}))
    dependency = common_dependency_path(finding.get("path", ""))
    behavior = real_behavioral_evidence(finding)
    exploit_specific = exploit_specific_artifact(finding, config)
    allowlisted = allowlisted_finding(finding, config)
    if allowlisted and not strong_allowlisted_behavior(finding):
        return "Likely False Positive" if categories or types else "Trusted Safe"
    if allowlisted and strong_allowlisted_behavior(finding):
        return "Suspicious"
    if trusted and not behavior and not known_bad_hash(finding, config):
        return "Trusted Safe" if not categories else "Likely False Positive"
    if (dependency or finding.get("low_signal_path")) and not behavior and not exploit_specific:
        return "Likely False Positive" if categories else "Trusted Safe"
    if "possible_context" in types:
        return "Indicator Found"
    if confirmed_exploit_artifact(finding, config):
        return "Confirmed Exploit"
    if types & {"sysmon_remote_thread", "sysmon_process_access", "suspicious_module_load"}:
        return "Confirmed Exploit" if confirmed_exploit_artifact(finding, config) else "Suspicious"
    if categories & HIGH_CONFIDENCE_CHEAT_CATEGORIES and not exploit_specific:
        return "Indicator Found"
    if categories & {"A1", "A2", "A3", "X1", "X2", "RAM Suspicious Indicator"} and not behavior:
        return "Indicator Found"
    if "Suspicious DLL Loading" in categories and not ("suspicious_module_load" in types or finding.get("signer", {}).get("status", "").lower() in {"notsigned", "unknown", "missing"}):
        return "Indicator Found"
    if score >= config["category_thresholds"]["suspicious"]:
        return "Suspicious"
    if score >= config["category_thresholds"]["weak"]:
        return "Indicator Found"
    return "Indicator Found"


def finalize_findings(findings: list[dict], config: dict) -> list[dict]:
    visible = [f for f in findings if not f.get("suppressed") and not securo_internal_path(f.get("path", ""), config)]
    for f in visible:
        apply_executor_keyword_check(f, config)
        f["score"] = max(0, f.get("score", 0))
        f["classification"] = categorize_finding(f, config)
        if f["classification"] == "Confirmed Exploit" and f["score"] < config["category_thresholds"]["confirmed"]:
            add_score(f, config["category_thresholds"]["confirmed"] - f["score"], "Confirmed exploit artifact rule matched")
        if f["classification"] == "Confirmed Exploit":
            f["attribution_explanation"] = "Confirmed Roblox exploit artifact evidence exists for this item."
        elif f["classification"] == "Suspicious":
            f["attribution_explanation"] = "This artifact is suspicious because it is exploit-related, user-writable, or close in time to Roblox activity, but direct injection proof may be missing."
        elif f["classification"] == "Likely False Positive":
            f["attribution_explanation"] = "This looks like a dependency, trusted signed file, or noisy path context. It should not be treated as cheating without behavioral evidence."
        elif f["classification"] == "Trusted Safe":
            f["attribution_explanation"] = "This file is trusted/safe in the available evidence."
        else:
            f["attribution_explanation"] = "An indicator was found, but it is not enough to confirm cheating by itself."
        f["confidence_level"] = finding_confidence_level(f)
    return sorted(visible, key=lambda x: x.get("score", 0), reverse=True)


def get_common_roblox_log_dirs() -> list[Path]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    user = Path(os.environ.get("USERPROFILE", ""))
    dirs = [
        local / "Roblox" / "logs",
        local / "Roblox" / "logs" / "archive",
        user / "AppData" / "Local" / "Roblox" / "logs",
    ]
    found = []
    for d in dirs:
        try:
            if d.exists():
                found.append(d)
        except OSError:
            continue
    return found


def parse_log_timestamp(line: str, fallback_date: dt.datetime):
    patterns = [
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        r"(\d{2}:\d{2}:\d{2})",
    ]
    for pat in patterns:
        m = re.search(pat, line)
        if not m:
            continue
        value = m.group(1)
        if len(value) == 8:
            return fallback_date.replace(hour=int(value[:2]), minute=int(value[3:5]), second=int(value[6:8]), microsecond=0)
        return parse_dt(value)
    return None


def format_duration(start: str, end: str) -> str:
    s = parse_dt(start)
    e = parse_dt(end)
    if not s or not e or e < s:
        return ""
    seconds = int((e - s).total_seconds())
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def parse_roblox_logs(days: int, config: dict | None = None) -> tuple[list[dict], list[dict]]:
    sessions = []
    timeline = []
    cut = cutoff(days)
    config = config or {"suspicious_name_terms": []}
    for folder in get_common_roblox_log_dirs():
        try:
            logs = list(folder.glob("*.log"))
        except OSError:
            continue
        for path in logs:
            try:
                mtime = dt.datetime.fromtimestamp(path.stat().st_mtime)
            except Exception:
                continue
            if mtime < cut:
                continue
            session = {
                "log_file": str(path),
                "start_time": mtime.isoformat(sep=" ", timespec="seconds"),
                "end_time": "",
                "duration": "",
                "user_id": "",
                "username": "",
                "display_name": "",
                "place_id": "",
                "job_id": "",
                "version": "",
                "load_client_settings": [],
                "errors": [],
                "crashes": [],
                "flags": [],
                "suspicious_lines": [],
            }
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                lines = []
            seen_times = []
            for line in lines:
                ts = parse_log_timestamp(line, mtime)
                if ts:
                    seen_times.append(ts)
                if "LoadClientSettings" in line:
                    session["load_client_settings"].append(line.strip()[:500])
                if re.search(r"\b(error|warn|failed|exception)\b", line, re.I):
                    session["errors"].append(line.strip()[:500])
                if re.search(r"\b(crash|fatal|minidump|stack trace)\b", line, re.I):
                    session["crashes"].append(line.strip()[:500])
                if re.search(r"\b(fflag|dfint|fflag|flag)\b", line, re.I):
                    session["flags"].append(line.strip()[:500])
                if suspicious_text(line, config):
                    session["suspicious_lines"].append(line.strip()[:500])
                for key, pat in [
                    ("user_id", r"(?:userid|user id|userId)[^\d]*(\d+)"),
                    ("place_id", r"(?:placeid|place id|gameid|game id|placeId)[^\d]*(\d+)"),
                    ("username", r"(?:username|user name)[^\w@.-]*([\w@.-]{2,64})"),
                    ("display_name", r"(?:displayname|display name|displayName)[^\w@.-]*([\w @.-]{2,64})"),
                    ("job_id", r"(?:jobid|job id|jobId)[^\w-]*([\w-]{8,})"),
                    ("version", r"(?:version|client version)[^\d]*(\d+(?:\.\d+){1,4})"),
                ]:
                    if not session[key]:
                        m = re.search(pat, line, re.I)
                        if m:
                            session[key] = m.group(1)
            if seen_times:
                session["start_time"] = min(seen_times).isoformat(sep=" ", timespec="seconds")
                session["end_time"] = max(seen_times).isoformat(sep=" ", timespec="seconds")
                session["duration"] = format_duration(session["start_time"], session["end_time"])
            if not session["duration"]:
                session["duration"] = "unknown"
            sessions.append(session)
            timeline.append({"time": session["start_time"], "source": "Roblox log", "text": f"{ROBLOX_EXE} session/log observed: {path.name}"})
            for line in session["crashes"][:3]:
                timeline.append({"time": session["start_time"], "source": "Roblox log", "text": f"Roblox crash/fatal line: {line[:160]}"})
    deduped = {}
    for s in sessions:
        key = (s.get("start_time"), s.get("end_time"), s.get("place_id"), s.get("job_id"), s.get("user_id"), s.get("username"))
        deduped[key] = s
    return list(deduped.values()), timeline


def query_events(log_name: str, event_ids: list[int], days: int, max_events=300) -> list[dict]:
    ms = days * 24 * 60 * 60 * 1000
    ids = " or ".join([f"EventID={i}" for i in event_ids])
    query = f"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    out = run_command(["wevtutil", "qe", log_name, "/q:" + query, "/f:xml", "/rd:true", "/c:" + str(max_events)], timeout=45)
    events = []
    for chunk in re.findall(r"<Event[\s\S]*?</Event>", out):
        try:
            root = ET.fromstring(chunk)
            system = root.find("e:System", EVENT_NS)
            event_id = int(system.findtext("e:EventID", default="0", namespaces=EVENT_NS))
            provider = system.find("e:Provider", EVENT_NS).attrib.get("Name", "")
            time_node = system.find("e:TimeCreated", EVENT_NS)
            created = parse_iso_event_time(time_node.attrib.get("SystemTime", "")) if time_node is not None else None
            data = {}
            for d in root.findall(".//e:EventData/e:Data", EVENT_NS):
                name = d.attrib.get("Name", "")
                data[name] = d.text or ""
            events.append({"event_id": event_id, "provider": provider, "time": created, "data": data, "raw": chunk})
        except Exception:
            continue
    return events


def event_log_exists(log_name: str) -> bool:
    out = run_command(["wevtutil", "gl", log_name], timeout=10)
    return "name:" in out.lower() or "enabled:" in out.lower()


def safe_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def safe_glob_any(base: Path, pattern: str) -> bool:
    try:
        return any(base.glob(pattern))
    except OSError:
        return False


def evidence_quality(days: int) -> dict:
    sysmon_exists = event_log_exists("Microsoft-Windows-Sysmon/Operational")
    security_exists = event_log_exists("Security")
    defender_exists = event_log_exists("Microsoft-Windows-Windows Defender/Operational")
    q = {
        "Sysmon installed": sysmon_exists,
        "Sysmon Event ID 1 available": False,
        "Sysmon Event ID 7 available": False,
        "Sysmon Event ID 8 available": False,
        "Sysmon Event ID 10 available": False,
        "Security 4688 available": False,
        "Security 4688 command line available": False,
        "Prefetch available": safe_exists(Path("C:/Windows/Prefetch")),
        "Amcache available": safe_exists(Path("C:/Windows/AppCompat/Programs/Amcache.hve")),
        "Defender logs available": defender_exists,
        "Defender history folders available": safe_exists(Path("C:/ProgramData/Microsoft/Windows Defender/Scans/History/Service")),
        "PowerShell history available": safe_glob_any(Path(os.environ.get("APPDATA", "")), "Microsoft/Windows/PowerShell/PSReadLine/*history*.txt"),
        "Roblox logs available": bool(get_common_roblox_log_dirs()),
        "Chrome history available": safe_exists(Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data/Default/History"),
        "Edge history available": safe_exists(Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data/Default/History"),
        "Firefox history available": safe_exists(Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles"),
    }
    if sysmon_exists:
        evs = query_events("Microsoft-Windows-Sysmon/Operational", [1, 7, 8, 10], days, max_events=80)
        seen = {e["event_id"] for e in evs}
        for i in [1, 7, 8, 10]:
            q[f"Sysmon Event ID {i} available"] = i in seen
    if security_exists:
        evs = query_events("Security", [4688], days, max_events=80)
        q["Security 4688 available"] = bool(evs)
        q["Security 4688 command line available"] = any((e["data"].get("CommandLine") or "").strip() for e in evs)
    return q


def add_score(finding: dict, amount: int, reason: str):
    if finding.get("suppressed"):
        return
    finding["score"] += amount
    finding["score_breakdown"].append({"points": amount, "reason": reason})


def classify(score: int, config: dict) -> str:
    t = config.get("category_thresholds", {"confirmed": 70, "suspicious": 35, "weak": 10})
    if score >= t["confirmed"]:
        return "Confirmed Exploit"
    if score >= t["suspicious"]:
        return "Suspicious"
    return "Indicator Found"


def process_identity(path: str, config: dict) -> dict:
    norm = normalize_path(path)
    signer = signer_info(norm)
    return {
        "name": Path(norm).name if norm else "",
        "path": norm,
        "sha256": sha256_file(norm),
        "signer": signer,
        "known_safe_signer": is_known_safe_signer(signer, config),
    }


def find_near_roblox_launch(time_value, roblox_launches: list[dt.datetime], minutes=30) -> bool:
    if not time_value:
        return False
    return any(abs((time_value - launch).total_seconds()) <= minutes * 60 for launch in roblox_launches)


def collect_process_evidence(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    findings = {}
    timeline = []
    sysmon_events = query_events("Microsoft-Windows-Sysmon/Operational", [1, 7, 8, 10], days, max_events=800)
    sec_events = query_events("Security", [4688], days, max_events=400)
    defender_events = query_events("Microsoft-Windows-Windows Defender/Operational", [1116, 1117, 5007, 5013], days, max_events=200)
    roblox_launches = []

    for ev in sysmon_events + sec_events:
        data_text = json.dumps(ev["data"], ensure_ascii=False)
        if ROBLOX_EXE.lower() in data_text.lower():
            if ev["event_id"] in [1, 4688]:
                roblox_launches.append(ev["time"])
                if ev["time"]:
                    timeline.append({"time": ev["time"].isoformat(sep=" ", timespec="seconds"), "source": f"Event {ev['event_id']}", "text": f"{ROBLOX_EXE} launched or process-created context observed"})

    def get_finding(path: str, fallback_name="unknown") -> dict:
        ident = process_identity(path, config)
        key = ident["path"] or fallback_name
        if key not in findings:
            suppressed = securo_internal_path(ident["path"], config)
            findings[key] = {
                "name": ident["name"] or fallback_name,
                "path": ident["path"],
                "sha256": ident["sha256"],
                "signer": ident["signer"],
                "parent_process": "",
                "target_process": ROBLOX_EXE,
                "first_seen": "",
                "score": 0,
                "score_breakdown": [],
                "supporting_evidence": [],
                "evidence_types": [],
                "detection_categories": [],
                "detections": [],
                "artifact_source": "event_log",
                "attribution_explanation": "",
                "classification": "Indicator Found",
                "confidence_level": "Possible",
                "suppressed": suppressed,
                "suppression_reason": "Internal Securo Component" if suppressed else "",
            }
            if suppressed:
                return findings[key]
            if ident["known_safe_signer"]:
                add_score(findings[key], config["score_rules"]["known_safe_signer"], "Signed by known-safe signer")
            if ident["signer"].get("status", "").lower() in ["notsigned", "unknown", "missing"]:
                add_score(findings[key], config["score_rules"]["unsigned_executable"], "Unsigned or unverifiable executable")
            if risky_source_path(ident["path"]):
                add_score(findings[key], config["score_rules"]["risky_source_path"], "Executable path is in AppData, Temp, or Downloads")
            if trusted_dampened_signer(ident["signer"]):
                findings[key]["trust_dampened"] = True
                findings[key]["supporting_evidence"].append("Valid trusted signer; downgraded unless paired with known-bad hash or real behavioral evidence.")
            if common_dependency_path(ident["path"]):
                findings[key]["common_dependency"] = True
                findings[key]["supporting_evidence"].append("Common dependency/runtime file; strings alone are not enough to confirm exploitation.")
            if low_signal_path(ident["path"]):
                findings[key]["low_signal_path"] = True
                findings[key]["supporting_evidence"].append("Known noisy folder context; path-abuse score is dampened.")
        return findings[key]

    for ev in sysmon_events:
        d = ev["data"]
        text = json.dumps(d, ensure_ascii=False)
        source_path = d.get("SourceImage") or d.get("Image") or ""
        target_path = d.get("TargetImage") or ""
        if ROBLOX_EXE.lower() not in text.lower():
            continue
        if ev["event_id"] == 1:
            image = d.get("Image", "")
            if image:
                f = get_finding(image, Path(image).name)
                f["parent_process"] = d.get("ParentImage", f["parent_process"])
                if not f["first_seen"] and ev["time"]:
                    f["first_seen"] = ev["time"].isoformat(sep=" ", timespec="seconds")
                if find_near_roblox_launch(ev["time"], roblox_launches) or near_any_session(ev["time"], sessions):
                    add_score(f, config["score_rules"]["near_roblox_launch"], "Launched within 30 minutes of Roblox activity")
                f["supporting_evidence"].append(f"Sysmon ID 1 process context: {image}")
                f["evidence_types"].append("process_execution")
                timeline.append({"time": f["first_seen"], "source": "Sysmon ID 1", "text": f"{Path(image).name} launched near Roblox context"})
        elif ev["event_id"] == 8 and ROBLOX_EXE.lower() in target_path.lower():
            f = get_finding(source_path, Path(source_path).name or "unknown source")
            add_score(f, config["score_rules"]["sysmon_remote_thread"], "Sysmon ID 8 remote thread into Roblox")
            f["supporting_evidence"].append("Sysmon ID 8 remote thread creation targeting Roblox")
            f["evidence_types"].append("sysmon_remote_thread")
            if ev["time"]:
                timeline.append({"time": ev["time"].isoformat(sep=" ", timespec="seconds"), "source": "Sysmon ID 8", "text": f"{f['name']} created a remote thread into {ROBLOX_EXE}"})
        elif ev["event_id"] == 10 and ROBLOX_EXE.lower() in target_path.lower():
            f = get_finding(source_path, Path(source_path).name or "unknown source")
            granted = d.get("GrantedAccess", "")
            call_trace = d.get("CallTrace", "")
            risky = any(term.lower() in (granted + " " + call_trace).lower() for term in config["dangerous_access_terms"])
            if risky:
                add_score(f, config["score_rules"]["sysmon_process_access_dangerous"], "Sysmon ID 10 dangerous Roblox process access")
            else:
                add_score(f, 10, "Sysmon ID 10 Roblox process access")
            f["supporting_evidence"].append(f"Sysmon ID 10 process access, GrantedAccess={granted}")
            f["evidence_types"].append("sysmon_process_access")
            if ev["time"]:
                timeline.append({"time": ev["time"].isoformat(sep=" ", timespec="seconds"), "source": "Sysmon ID 10", "text": f"{f['name']} opened a handle to {ROBLOX_EXE} ({granted})"})
        elif ev["event_id"] == 7 and ROBLOX_EXE.lower() in d.get("Image", "").lower():
            dll = d.get("ImageLoaded", "")
            if dll and risky_source_path(dll):
                f = get_finding(dll, Path(dll).name)
                add_score(f, config["score_rules"]["suspicious_dll_loaded"], "Suspicious DLL loaded into Roblox from risky path")
                f["supporting_evidence"].append(f"Sysmon ID 7 DLL loaded into Roblox: {dll}")
                f["evidence_types"].append("suspicious_module_load")
                if ev["time"]:
                    timeline.append({"time": ev["time"].isoformat(sep=" ", timespec="seconds"), "source": "Sysmon ID 7", "text": f"DLL loaded into Roblox from {dll}"})

    for ev in sec_events:
        d = ev["data"]
        image = d.get("NewProcessName") or d.get("ProcessName") or ""
        cmd = d.get("CommandLine") or ""
        if image and (suspicious_name(image, config) or ROBLOX_EXE.lower() in cmd.lower()):
            f = get_finding(image, Path(image).name)
            f["parent_process"] = d.get("ParentProcessName", f["parent_process"])
            f["supporting_evidence"].append("Security ID 4688 process creation context")
            f["evidence_types"].append("process_execution")
            if suspicious_name(image, config):
                f["evidence_types"].append("prefetch")
                add_detection(f, "Executed Suspicious File", "Suspicious executable process creation observed", "High", 30)
            if near_any_session(ev["time"], sessions):
                add_score(f, config["score_rules"]["near_roblox_session"], "Security 4688 execution occurred within 30 minutes of a Roblox session")
            if not f["first_seen"] and ev["time"]:
                f["first_seen"] = ev["time"].isoformat(sep=" ", timespec="seconds")

    for ev in defender_events:
        text = json.dumps(ev["data"], ensure_ascii=False)
        paths = re.findall(r"[A-Za-z]:\\[^\"<>|]+?\.exe", text, re.I)
        for path in paths:
            if suspicious_name(path, config) or risky_source_path(path):
                f = get_finding(path, Path(path).name)
                add_score(f, config["score_rules"]["defender_detection"], "Windows Defender / AV event context")
                f["supporting_evidence"].append(f"Defender event {ev['event_id']} mentioned this executable")
                f["evidence_types"].append("defender_detection")
                if ev["time"]:
                    timeline.append({"time": ev["time"].isoformat(sep=" ", timespec="seconds"), "source": f"Defender {ev['event_id']}", "text": f"Defender logged activity for {f['name']}"})

    for f in findings.values():
        f["score"] = max(0, f["score"])
        f["classification"] = categorize_finding(f, config)
        if f["classification"] == "Confirmed Exploit":
            f["attribution_explanation"] = "This artifact has direct Roblox process interaction evidence."
        elif f["classification"] == "Suspicious":
            f["attribution_explanation"] = "This artifact is suspicious and Roblox-correlated, but the available logs may not prove injection."
        elif f["classification"] in {"Trusted Safe", "Likely False Positive"}:
            f["attribution_explanation"] = "Trusted signer, common dependency, or noisy path context lowered this result."
        else:
            f["attribution_explanation"] = "Available logs do not identify this as confirmed executor evidence; treat as context unless stronger evidence exists."
    return list(findings.values()), timeline


def scan_roots() -> list[Path]:
    user = Path(os.environ.get("USERPROFILE", ""))
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))
    roots = [
        user / "Downloads",
        user / "Desktop",
        user / "Documents",
        local,
        roaming,
        Path(os.environ.get("TEMP", "")),
        Path(os.environ.get("ProgramData", "C:/ProgramData")),
        local / "Roblox",
    ]
    unique = []
    seen = set()
    for root in roots:
        try:
            resolved = str(root.resolve()).lower()
            if resolved not in seen and root.exists():
                unique.append(root)
                seen.add(resolved)
        except OSError:
            continue
    return unique


def collect_prefetch_evidence(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Prefetch records execution hints even when Security/Sysmon process creation logs are absent.
    findings = {}
    timeline = []
    folder = Path("C:/Windows/Prefetch")
    if not safe_exists(folder):
        return [], []
    cut = cutoff(days)
    try:
        entries = list(folder.glob("*.pf"))
    except OSError:
        return [], []
    roblox_times = []
    for pf in entries:
        try:
            mtime = dt.datetime.fromtimestamp(pf.stat().st_mtime)
        except OSError:
            continue
        if mtime < cut:
            continue
        exe_name = pf.name.split("-")[0] + ".exe" if "-" in pf.name else pf.stem + ".exe"
        if ROBLOX_EXE.lower().replace(".exe", "") in pf.name.lower():
            roblox_times.append(mtime)
            timeline.append({"time": mtime.isoformat(sep=" ", timespec="seconds"), "source": "Prefetch", "text": f"Prefetch execution hint for {ROBLOX_EXE}"})
    for pf in entries:
        try:
            mtime = dt.datetime.fromtimestamp(pf.stat().st_mtime)
        except OSError:
            continue
        if mtime < cut:
            continue
        exe_name = pf.name.split("-")[0] + ".exe" if "-" in pf.name else pf.stem + ".exe"
        if not suspicious_name(exe_name, config):
            continue
        near = find_near_roblox_launch(mtime, roblox_times) or near_any_session(mtime, sessions)
        finding = make_finding("", exe_name, "prefetch", config)
        finding["first_seen"] = mtime.isoformat(sep=" ", timespec="seconds")
        add_score(finding, config["score_rules"]["prefetch_execution"], "Prefetch indicates suspicious executable ran")
        if near:
            add_score(finding, config["score_rules"]["near_roblox_session"], "Prefetch timestamp is within 30 minutes of Roblox activity")
        finding["supporting_evidence"].append(f"Prefetch file: {pf}")
        finding["evidence_types"].append("prefetch_execution")
        merge_findings(findings, finding)
        timeline.append({"time": finding["first_seen"], "source": "Prefetch", "text": f"Suspicious executable execution hint: {exe_name}"})
    return list(findings.values()), timeline


def collect_file_artifacts(days: int, config: dict, sessions: list[dict], verbose=False, progress=None) -> tuple[list[dict], list[dict]]:
    # File-system artifacts are indirect: they show exploit-like files existed, especially near Roblox play sessions.
    findings = {}
    timeline = []
    cut = cutoff(days)
    max_files = int(config.get("max_files_scanned") or 25000)
    seen_files = 0
    for root in scan_roots():
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            dirnames[:] = [d for d in dirnames if d.lower() not in {"node_modules", ".git", "windowsapps", "packages"}]
            dirnames[:] = [d for d in dirnames if not securo_internal_path(str(Path(dirpath) / d), config)]
            if securo_internal_path(dirpath, config):
                continue
            if seen_files > max_files:
                break
            for filename in filenames:
                seen_files += 1
                if progress and seen_files % 500 == 0:
                    progress(f"Checking file artifacts... files scanned={seen_files}", files_scanned=seen_files)
                if seen_files > max_files:
                    break
                path = Path(dirpath) / filename
                try:
                    st = path.stat()
                except OSError:
                    continue
                times = [
                    dt.datetime.fromtimestamp(st.st_ctime),
                    dt.datetime.fromtimestamp(st.st_mtime),
                    dt.datetime.fromtimestamp(st.st_atime),
                ]
                if max(times) < cut:
                    continue
                path_text = str(path)
                if securo_internal_path(path_text, config):
                    continue
                if not suspicious_extension(path_text, config):
                    continue
                finding = make_finding(path_text, filename, "file_system", config)
                inspect_file_indicators(path_text, finding)
                near_session = any(near_any_session(t, sessions) for t in times)
                structurally_flagged = bool(finding.get("detection_categories")) or near_session or common_dependency_path(path_text) or low_signal_path(path_text)
                if not structurally_flagged:
                    continue
                finding["first_seen"] = min(times).isoformat(sep=" ", timespec="seconds")
                add_score(finding, config["score_rules"]["file_artifact"], "Tracked file artifact found in common user/system location")
                if near_session:
                    add_score(finding, config["score_rules"]["near_roblox_session"], "File timestamp is within 30 minutes of Roblox activity")
                finding["supporting_evidence"].append(
                    f"created={times[0].isoformat(sep=' ', timespec='seconds')} modified={times[1].isoformat(sep=' ', timespec='seconds')} accessed={times[2].isoformat(sep=' ', timespec='seconds')}"
                )
                finding["evidence_types"].append("file_artifact")
                merge_findings(findings, finding)
                timeline.append({"time": finding["first_seen"], "source": "File system", "text": f"Suspicious file artifact: {path_text}"})
    return list(findings.values()), timeline


def make_possible_context_finding(path_text: str, name: str, source: str, reason: str, when: dt.datetime | None, config: dict) -> dict:
    looks_like_path = bool(re.match(r"^[a-z]:[\\/]", str(path_text), re.I) or str(path_text).startswith(("\\\\", "/", "~")) or "\\" in str(path_text) or "/" in str(path_text))
    finding = {
        "name": name or Path(path_text).name or source,
        "path": normalize_path(path_text) if path_text and "://" not in path_text and looks_like_path else path_text,
        "sha256": "",
        "signer": {"status": "not checked", "subject": "", "issuer": ""},
        "parent_process": "",
        "target_process": ROBLOX_EXE,
        "first_seen": when.isoformat(sep=" ", timespec="seconds") if when else "",
        "score": 0,
        "score_breakdown": [],
        "supporting_evidence": [reason],
        "evidence_types": ["possible_context"],
        "detection_categories": [source],
        "detections": [{"category": source, "type": detection_type_for_category(source), "reason": reason, "risk": "Low"}],
        "artifact_source": source.lower().replace(" ", "_"),
        "attribution_explanation": "",
        "classification": "Weak",
    }
    add_score(finding, config["score_rules"]["file_artifact"], f"{source}: possible context only")
    return finding


def collect_shellbag_context(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # ShellBag Analyzer exports can show folders a user browsed. This is indirect context only.
    findings = {}
    timeline = []
    cut = cutoff(days)
    candidates = []
    for root in scan_roots():
        try:
            for path in root.rglob("*"):
                name = path.name.lower()
                if "shellbag" not in name and "shell bag" not in name:
                    continue
                if path.suffix.lower() not in {".txt", ".csv", ".json", ".log"}:
                    continue
                candidates.append(path)
                if len(candidates) >= 40:
                    break
        except OSError:
            continue
    for export in candidates:
        try:
            mtime = dt.datetime.fromtimestamp(export.stat().st_mtime)
            if mtime < cut:
                continue
            text = export.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if not suspicious_text(line, config):
                continue
            reason = f"ShellBag Analyzer export mentions possible exploit path/name: {line[:220]}"
            finding = make_possible_context_finding(str(export), export.name, "ShellBag Analyzer", reason, mtime, config)
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": "ShellBag Analyzer", "text": reason})
            break
    return list(findings.values()), timeline


def collect_recycle_bin_context(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Recycle Bin entries only prove a suspicious name/path may have existed or been deleted.
    findings = {}
    timeline = []
    cut = cutoff(days)
    recycle_roots = [Path(drive + ":\\$Recycle.Bin") for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(drive + ":\\").exists()]
    for root in recycle_roots:
        try:
            entries = list(root.rglob("*"))
        except OSError:
            continue
        for entry in entries[:5000]:
            try:
                mtime = dt.datetime.fromtimestamp(entry.stat().st_mtime)
            except OSError:
                continue
            if mtime < cut:
                continue
            text = str(entry)
            if not suspicious_text(text, config):
                continue
            reason = f"Recycle Bin metadata/path contains possible exploit-related name: {text}"
            finding = make_possible_context_finding(text, entry.name, "Recycle Bin", reason, mtime, config)
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": "Recycle Bin", "text": reason})
    return list(findings.values()), timeline


def parse_recycle_i_record(path: Path) -> dict:
    # Windows $Recycle.Bin $I files store deleted-file metadata. This reads metadata only.
    try:
        data = path.read_bytes()
    except OSError:
        return {}
    original = ""
    deleted_time = ""
    size = ""
    try:
        if len(data) >= 24:
            size = str(int.from_bytes(data[8:16], "little", signed=False))
            filetime = int.from_bytes(data[16:24], "little", signed=False)
            if filetime:
                deleted_dt = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=filetime / 10)
                deleted_time = deleted_dt.isoformat(sep=" ", timespec="seconds")
        text = data[24:].decode("utf-16-le", errors="ignore").strip("\x00\r\n ")
        original = text.split("\x00", 1)[0]
    except Exception:
        pass
    return {"original_path": original, "deleted_time": deleted_time, "size": size, "metadata_file": str(path)}


def collect_recovery_artifacts(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    findings = {}
    timeline = []
    recovered = []
    cut = cutoff(days)
    roots = [Path(f"{letter}:/$Recycle.Bin") for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
    for root in roots:
        if not safe_exists(root):
            continue
        try:
            entries = list(root.rglob("$I*"))[:3000]
        except OSError:
            continue
        for entry in entries:
            try:
                mtime = dt.datetime.fromtimestamp(entry.stat().st_mtime)
            except Exception:
                continue
            if mtime < cut:
                continue
            meta = parse_recycle_i_record(entry)
            original = meta.get("original_path") or str(entry)
            if not suspicious_text(original, config):
                continue
            when = meta.get("deleted_time") or mtime.isoformat(sep=" ", timespec="seconds")
            finding = make_possible_context_finding(
                original,
                Path(original).name or entry.name,
                "Recovered File Metadata",
                "Recycle Bin metadata recovered for a suspicious deleted path. Manual review required.",
                parse_dt(when) or mtime,
                config,
            )
            finding["evidence_types"].append("recovery")
            finding["manual_review_required"] = True
            finding["recovered_metadata"] = meta
            add_detection(finding, "Suspicious File Deletion", "Deleted suspicious file metadata recovered from Recycle Bin", "Medium", 20)
            merge_findings(findings, finding)
            recovered.append({
                "name": finding["name"],
                "path": original,
                "source": "Recycle Bin",
                "timestamp": when,
                "metadata": meta,
                "manualReviewRequired": True,
            })
            timeline.append({"time": when, "source": "Recovery", "text": f"Recovered deleted-file metadata: {original}"})
    return list(findings.values()), timeline, recovered


def collect_warning_logs(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    warnings = []
    findings = {}
    timeline = []
    system = collect_system_info()
    virt_text = json.dumps(system, default=str).lower()
    if any(term in virt_text for term in VIRTUALIZATION_TERMS):
        when = iso_now()
        warning = {
            "detectionName": "Virtualization Check",
            "severity": "Medium",
            "explanation": "Virtualization or sandbox indicator was observed. This can be legitimate, but may reduce confidence in local artifacts.",
            "evidencePath": "System information",
            "timestamp": when,
            "manualReviewRequired": True,
            "confidenceLevel": "medium",
            "type": "Warning",
        }
        warnings.append(warning)
        finding = make_possible_context_finding("System information", "Virtualization Check", "Virtualization Check", warning["explanation"], parse_dt(when), config)
        finding["evidence_types"].append("warning")
        add_detection(finding, "Virtualization Check", warning["explanation"], "Medium", 15)
        merge_findings(findings, finding)
        timeline.append({"time": when, "source": "Warning", "text": warning["explanation"]})

    activities_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "ConnectedDevicesPlatform",
        Path(os.environ.get("LOCALAPPDATA", "")) / "ConnectedDevicesPlatform" / "L.UserActivity",
    ]
    if not any(safe_exists(p) for p in activities_paths):
        when = iso_now()
        warning = {
            "detectionName": "Disabled ActivitiesCache",
            "severity": "Low",
            "explanation": "Windows ActivitiesCache/UserActivity artifacts were not found. This is a coverage limitation, not proof of cheating.",
            "evidencePath": "ConnectedDevicesPlatform ActivitiesCache",
            "timestamp": when,
            "manualReviewRequired": True,
            "confidenceLevel": "low",
            "type": "Warning",
        }
        warnings.append(warning)
        finding = make_possible_context_finding("ConnectedDevicesPlatform ActivitiesCache", "ActivitiesCache", "ActivitiesCache Disabled", warning["explanation"], parse_dt(when), config)
        finding["evidence_types"].append("warning")
        add_detection(finding, "ActivitiesCache Disabled", warning["explanation"], "Low", 10)
        merge_findings(findings, finding)
        timeline.append({"time": when, "source": "Warning", "text": warning["explanation"]})

    if config.get("ruin_mode_enabled"):
        when = iso_now()
        warning = {
            "detectionName": "RUIN Mode Warning",
            "severity": "Medium",
            "explanation": "RUIN Mode is enabled. Game instance modification checks may require the game to close after scanning.",
            "evidencePath": "Configuration",
            "timestamp": when,
            "manualReviewRequired": True,
            "confidenceLevel": "medium",
            "type": "Warning",
        }
        warnings.append(warning)
        finding = make_possible_context_finding("Configuration", "RUIN Mode", "RUIN Mode Warning", warning["explanation"], parse_dt(when), config)
        finding["evidence_types"].append("warning")
        add_detection(finding, "RUIN Mode Warning", warning["explanation"], "Medium", 10)
        merge_findings(findings, finding)
        timeline.append({"time": when, "source": "Warning", "text": warning["explanation"]})
    return list(findings.values()), timeline, warnings


def collect_powershell_history(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # PowerShell history can reveal download-and-execute behavior even when process logs are missing.
    findings = {}
    timeline = []
    base = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    try:
        files = list(base.glob("*history*.txt"))
    except OSError:
        return [], []
    download_terms = re.compile(r"(invoke-webrequest|iwr|wget|curl|start-process|powershell\s+-|bitsadmin|downloadstring|frombase64string|expand-archive)", re.I)
    for hist in files:
        try:
            mtime = dt.datetime.fromtimestamp(hist.stat().st_mtime)
            lines = hist.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if mtime < cutoff(days):
            continue
        for i, line in enumerate(lines, start=1):
            if not download_terms.search(line):
                continue
            name = f"PowerShell history line {i}"
            finding = make_finding(str(hist), name, "powershell_history", config)
            finding["first_seen"] = mtime.isoformat(sep=" ", timespec="seconds")
            add_score(finding, config["score_rules"]["powershell_download_execute"], "PowerShell history contains download/execute pattern")
            if near_any_session(mtime, sessions):
                add_score(finding, config["score_rules"]["near_roblox_session"], "PowerShell history timestamp is within 30 minutes of Roblox activity")
            finding["supporting_evidence"].append(f"{hist}:{i}: {line[:500]}")
            finding["evidence_types"].append("powershell_history")
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": "PowerShell history", "text": f"Suspicious PowerShell command: {line[:160]}"})
    return list(findings.values()), timeline


def collect_defender_history(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Defender Operational logs are best; history folders sometimes retain readable threat/path fragments.
    findings = {}
    timeline = []
    roots = [
        Path("C:/ProgramData/Microsoft/Windows Defender/Scans/History/Service"),
        Path("C:/ProgramData/Microsoft/Windows Defender/Quarantine"),
    ]
    cut = cutoff(days)
    for root in roots:
        if not safe_exists(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames[:500]:
                path = Path(dirpath) / filename
                try:
                    st = path.stat()
                except OSError:
                    continue
                mtime = dt.datetime.fromtimestamp(st.st_mtime)
                if mtime < cut:
                    continue
                text = ""
                try:
                    if st.st_size < 2_000_000:
                        text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                if not suspicious_text(str(path) + " " + text, config):
                    continue
                finding = make_finding(str(path), filename, "defender_history", config)
                finding["first_seen"] = mtime.isoformat(sep=" ", timespec="seconds")
                add_score(finding, config["score_rules"]["defender_detection"], "Defender history contains suspicious Roblox exploit-related text/path")
                if near_any_session(mtime, sessions):
                    add_score(finding, config["score_rules"]["near_roblox_session"], "Defender history timestamp is within 30 minutes of Roblox activity")
                paths = re.findall(r"[A-Za-z]:\\[^\"<>|]{3,260}", text)
                if paths:
                    finding["supporting_evidence"].append("Affected path candidates: " + "; ".join(paths[:5]))
                finding["supporting_evidence"].append(f"Defender history artifact: {path}")
                finding["evidence_types"].append("defender_history")
                merge_findings(findings, finding)
                timeline.append({"time": finding["first_seen"], "source": "Defender history", "text": f"Defender history artifact: {path.name}"})
    return list(findings.values()), timeline


def collect_persistence(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Persistence locations catch loaders that re-run at login or via scheduled tasks/services.
    findings = {}
    timeline = []
    checks = []
    run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    for key in run_keys:
        out = run_command(["reg", "query", key], timeout=15)
        checks.extend(("Registry Run key", key, line) for line in out.splitlines())
    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("ProgramData", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    for folder in startup_dirs:
        try:
            for item in folder.glob("*"):
                checks.append(("Startup folder", str(folder), str(item)))
        except OSError:
            pass
    tasks = run_command(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=35)
    try:
        for row in csv.DictReader(tasks.splitlines()):
            checks.append(("Scheduled task", row.get("TaskName", ""), json.dumps(row)))
    except Exception:
        pass
    services = run_command(["wmic", "service", "get", "Name,PathName,StartMode", "/format:csv"], timeout=25)
    for line in services.splitlines():
        checks.append(("Service", "", line))
    wmi = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer | Select-Object Name,CommandLineTemplate,ExecutablePath,ScriptText | ConvertTo-Csv -NoTypeInformation"], timeout=25)
    for line in wmi.splitlines():
        checks.append(("WMI persistence", "", line))
    for source, location, text in checks:
        if not (suspicious_text(text, config) or user_writable_path(text)):
            continue
        paths = re.findall(r"[A-Za-z]:\\[^\"<>|]+?\.(?:exe|dll|ps1|bat|cmd|vbs|js)", text, re.I)
        path = paths[0] if paths else location
        finding = make_finding(path, source, "persistence", config)
        finding["first_seen"] = dt.datetime.now().isoformat(sep=" ", timespec="seconds")
        add_score(finding, config["score_rules"]["persistence"], f"Suspicious persistence entry: {source}")
        finding["supporting_evidence"].append(text[:800])
        finding["evidence_types"].append("persistence")
        merge_findings(findings, finding)
        timeline.append({"time": finding["first_seen"], "source": source, "text": f"Suspicious persistence entry: {text[:160]}"})
    return list(findings.values()), timeline


def copy_locked_db(path: Path) -> Path | None:
    try:
        if not path.exists():
            return None
        tmp = Path(tempfile.gettempdir()) / f"{APP_NAME}_{os.getpid()}_{path.name}"
        shutil.copy2(path, tmp)
        return tmp
    except OSError:
        return None


def chrome_time_to_datetime(value):
    try:
        if not value:
            return None
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=int(value))
    except Exception:
        return None


def firefox_time_to_datetime(value):
    try:
        if not value:
            return None
        return dt.datetime.fromtimestamp(int(value) / 1_000_000)
    except Exception:
        return None


def collect_browser_downloads(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Browser histories are copied first, then queried read-only, so locked live databases are handled safely.
    findings = {}
    timeline = []
    cut = cutoff(days)
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))
    chrome_dbs = [
        ("Chrome", local / "Google/Chrome/User Data/Default/History"),
        ("Edge", local / "Microsoft/Edge/User Data/Default/History"),
    ]
    for browser, db in chrome_dbs:
        copied = copy_locked_db(db)
        if not copied:
            continue
        try:
            conn = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
            rows = conn.execute("select target_path, tab_url, start_time, received_bytes from downloads order by start_time desc limit 500").fetchall()
            conn.close()
        except Exception:
            rows = []
        for target_path, tab_url, start_time, received_bytes in rows:
            when = chrome_time_to_datetime(start_time)
            text = f"{target_path} {tab_url}"
            if not when or when < cut or not suspicious_text(text, config):
                continue
            finding = make_finding(str(target_path or tab_url), Path(str(target_path or tab_url)).name, "browser_download", config)
            finding["first_seen"] = when.isoformat(sep=" ", timespec="seconds")
            add_score(finding, config["score_rules"]["browser_download"], f"{browser} download history contains suspicious Roblox exploit-related item")
            if near_any_session(when, sessions):
                add_score(finding, config["score_rules"]["near_roblox_session"], "Browser download is within 30 minutes of Roblox activity")
            finding["supporting_evidence"].append(f"{browser} download target={target_path} url={tab_url} bytes={received_bytes}")
            finding["evidence_types"].append("browser_download")
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": f"{browser} downloads", "text": f"Suspicious browser download: {target_path or tab_url}"})
    try:
        firefox_dbs = list((roaming / "Mozilla/Firefox/Profiles").glob("*/places.sqlite"))
    except OSError:
        firefox_dbs = []
    for db in firefox_dbs:
        copied = copy_locked_db(db)
        if not copied:
            continue
        try:
            conn = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
            rows = conn.execute("select url, title, last_visit_date from moz_places order by last_visit_date desc limit 800").fetchall()
            conn.close()
        except Exception:
            rows = []
        for url, title, last_visit_date in rows:
            when = firefox_time_to_datetime(last_visit_date)
            text = f"{url} {title}"
            if not when or when < cut or not suspicious_text(text, config):
                continue
            finding = make_finding(url, title or "Firefox suspicious download/visit", "browser_download", config)
            finding["first_seen"] = when.isoformat(sep=" ", timespec="seconds")
            add_score(finding, config["score_rules"]["browser_download"], "Firefox history contains suspicious Roblox exploit-related URL/title")
            if near_any_session(when, sessions):
                add_score(finding, config["score_rules"]["near_roblox_session"], "Firefox history item is within 30 minutes of Roblox activity")
            finding["supporting_evidence"].append(f"Firefox url={url} title={title}")
            finding["evidence_types"].append("browser_download")
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": "Firefox history", "text": f"Suspicious browser history item: {url}"})
    return list(findings.values()), timeline


def combine_findings(groups: list[list[dict]], config: dict) -> list[dict]:
    combined = {}
    for group in groups:
        for finding in group:
            merge_findings(combined, finding)
    return finalize_findings(list(combined.values()), config)


def finding_event_time(finding: dict):
    return parse_dt(finding.get("first_seen"))


def finding_near_roblox(finding: dict, sessions: list[dict]) -> bool:
    when = finding_event_time(finding)
    return bool(when and near_any_session(when, sessions, minutes=30))


def finding_matches(finding: dict, evidence_types: set[str] | None = None, categories: set[str] | None = None) -> bool:
    types = set(finding.get("evidence_types", []))
    cats = set(finding.get("detection_categories", []))
    return bool((evidence_types and types & evidence_types) or (categories and cats & categories))


def correlation_confidence(score: int, artifact_count: int, critical=False) -> str:
    if critical or score >= 60 or artifact_count >= 5:
        return "Critical"
    if score >= 36 or artifact_count >= 4:
        return "High"
    if score >= 18 or artifact_count >= 2:
        return "Medium"
    return "Low"


def confidence_to_legacy(confidence: str) -> str:
    if confidence == "Critical":
        return "Confirmed"
    if confidence == "High":
        return "Likely"
    return "Possible"


def correlation_timeline(events: list[dict], source_findings: list[dict], sessions: list[dict], limit=8) -> list[dict]:
    source_terms = {str(f.get("name", "")).lower() for f in source_findings if f.get("name")}
    source_terms.update(str(f.get("path", "")).lower() for f in source_findings if f.get("path"))
    source_times = [finding_event_time(f) for f in source_findings if finding_event_time(f)]
    selected = []
    for event in events:
        text = " ".join(str(event.get(k, "")) for k in ["source", "text"]).lower()
        when = parse_dt(event.get("time"))
        matched_text = any(term and term in text for term in source_terms)
        matched_time = when and (near_any_session(when, sessions, minutes=30) or any(abs((when - t).total_seconds()) <= 30 * 60 for t in source_times))
        if matched_text or matched_time:
            selected.append({
                "time": event.get("time", ""),
                "source": event.get("source", ""),
                "text": event.get("text", ""),
            })
    if not selected:
        for f in source_findings:
            if f.get("first_seen"):
                selected.append({"time": f.get("first_seen", ""), "source": f.get("artifact_source", "artifact"), "text": f.get("name") or f.get("path", "")})
    return dedupe_timeline(selected)[:limit]


def make_correlation_finding(name: str, evidence_category: str, score: int, evidence: list[str], source_findings: list[dict], events: list[dict], config: dict, critical=False) -> dict:
    source_findings = [f for f in source_findings if f and not f.get("suppressed") and not securo_internal_path(f.get("path", ""), config)]
    if not source_findings and not evidence:
        return {}
    confidence = correlation_confidence(score, len(evidence), critical=critical)
    first_seen = first_time(*[f.get("first_seen") for f in source_findings], *[e.get("time") for e in events])
    supporting_artifacts = []
    for f in source_findings:
        label = f.get("path") or f.get("name") or f.get("artifact_source", "")
        if label and label not in supporting_artifacts:
            supporting_artifacts.append(label)
    detection = {
        "category": name,
        "type": "Specific",
        "reason": "; ".join(evidence[:4]),
        "risk": "High" if confidence in {"High", "Critical"} else "Medium",
    }
    return {
        "name": name,
        "path": "Forensic artifact correlation",
        "sha256": "",
        "signer": {"status": "not checked", "subject": "", "issuer": ""},
        "parent_process": "",
        "target_process": ROBLOX_EXE,
        "first_seen": first_seen,
        "score": score,
        "score_breakdown": [{"points": score, "reason": f"{name}: evidence-backed artifact correlation"}],
        "supporting_evidence": evidence + supporting_artifacts[:12],
        "supporting_artifacts": supporting_artifacts[:20],
        "evidence_types": ["forensic_correlation", evidence_category],
        "detection_categories": [name],
        "detections": [detection],
        "artifact_source": "forensic_correlation",
        "attribution_explanation": "This finding is based on multiple Windows artifacts lining up in time. It does not rely on a filename, hash, or single keyword by itself.",
        "classification": "Suspicious" if confidence in {"High", "Critical"} else "Indicator Found",
        "confidence_level": confidence_to_legacy(confidence),
        "forensic_confidence": confidence,
        "evidence_category": evidence_category,
        "evidence_score_contribution": score,
        "event_timeline": events,
        "correlation_finding": True,
        "suppressed": False,
        "suppression_reason": "",
    }


def build_forensic_correlation_findings(findings: list[dict], timeline: list[dict], sessions: list[dict], config: dict) -> list[dict]:
    # Correlation findings are scenario-based. They require multiple artifacts to line up, not a single name/string.
    visible = [f for f in findings if not f.get("suppressed") and not securo_internal_path(f.get("path", ""), config)]
    near_session = [f for f in visible if finding_near_roblox(f, sessions)]
    process_exec = [f for f in visible if finding_matches(f, {"process_execution", "prefetch_execution", "powershell_history"})]
    dll_activity = [f for f in visible if finding_matches(f, {"suspicious_module_load", "sysmon_remote_thread", "sysmon_process_access", "ram_indicator"}, {"Suspicious DLL Loading", "RAM Suspicious Indicator"})]
    deleted = [f for f in visible if finding_matches(f, {"recovery", "possible_context"}, {"Recycle Bin", "Recovered File Metadata", "Suspicious File Deletion", "Suspicious DLL Deletion"})]
    archive = [f for f in visible if finding_matches(f, {"archive_artifact", "browser_download"}, {"RAR File Execution"})]
    external = [f for f in visible if finding_matches(f, {"external_device"}, {"External Device Execution"})]
    packed = [f for f in visible if finding_matches(f, {"packed", "dotnet"}, {"UPX Packer", "Generic Packed File", "Suspicious Net File", "DotNetExecutable", "DotNetDLL"})]
    tampered = [f for f in visible if finding_matches(f, {"modified_extension", "bypass_method"}, {"Tampered File", "Modified File Extension", "Generic Bypass Method"})]
    defender = [f for f in visible if finding_matches(f, {"defender_detection", "defender_history"}, {"Windows Defender", "Antivirus Detection"})]

    results = []
    session_exec = [f for f in process_exec if f in near_session]
    session_dll = [f for f in dll_activity if f in near_session or finding_matches(f, {"suspicious_module_load", "sysmon_remote_thread", "sysmon_process_access"})]

    if session_exec and (session_dll or deleted or defender or packed):
        sources = session_exec[:4] + session_dll[:3] + deleted[:2] + defender[:2]
        evidence = ["Executable activity occurred during or near a Roblox session"]
        if session_dll:
            evidence.append("DLL/process-access activity was observed in the same Roblox window")
        if deleted:
            evidence.append("Deletion or recovery metadata exists for related suspicious artifacts")
        if defender:
            evidence.append("Antivirus/Defender telemetry exists near the same activity")
        if packed:
            evidence.append("Packed or obfuscated executable traits were observed")
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("Possible Roblox Exploit Execution", "Roblox exploit execution", 14 + len(evidence) * 8, evidence, sources, events, config))

    if session_dll:
        sources = session_dll[:6]
        categories = set().union(*(set(f.get("evidence_types", [])) for f in sources))
        evidence = ["DLL/process interaction evidence was observed against Roblox or during a Roblox session"]
        if "sysmon_remote_thread" in categories:
            evidence.append("Sysmon remote-thread evidence targeted Roblox")
        if "sysmon_process_access" in categories:
            evidence.append("Sysmon process-access evidence targeted Roblox")
        if "suspicious_module_load" in categories:
            evidence.append("Module-load evidence showed a DLL loaded into Roblox from a risky location")
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("Possible DLL Injection Activity", "DLL injection activity", 18 + len(evidence) * 10, evidence, sources, events, config, critical="sysmon_remote_thread" in categories))

    session_game_mods = [f for f in visible if f in near_session and finding_matches(f, {"ruin_mode"}, {"Game Instance Modification"})]
    if session_game_mods:
        evidence = ["Game instance modification artifact was observed near game activity", "Manual review is required because mods can be legitimate or malicious depending on context"]
        events = correlation_timeline(timeline, session_game_mods, sessions)
        results.append(make_correlation_finding("Possible Game Instance Modification", "game instance modification", 24, evidence, session_game_mods, events, config))

    fastflag_evidence = []
    fastflag_events = []
    for session in sessions:
        lines = session.get("load_client_settings", []) or []
        if lines:
            fastflag_evidence.append(f"Roblox log recorded LoadClientSettings activity for user {session.get('user_id') or 'unknown'}")
            fastflag_events.append({"time": session.get("start_time", ""), "source": "Roblox log", "text": "; ".join(str(x)[:120] for x in lines[:3])})
    client_settings = [f for f in visible if "clientsettings" in (f.get("path", "") + f.get("name", "")).lower() or "fastflag" in " ".join(f.get("supporting_evidence", [])).lower()]
    if fastflag_evidence or client_settings:
        evidence = fastflag_evidence[:3] or ["ClientSettings/FastFlag-related artifact was observed"]
        if client_settings:
            evidence.append("ClientSettings/FastFlag file artifact exists in scanned evidence")
        events = dedupe_timeline(fastflag_events + correlation_timeline(timeline, client_settings, sessions))
        results.append(make_correlation_finding("Possible FastFlag Modifications", "FastFlag modifications", 12 + len(evidence) * 6, evidence, client_settings, events, config))

    users = {(s.get("user_id") or "", (s.get("username") or "Unknown").lower()) for s in sessions if s.get("user_id") or s.get("username")}
    user_ids = {u for u, _ in users if u}
    if len(user_ids) > 1 or len(users) > 1:
        evidence = [f"Multiple Roblox account identities were observed in logs: {len(users)} account entries"]
        events = [{"time": s.get("start_time", ""), "source": "Roblox log", "text": f"Account observed user={s.get('username') or 'Unknown'} id={s.get('user_id') or 'unknown'} place={s.get('place_id') or 'unknown'}"} for s in sessions if s.get("user_id") or s.get("username")]
        results.append(make_correlation_finding("Possible Alternate Roblox Account Usage", "alternate Roblox account usage", 10 + min(len(users), 5) * 4, evidence, [], dedupe_timeline(events), config))

    if session_exec and deleted:
        sources = session_exec[:4] + deleted[:4]
        evidence = ["Execution evidence exists for a suspicious application", "Deletion/recovery metadata exists after or near execution"]
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("Executed-Then-Deleted Application", "executed-then-deleted application", 32, evidence, sources, events, config))

    if archive and session_exec:
        sources = archive[:3] + session_exec[:4]
        evidence = ["Archive/download artifact was observed", "Executable activity occurred during or near the same Roblox session"]
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("Suspicious Archive-To-Execution Chain", "archive-to-execution chain", 28, evidence, sources, events, config))

    if external:
        sources = external[:5]
        evidence = ["Executable or suspicious artifact was observed on an external/removable-drive style path"]
        if any(f in near_session for f in external):
            evidence.append("External-drive artifact timestamp is close to Roblox activity")
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("Suspicious External Drive Execution", "external drive execution", 18 + len(evidence) * 6, evidence, sources, events, config))

    if packed:
        sources = packed[:6]
        evidence = ["Packed/obfuscated executable traits were observed"]
        if any(f in near_session for f in packed):
            evidence.append("Packed artifact timestamp is close to Roblox activity")
        if any(f in process_exec for f in packed):
            evidence.append("Packed artifact also has execution evidence")
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("Packed Or Obfuscated Executable", "packed or obfuscated executable", 16 + len(evidence) * 7, evidence, sources, events, config))

    if tampered:
        sources = tampered[:6]
        evidence = ["File tampering, modified extension, or bypass/integrity indicator was observed"]
        if any(f in near_session for f in tampered):
            evidence.append("Tampering/integrity artifact timestamp is close to Roblox activity")
        events = correlation_timeline(timeline, sources, sessions)
        results.append(make_correlation_finding("File Tampering Or Integrity Violation", "file tampering and integrity violation", 20 + len(evidence) * 8, evidence, sources, events, config))

    return [r for r in results if r]


def correlation_findings_for_report(findings: list[dict]) -> list[dict]:
    rows = []
    for f in findings:
        if not f.get("correlation_finding"):
            continue
        rows.append({
            "name": f.get("name", ""),
            "evidenceCategory": f.get("evidence_category", ""),
            "confidenceLevel": f.get("forensic_confidence", ""),
            "evidenceScoreContribution": f.get("evidence_score_contribution", f.get("score", 0)),
            "supportingArtifacts": f.get("supporting_artifacts", []),
            "supportingEvidence": f.get("supporting_evidence", []),
            "timeline": f.get("event_timeline", []),
        })
    return rows


def engine_assessment(finding: dict, config: dict) -> dict:
    categories = set(finding.get("detection_categories", []))
    score = int(finding.get("score", 0) or 0)
    local_hits = len(categories)
    vt_enabled = bool(config.get("virustotal_api_key"))
    if finding.get("classification") == "Confirmed Exploit":
        detectability = "high"
    elif score >= 50 or categories & GENERIC_DETECTION_CATEGORIES:
        detectability = "medium-high"
    elif score >= 25:
        detectability = "medium"
    else:
        detectability = "low"
    return {
        "file": finding.get("name", ""),
        "path": finding.get("path", ""),
        "sha256": finding.get("sha256", ""),
        "localHeuristicScore": score,
        "localEngineHits": local_hits,
        "detectabilityRange": detectability,
        "virusTotalEnabled": vt_enabled,
        "virusTotalStatus": "configured_not_queried" if vt_enabled else "not_configured",
        "manualReviewRequired": finding.get("classification") not in {"Confirmed Exploit", "Trusted Safe"},
    }


def antivirus_logs_from_findings(findings: list[dict]) -> list[dict]:
    rows = []
    for f in findings:
        if "defender_detection" not in f.get("evidence_types", []) and not any(d.get("type") == "Antivirus" for d in f.get("detections", [])):
            continue
        rows.append({
            "filePath": f.get("path", ""),
            "detectionName": "; ".join(d.get("category", "") for d in f.get("detections", []) if d.get("type") == "Antivirus") or "Antivirus Detection",
            "antivirusSource": f.get("artifact_source", "Windows Defender"),
            "timestamp": f.get("first_seen", ""),
            "severity": "High" if f.get("classification") in {"Confirmed Exploit", "Suspicious"} else "Medium",
            "classification": f.get("classification", "Indicator Found"),
        })
    return rows


def detect_logs_from_report_parts(findings: list[dict], warnings: list[dict], recovered: list[dict], antivirus_logs: list[dict], config: dict) -> list[dict]:
    logs = []
    for f in findings:
        detections = f.get("detections") or [{"category": f.get("classification", "Manual Review"), "type": "Manual Review", "reason": f.get("attribution_explanation", ""), "risk": "Low"}]
        for d in detections:
            log_type = d.get("type") or detection_type_for_category(d.get("category", ""))
            logs.append({
                "type": log_type,
                "detectionName": d.get("category", "Detection"),
                "severity": d.get("risk", "Medium"),
                "explanation": d.get("reason", ""),
                "evidencePath": f.get("path", ""),
                "artifactSource": f.get("artifact_source", ""),
                "timestamp": f.get("first_seen", ""),
                "manualReviewRequired": review_required_for_type(log_type, f.get("classification", "Indicator Found")),
                "confidenceLevel": confidence_from_score(f.get("score", 0), f.get("classification", "Indicator Found")),
                "classification": f.get("classification", "Indicator Found"),
                "score": f.get("score", 0),
                "sha256": f.get("sha256", ""),
                "signer": f.get("signer", {}),
            })
    for warning in warnings:
        logs.append({
            "type": "Warning",
            "detectionName": warning.get("detectionName", "Warning"),
            "severity": warning.get("severity", "Low"),
            "explanation": warning.get("explanation", ""),
            "evidencePath": warning.get("evidencePath", ""),
            "artifactSource": warning.get("evidencePath", ""),
            "timestamp": warning.get("timestamp", ""),
            "manualReviewRequired": True,
            "confidenceLevel": warning.get("confidenceLevel", "low"),
            "classification": "Warning",
            "score": 0,
            "sha256": "",
            "signer": {},
        })
    for item in recovered:
        logs.append({
            "type": "Recovery",
            "detectionName": "Recovered File Metadata",
            "severity": "Medium",
            "explanation": "Deleted-file metadata was recovered. This requires manual review and is not proof of cheating by itself.",
            "evidencePath": item.get("path", ""),
            "artifactSource": item.get("source", ""),
            "timestamp": item.get("timestamp", ""),
            "manualReviewRequired": True,
            "confidenceLevel": "medium",
            "classification": "Recovery",
            "score": 0,
            "sha256": "",
            "signer": {},
        })
    for av in antivirus_logs:
        logs.append({
            "type": "Antivirus",
            "detectionName": av.get("detectionName", "Antivirus Detection"),
            "severity": av.get("severity", "Medium"),
            "explanation": "Antivirus log reported a detection or remediation event.",
            "evidencePath": av.get("filePath", ""),
            "artifactSource": av.get("antivirusSource", ""),
            "timestamp": av.get("timestamp", ""),
            "manualReviewRequired": av.get("classification") != "Confirmed Exploit",
            "confidenceLevel": "medium",
            "classification": av.get("classification", "Indicator Found"),
            "score": 0,
            "sha256": "",
            "signer": {},
        })
    return sorted(logs, key=lambda x: (parse_dt(x.get("timestamp")) or dt.datetime.min), reverse=True)


def determine_overall_category(report: dict) -> str:
    findings = report.get("findings", [])
    quality = report.get("evidence_quality", {})
    if any(f.get("classification") == "Confirmed Exploit" for f in findings):
        return "Confirmed Exploit"
    if any(f.get("classification") == "Suspicious" for f in findings):
        return "Suspicious"
    if any(f.get("classification") == "Indicator Found" for f in findings):
        return "Indicator Found"
    if any(f.get("classification") == "Likely False Positive" for f in findings):
        return "Likely False Positive"
    if any(f.get("classification") == "Trusted Safe" for f in findings):
        return "Trusted Safe"
    available = sum(1 for v in quality.values() if v)
    important = [
        quality.get("Roblox logs available"),
        quality.get("Prefetch available"),
        quality.get("Defender logs available"),
        quality.get("PowerShell history available"),
        quality.get("Sysmon Event ID 8 available"),
        quality.get("Sysmon Event ID 10 available"),
        quality.get("Security 4688 available"),
    ]
    if available < 3 or sum(1 for v in important if v) < 2:
        return "Insufficient data"
    return "Clean-but-limited"


def attach_session_status(sessions: list[dict], findings: list[dict]) -> list[dict]:
    for session in sessions:
        session["status"] = "Clean"
        session["linked_detections"] = []
    for finding in findings:
        first_seen = parse_dt(finding.get("first_seen"))
        if not first_seen:
            continue
        for session in sessions:
            if not near_any_session(first_seen, [session], minutes=30):
                continue
            class_name = finding.get("classification", "Indicator Found")
            if class_name == "Confirmed Exploit":
                session["status"] = "Confirmed Exploit"
            elif session.get("status") != "Confirmed Exploit" and class_name == "Suspicious":
                session["status"] = "Suspicious"
            session["linked_detections"].append({
                "name": finding.get("name", ""),
                "path": finding.get("path", ""),
                "classification": class_name,
                "score": finding.get("score", 0),
                "detections": finding.get("detections", []),
                "detectionCategories": sorted(set(finding.get("detection_categories", []))),
                "sha256": finding.get("sha256", ""),
            })
    return sessions


def confidence_for(overall: str, quality: dict) -> str:
    important_available = sum(
        1
        for key in [
            "Roblox logs available",
            "Prefetch available",
            "Defender logs available",
            "PowerShell history available",
            "Sysmon Event ID 8 available",
            "Sysmon Event ID 10 available",
            "Security 4688 available",
        ]
        if quality.get(key)
    )
    if overall == "Confirmed Exploit":
        return "high"
    if overall == "Suspicious":
        return "medium" if important_available >= 3 else "low"
    if overall == "Indicator Found":
        return "low"
    if overall in {"Clean-but-limited", "Likely False Positive", "Trusted Safe"}:
        return "limited"
    return "insufficient"


def limitations_from_quality(quality: dict) -> list[str]:
    limits = []
    if not quality.get("Sysmon installed"):
        limits.append("Sysmon was not detected, so direct remote-thread, module-load, and process-access telemetry may be unavailable.")
    else:
        for event_id, meaning in [(7, "module load"), (8, "remote thread"), (10, "process access")]:
            if not quality.get(f"Sysmon Event ID {event_id} available"):
                limits.append(f"Sysmon Event ID {event_id} evidence was not available in the scan window, so {meaning} coverage may be incomplete.")
    if not quality.get("Security 4688 available"):
        limits.append("Security Event ID 4688 process creation evidence was not available.")
    if not quality.get("Security 4688 command line available"):
        limits.append("Security 4688 command-line logging was not available, so process arguments may be missing.")
    if not quality.get("Prefetch available"):
        limits.append("Prefetch was not available or accessible.")
    if not quality.get("Defender logs available") and not quality.get("Defender history folders available"):
        limits.append("Defender telemetry was not available or accessible.")
    if not quality.get("Roblox logs available"):
        limits.append("Roblox logs were not found or were not accessible.")
    return limits


def camel_session(session: dict) -> dict:
    return {
        "gameId": session.get("place_id", ""),
        "placeId": session.get("place_id", ""),
        "jobId": session.get("job_id", ""),
        "userId": session.get("user_id", ""),
        "username": session.get("username") or "Unknown",
        "displayName": session.get("display_name") or "",
        "version": session.get("version", ""),
        "launchTime": session.get("start_time", ""),
        "exitTime": session.get("end_time", ""),
        "duration": session.get("duration") or "unknown",
        "status": session.get("status", "Clean"),
        "linkedDetections": session.get("linked_detections", []),
        "logFile": session.get("log_file", ""),
        "loadClientSettings": session.get("load_client_settings", []),
        "errors": session.get("errors", [])[:20],
        "crashes": session.get("crashes", [])[:20],
        "suspiciousLines": session.get("suspicious_lines", [])[:20],
    }


def camel_finding(finding: dict) -> dict:
    return {
        "name": finding.get("name", ""),
        "path": finding.get("path", ""),
        "sha256": finding.get("sha256", ""),
        "score": finding.get("score", 0),
        "category": finding.get("classification", "Indicator Found"),
        "classification": finding.get("classification", "Indicator Found"),
        "confidenceLevel": finding.get("confidence_level", finding_confidence_level(finding)),
        "firstSeen": finding.get("first_seen", ""),
        "artifactSource": finding.get("artifact_source", ""),
        "evidenceTypes": sorted(set(finding.get("evidence_types", []))),
        "detectionCategories": sorted(set(finding.get("detection_categories", []))),
        "detections": finding.get("detections", []),
        "signer": finding.get("signer", {}),
        "parentProcess": finding.get("parent_process", ""),
        "targetProcess": finding.get("target_process", ROBLOX_EXE),
        "scoreBreakdown": finding.get("score_breakdown", []),
        "supportingEvidence": finding.get("supporting_evidence", [])[:30],
        "attributionExplanation": finding.get("attribution_explanation", ""),
        "evidenceCategory": finding.get("evidence_category", ""),
        "forensicConfidence": finding.get("forensic_confidence", ""),
        "evidenceScoreContribution": finding.get("evidence_score_contribution", 0),
        "supportingArtifacts": finding.get("supporting_artifacts", []),
        "eventTimeline": finding.get("event_timeline", []),
        "correlationFinding": bool(finding.get("correlation_finding")),
    }


def build_scan_report(days: int, config: dict, verbose=False) -> dict:
    days = int(config.get("scan_days", days) or days)
    scan_time = iso_now()
    sessions_raw, roblox_timeline = parse_roblox_logs(days, config)
    process_findings, process_timeline = collect_process_evidence(days, config, sessions_raw)
    prefetch_findings, prefetch_timeline = collect_prefetch_evidence(days, config, sessions_raw)
    file_findings, file_timeline = collect_file_artifacts(days, config, sessions_raw, verbose=verbose)
    ps_findings, ps_timeline = collect_powershell_history(days, config, sessions_raw)
    defender_findings, defender_timeline = collect_defender_history(days, config, sessions_raw)
    persistence_findings, persistence_timeline = collect_persistence(days, config, sessions_raw)
    if config.get("skip_browser_artifacts"):
        browser_findings, browser_timeline = [], []
    else:
        browser_findings, browser_timeline = collect_browser_downloads(days, config, sessions_raw)
    shellbag_findings, shellbag_timeline = collect_shellbag_context(days, config, sessions_raw)
    recycle_findings, recycle_timeline = collect_recycle_bin_context(days, config, sessions_raw)
    if config.get("skip_recovery_metadata"):
        recovery_findings, recovery_timeline, recovery_artifacts = [], [], []
    else:
        recovery_findings, recovery_timeline, recovery_artifacts = collect_recovery_artifacts(days, config, sessions_raw)
    warning_findings, warning_timeline, warning_logs = collect_warning_logs(days, config, sessions_raw)
    raw_timeline = (
        roblox_timeline
        + process_timeline
        + prefetch_timeline
        + file_timeline
        + ps_timeline
        + defender_timeline
        + persistence_timeline
        + browser_timeline
        + shellbag_timeline
        + recycle_timeline
        + recovery_timeline
        + warning_timeline
    )
    findings = combine_findings(
        [process_findings, prefetch_findings, file_findings, ps_findings, defender_findings, persistence_findings, browser_findings, shellbag_findings, recycle_findings, recovery_findings, warning_findings],
        config,
    )
    correlation_findings = build_forensic_correlation_findings(findings, raw_timeline, sessions_raw, config)
    if correlation_findings:
        findings = combine_findings([findings, correlation_findings], config)
    antivirus_logs = antivirus_logs_from_findings(findings)
    detect_logs = detect_logs_from_report_parts(findings, warning_logs, recovery_artifacts, antivirus_logs, config)
    engine_results = [engine_assessment(f, config) for f in findings if f.get("path") or f.get("sha256")]
    sessions_raw = attach_session_status(sessions_raw, findings)
    quality = evidence_quality(days)
    timeline = annotate_timeline_confidence(filter_customer_timeline(dedupe_timeline(raw_timeline), config), findings)
    partial = {"findings": findings, "evidence_quality": quality}
    highest_result = determine_overall_category(partial)
    top_score = max([f.get("score", 0) for f in findings], default=0)
    system = collect_system_info()
    system["scan_time"] = scan_time
    limitations = limitations_from_quality(quality)
    if config.get("skip_browser_artifacts"):
        limitations.append("Browser artifacts were skipped by the selected scan profile.")
    if config.get("skip_recovery_metadata"):
        limitations.append("Recovery metadata was skipped by the selected scan profile.")
    report = {
        "scanTime": scan_time,
        "hostname": system.get("hostname", ""),
        "highestResult": highest_result,
        "confidence": confidence_for(highest_result, quality),
        "evidenceSources": quality,
        "timeline": timeline,
        "sessions": [camel_session(s) for s in sessions_raw],
        "findings": [camel_finding(f) for f in findings],
        "detectLogs": detect_logs,
        "correlationFindings": correlation_findings_for_report(findings),
        "warningLogs": warning_logs,
        "recoveryArtifacts": recovery_artifacts,
        "antivirusLogs": antivirus_logs,
        "engineResults": engine_results,
        "limitations": limitations,
        "scanDays": days,
        "scanProfile": config.get("scan_profile", "standard"),
        "scanProfileDescription": config.get("scan_profile_description", ""),
        "topScore": top_score,
        "systemInfo": system,
        "finalStatement": "No confirmed Roblox injection evidence was found in available logs. Logging coverage may not be sufficient to rule it out."
        if highest_result not in ["Confirmed Exploit", "Suspicious"]
        else "Confirmed exploit or suspicious Roblox exploit/injection evidence was found in available artifacts.",
    }
    return report


def emit_progress(progress, stage: str, percent: int | None = None, files_scanned: int | None = None):
    message = stage if percent is None else f"{stage} ({percent}%)"
    try:
        progress(message, stage=stage, percent=percent, files_scanned=files_scanned)
    except TypeError:
        progress(message)


class ScanDiagnostics:
    def __init__(self, config: dict):
        self.config = config
        self.started_at = iso_now()
        self.stage = "queued"
        self.percent = 0
        self.files_scanned = 0
        self.last_successful_operation = "queued"
        self.events: list[dict] = []
        self.errors: list[str] = []

    def progress(self, message: str, stage: str | None = None, percent: int | None = None, files_scanned: int | None = None):
        if stage:
            self.stage = stage
        else:
            self.stage = message
        if percent is not None:
            self.percent = percent
        if files_scanned is not None:
            self.files_scanned = max(self.files_scanned, int(files_scanned or 0))
        self.last_successful_operation = message
        event = {
            "time": iso_now(),
            "stage": self.stage,
            "progressPercent": self.percent,
            "filesScanned": self.files_scanned,
            "message": message,
        }
        self.events.append(event)
        write_app_log(self.config, f"stage={self.stage} progress={self.percent}% files={self.files_scanned} message={message}")

    def fail(self, message: str):
        self.errors.append(message)
        write_app_log(self.config, f"scan diagnostic error: {message}")

    def snapshot(self) -> dict:
        return {
            "startedAt": self.started_at,
            "stage": self.stage,
            "progressPercent": self.percent,
            "filesScanned": self.files_scanned,
            "lastSuccessfulOperation": self.last_successful_operation,
            "events": self.events[-80:],
            "errors": self.errors[-20:],
        }


def diagnostic_report(status: str, reason: str, diagnostics: ScanDiagnostics, config: dict) -> dict:
    scan_time = iso_now()
    system = collect_system_info()
    system["scan_time"] = scan_time
    status_label = "timeout" if status == "timeout" else "failed"
    return {
        "scanTime": scan_time,
        "hostname": system.get("hostname", socket.gethostname()),
        "highestResult": status_label,
        "confidence": "diagnostic",
        "evidenceSources": {"diagnosticReport": True, "partialScan": True},
        "timeline": [
            {
                "time": event.get("time", ""),
                "source": "Scan diagnostics",
                "text": f"{event.get('stage')} - {event.get('message')} ({event.get('progressPercent', 0)}%, files={event.get('filesScanned', 0)})",
                "confidence": "Possible",
            }
            for event in diagnostics.events[-40:]
        ],
        "sessions": [],
        "findings": [],
        "detectLogs": [],
        "correlationFindings": [],
        "warningLogs": [{
            "detectionName": f"Scan {status_label}",
            "severity": "High" if status == "timeout" else "Medium",
            "explanation": reason,
            "evidencePath": "Securo scan diagnostics",
            "timestamp": scan_time,
            "manualReviewRequired": True,
            "confidenceLevel": "medium",
            "type": "Warning",
        }],
        "recoveryArtifacts": [],
        "antivirusLogs": [],
        "engineResults": [],
        "limitations": [
            reason,
            f"Last successful operation: {diagnostics.last_successful_operation}",
            f"Last stage: {diagnostics.stage}",
            f"Files scanned before terminal state: {diagnostics.files_scanned}",
        ],
        "scanDays": int(config.get("scan_days", 7)),
        "scanProfile": config.get("scan_profile", "standard"),
        "scanProfileDescription": config.get("scan_profile_description", ""),
        "topScore": 0,
        "systemInfo": system,
        "scanStatus": status_label,
        "diagnostics": diagnostics.snapshot(),
        "finalStatement": "The scan did not complete normally. A diagnostic report was generated so the PIN/session can reach a terminal state.",
    }


def run_scan_with_timeout(days: int, config: dict, progress, timeout_seconds: int) -> tuple[str, dict]:
    diagnostics = ScanDiagnostics(config)

    def tracked_progress(message: str, stage: str | None = None, percent: int | None = None, files_scanned: int | None = None):
        diagnostics.progress(message, stage=stage, percent=percent, files_scanned=files_scanned)
        try:
            progress(message)
        except TypeError:
            progress(str(message))

    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def scan_target():
        try:
            report = build_scan_report_with_progress(days, config, tracked_progress)
            report["scanStatus"] = "completed"
            report["diagnostics"] = diagnostics.snapshot()
            try:
                result_queue.put_nowait(("completed", report))
            except queue.Full:
                pass
        except Exception as exc:
            diagnostics.fail(str(exc))
            try:
                result_queue.put_nowait(("failed", diagnostic_report("failed", str(exc), diagnostics, config)))
            except queue.Full:
                pass

    diagnostics.progress("Scan started", stage="scanning", percent=0)
    worker = threading.Thread(target=scan_target, daemon=True)
    worker.start()
    try:
        return result_queue.get(timeout=max(1, int(timeout_seconds or 900)))
    except queue.Empty:
        reason = f"Scan exceeded configured timeout of {timeout_seconds} seconds while at stage '{diagnostics.stage}'."
        diagnostics.fail(reason)
        return "timeout", diagnostic_report("timeout", reason, diagnostics, config)


def build_scan_report_with_progress(days: int, config: dict, progress) -> dict:
    days = int(config.get("scan_days", days) or days)
    scan_time = iso_now()
    emit_progress(progress, "Scan started", 0)
    emit_progress(progress, "Collecting Roblox logs", 5)
    sessions_raw, roblox_timeline = parse_roblox_logs(days, config)
    emit_progress(progress, "Checking event logs", 12)
    process_findings, process_timeline = collect_process_evidence(days, config, sessions_raw)
    emit_progress(progress, "Checking Prefetch artifacts", 22)
    prefetch_findings, prefetch_timeline = collect_prefetch_evidence(days, config, sessions_raw)
    emit_progress(progress, "Checking file artifacts", 34)
    file_findings, file_timeline = collect_file_artifacts(days, config, sessions_raw, verbose=False, progress=progress)
    emit_progress(progress, "Checking PowerShell history", 50)
    ps_findings, ps_timeline = collect_powershell_history(days, config, sessions_raw)
    emit_progress(progress, "Checking Defender artifacts", 58)
    defender_findings, defender_timeline = collect_defender_history(days, config, sessions_raw)
    emit_progress(progress, "Checking persistence entries", 66)
    persistence_findings, persistence_timeline = collect_persistence(days, config, sessions_raw)
    emit_progress(progress, "Checking browser artifacts", 74)
    if config.get("skip_browser_artifacts"):
        browser_findings, browser_timeline = [], []
        emit_progress(progress, "Browser artifacts skipped by scan profile", 74)
    else:
        browser_findings, browser_timeline = collect_browser_downloads(days, config, sessions_raw)
    emit_progress(progress, "Checking ShellBag Analyzer context", 80)
    shellbag_findings, shellbag_timeline = collect_shellbag_context(days, config, sessions_raw)
    emit_progress(progress, "Checking Recycle Bin context", 84)
    recycle_findings, recycle_timeline = collect_recycle_bin_context(days, config, sessions_raw)
    emit_progress(progress, "Checking recovery metadata", 88)
    if config.get("skip_recovery_metadata"):
        recovery_findings, recovery_timeline, recovery_artifacts = [], [], []
        emit_progress(progress, "Recovery metadata skipped by scan profile", 88)
    else:
        recovery_findings, recovery_timeline, recovery_artifacts = collect_recovery_artifacts(days, config, sessions_raw)
    emit_progress(progress, "Checking warning indicators", 92)
    warning_findings, warning_timeline, warning_logs = collect_warning_logs(days, config, sessions_raw)
    emit_progress(progress, "Building report", 96)
    raw_timeline = (
        roblox_timeline
        + process_timeline
        + prefetch_timeline
        + file_timeline
        + ps_timeline
        + defender_timeline
        + persistence_timeline
        + browser_timeline
        + shellbag_timeline
        + recycle_timeline
        + recovery_timeline
        + warning_timeline
    )
    findings = combine_findings(
        [process_findings, prefetch_findings, file_findings, ps_findings, defender_findings, persistence_findings, browser_findings, shellbag_findings, recycle_findings, recovery_findings, warning_findings],
        config,
    )
    correlation_findings = build_forensic_correlation_findings(findings, raw_timeline, sessions_raw, config)
    if correlation_findings:
        findings = combine_findings([findings, correlation_findings], config)
    antivirus_logs = antivirus_logs_from_findings(findings)
    detect_logs = detect_logs_from_report_parts(findings, warning_logs, recovery_artifacts, antivirus_logs, config)
    engine_results = [engine_assessment(f, config) for f in findings if f.get("path") or f.get("sha256")]
    sessions_raw = attach_session_status(sessions_raw, findings)
    quality = evidence_quality(days)
    timeline = annotate_timeline_confidence(filter_customer_timeline(dedupe_timeline(raw_timeline), config), findings)
    partial = {"findings": findings, "evidence_quality": quality}
    highest_result = determine_overall_category(partial)
    top_score = max([f.get("score", 0) for f in findings], default=0)
    system = collect_system_info()
    system["scan_time"] = scan_time
    limitations = limitations_from_quality(quality)
    if config.get("skip_browser_artifacts"):
        limitations.append("Browser artifacts were skipped by the selected scan profile.")
    if config.get("skip_recovery_metadata"):
        limitations.append("Recovery metadata was skipped by the selected scan profile.")
    report = {
        "scanTime": scan_time,
        "hostname": system.get("hostname", ""),
        "highestResult": highest_result,
        "confidence": confidence_for(highest_result, quality),
        "evidenceSources": quality,
        "timeline": timeline,
        "sessions": [camel_session(s) for s in sessions_raw],
        "findings": [camel_finding(f) for f in findings],
        "detectLogs": detect_logs,
        "correlationFindings": correlation_findings_for_report(findings),
        "warningLogs": warning_logs,
        "recoveryArtifacts": recovery_artifacts,
        "antivirusLogs": antivirus_logs,
        "engineResults": engine_results,
        "limitations": limitations,
        "scanDays": days,
        "scanProfile": config.get("scan_profile", "standard"),
        "scanProfileDescription": config.get("scan_profile_description", ""),
        "topScore": top_score,
        "systemInfo": system,
        "finalStatement": "No confirmed Roblox injection evidence was found in available logs. Logging coverage may not be sufficient to rule it out."
        if highest_result not in ["Confirmed Exploit", "Suspicious"]
        else "Confirmed exploit or suspicious Roblox exploit/injection evidence was found in available artifacts.",
    }
    emit_progress(progress, "Scan completed", 100)
    return report


def save_local_reports(report: dict, config: dict, html_only=False, json_only=False) -> list[Path]:
    dirs = ensure_storage_dirs(config)
    report_base = dirs["reports"] / f"securo_check_{now_stamp()}"
    written = []
    if not json_only:
        html_path = report_base.with_suffix(".html")
        html_path.write_text(render_html(report), encoding="utf-8")
        written.append(html_path)
    if json_only:
        json_path = report_base.with_suffix(".json")
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        written.append(json_path)
    elif not html_only:
        json_path = report_base.with_suffix(".json")
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        txt_path = report_base.with_suffix(".txt")
        txt_path.write_text(render_txt(report), encoding="utf-8")
        history_path = dirs["history"] / "securo_check_history.sqlite"
        save_sqlite(history_path, report)
        written += [json_path, txt_path, history_path]
    write_app_log(config, f"Saved scan outputs: {', '.join(str(path) for path in written)}")
    return written


def collect_system_info() -> dict:
    info = {
        "scan_time": dt.datetime.now().isoformat(sep=" ", timespec="seconds"),
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "cpu": platform.processor(),
        "ram": "",
        "gpu": "",
        "hardware_uuid": "",
        "virtualization_indicators": [],
    }
    out = run_command(["wmic", "computersystem", "get", "TotalPhysicalMemory,Manufacturer,Model", "/format:csv"], timeout=10)
    info["ram"] = out.strip()
    info["gpu"] = run_command(["wmic", "path", "win32_VideoController", "get", "Name", "/format:list"], timeout=10).strip()
    info["hardware_uuid"] = run_command(["wmic", "csproduct", "get", "UUID", "/format:list"], timeout=10).strip()
    virt_text = (out + info["hardware_uuid"]).lower()
    for term in ["virtualbox", "vmware", "hyper-v", "qemu", "kvm", "xen"]:
        if term in virt_text:
            info["virtualization_indicators"].append(term)
    return info


def dedupe_timeline(events: list[dict]) -> list[dict]:
    seen = set()
    clean = []
    for e in events:
        key = (e.get("time", ""), e.get("source", ""), e.get("text", ""))
        if key in seen or not e.get("time"):
            continue
        seen.add(key)
        clean.append(e)
    return sorted(clean, key=lambda x: x["time"])


def confidence_for_classification(classification: str) -> str:
    if classification == "Confirmed Exploit":
        return "Confirmed"
    if classification == "Suspicious":
        return "Likely"
    return "Possible"


def annotate_timeline_confidence(timeline: list[dict], findings: list[dict]) -> list[dict]:
    enriched = []
    for event in timeline:
        text = " ".join(str(v) for v in event.values()).lower()
        confidence = "Possible"
        for finding in findings:
            name = str(finding.get("name", "")).lower()
            path = str(finding.get("path", "")).lower()
            if (name and name in text) or (path and path in text):
                confidence = finding.get("confidence_level") or confidence_for_classification(finding.get("classification", "Indicator Found"))
                break
        item = dict(event)
        item["confidence"] = confidence
        enriched.append(item)
    return enriched


def save_sqlite(path: Path, report: dict):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("create table if not exists scans (id integer primary key, scan_time text, hostname text, highest_score integer, highest_classification text, json_report text)")
    cur.execute(
        "insert into scans(scan_time, hostname, highest_score, highest_classification, json_report) values (?, ?, ?, ?, ?)",
        (report["scanTime"], report["hostname"], report.get("topScore", 0), report["highestResult"], json.dumps(report)),
    )
    conn.commit()
    conn.close()


def render_txt(report: dict) -> str:
    lines = []
    lines += [APP_NAME, "=" * len(APP_NAME), f"Scan time: {report['scanTime']}", f"Hostname: {report['hostname']}", f"Highest result: {report['highestResult']} ({report.get('topScore', 0)})", f"Confidence: {report['confidence']}", ""]
    primary_session = report["sessions"][0] if report["sessions"] else {}
    lines += [
        "Summary",
        "-------",
        f"User: {primary_session.get('username', 'Unknown')}",
        f"User ID: {primary_session.get('userId', '')}",
        f"Place ID: {primary_session.get('placeId', '')}",
        f"Risk Level: {report['highestResult']}",
        f"Injection Evidence: {report['highestResult'] if report['highestResult'] in ['Confirmed Exploit', 'Suspicious'] else 'Not confirmed'}",
        "",
    ]
    lines += ["Evidence Quality", "----------------"]
    for k, v in report["evidenceSources"].items():
        lines.append(f"{k}: {'yes' if v else 'no'}")
    lines.append("")
    lines += ["Detect Logs", "-----------"]
    if not report.get("detectLogs"):
        lines.append("No detect logs found.")
    for d in report.get("detectLogs", []):
        lines += [
            f"[{d.get('type')}] {d.get('detectionName')} Severity={d.get('severity')} Confidence={d.get('confidenceLevel')}",
            f"  Evidence: {d.get('evidencePath') or d.get('artifactSource')}",
            f"  Time: {d.get('timestamp')}",
            f"  Manual review required: {'yes' if d.get('manualReviewRequired') else 'no'}",
            f"  Explanation: {d.get('explanation')}",
        ]
    lines.append("")
    lines += ["Forensic Correlation Findings", "-----------------------------"]
    if not report.get("correlationFindings"):
        lines.append("No cross-artifact correlation findings were generated.")
    for item in report.get("correlationFindings", []):
        lines += [
            item.get("name", "Correlation Finding"),
            f"Confidence: {item.get('confidenceLevel')}",
            f"Evidence Score: +{item.get('evidenceScoreContribution', 0)}",
            f"Evidence Category: {item.get('evidenceCategory')}",
            "Evidence:",
        ]
        lines += [f"  - {x}" for x in item.get("supportingEvidence", [])[:8]]
        lines += ["Timeline:"]
        for event in item.get("timeline", [])[:8]:
            lines.append(f"  {event.get('time')} {event.get('source')}: {event.get('text')}")
        lines.append("")
    lines += ["Warning Logs", "------------"]
    if not report.get("warningLogs"):
        lines.append("No warning logs found.")
    for w in report.get("warningLogs", []):
        lines.append(f"{w.get('detectionName')} Severity={w.get('severity')} Confidence={w.get('confidenceLevel')} ManualReview={'yes' if w.get('manualReviewRequired') else 'no'} Source={w.get('evidencePath')} Time={w.get('timestamp')}: {w.get('explanation')}")
    lines.append("")
    lines += ["Timeline", "--------"]
    for e in report["timeline"]:
        lines.append(f"{e['time']}  {e['text']}")
    lines.append("")
    lines += ["Roblox Sessions", "---------------"]
    for s in report["sessions"]:
        lines += [
            f"Username: {s['username'] or 'Unknown'}",
            f"Display Name: {s.get('displayName', '')}",
            f"User ID: {s['userId']}",
            f"Place ID: {s['placeId']}",
            f"Job ID: {s['jobId']}",
            f"Session Start Time: {s['launchTime']}",
            f"Session End Time: {s['exitTime']}",
            f"Duration: {s['duration'] or 'unknown'}",
            f"Status: {s.get('status', 'Clean')}",
            f"loadclient settings: {' | '.join(s['loadClientSettings'][:3])}",
            "",
        ]
        for linked in s.get("linkedDetections", []):
            lines += [f"  Detection: {linked.get('name')} {linked.get('classification')} {linked.get('path')}"]
    lines += ["Findings", "--------"]
    if not report["findings"]:
        lines += ["No confirmed Roblox injection evidence was found in available logs.", "Logging coverage may not be sufficient to rule it out.", ""]
    for f in sorted(report["findings"], key=lambda x: x["score"], reverse=True):
        banner = f"\n*** {f['name']} DETECTED! ***" if f["classification"] in ["Confirmed Exploit", "Suspicious"] else ""
        lines += [banner, f"Process: {f['name']}", f"Path: {f['path']}", f"SHA256: {f['sha256']}", f"Signer: {f['signer'].get('status')} {f['signer'].get('subject')}", f"Score: {f['score']}", f"Classification: {f['classification']}", "Score breakdown:"]
        if f.get("detections"):
            lines += ["Detection categories:"]
            for detection in f["detections"]:
                lines.append(f"  - {detection.get('category')}: {detection.get('reason')} Risk={detection.get('risk')}")
        for b in f["scoreBreakdown"]:
            lines.append(f"  {b['points']:+} {b['reason']}")
        lines += ["Supporting evidence:"]
        lines += [f"  - {x}" for x in f["supportingEvidence"]]
        lines += [f"Attribution: {f['attributionExplanation']}", ""]
    lines += ["Recovery Artifacts", "------------------"]
    if not report.get("recoveryArtifacts"):
        lines.append("No recovery metadata found.")
    for item in report.get("recoveryArtifacts", []):
        lines.append(f"{item.get('timestamp')} {item.get('source')}: {item.get('path')} ManualReview={'yes' if item.get('manualReviewRequired') else 'no'}")
    lines.append("")
    lines += ["Antivirus Logs", "--------------"]
    if not report.get("antivirusLogs"):
        lines.append("No antivirus detections found.")
    for item in report.get("antivirusLogs", []):
        lines.append(f"{item.get('timestamp')} {item.get('antivirusSource')} {item.get('severity')} {item.get('detectionName')}: {item.get('filePath')}")
    lines.append("")
    lines += ["Engines", "-------"]
    if not report.get("engineResults"):
        lines.append("No engine heuristic results found.")
    for item in report.get("engineResults", [])[:40]:
        lines.append(f"{item.get('detectabilityRange')} score={item.get('localHeuristicScore')} VT={item.get('virusTotalStatus')} {item.get('path')}")
    lines.append("")
    lines += ["Evidence Limitations", "--------------------"]
    lines += [f"- {x}" for x in report["limitations"]]
    lines += ["", "Final Note", "----------", report["finalStatement"]]
    return "\n".join([x for x in lines if x is not None])


def html_timestamp(value) -> str:
    parsed = parse_dt(value)
    if not parsed:
        return ""
    return parsed.isoformat(timespec="seconds")


def html_data_timestamp(value) -> str:
    stamp = html_timestamp(value)
    return f' data-timestamp="{html.escape(stamp)}"' if stamp else ""


def html_table(rows: list[dict], columns: list[str], timestamp_key: str | None = None) -> str:
    if not rows:
        return "<p class='muted'>None found.</p>"
    head = "".join(f"<th>{html.escape(c)}</th>" for c in columns)
    body = ""
    for r in rows:
        body += f"<tr class='report-entry'{html_data_timestamp(r.get(timestamp_key)) if timestamp_key else ''}>" + "".join(f"<td>{html.escape(str(r.get(c, '')))}</td>" for c in columns) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(report: dict) -> str:
    top_rows = [{
        "Process": f["name"], "Path": f["path"], "Score": f["score"], "Classification": f["classification"],
        "Signer": f["signer"].get("status", ""), "First Seen": f["firstSeen"], "Reason": "; ".join(b["reason"] for b in f["scoreBreakdown"][:3])
    } for f in sorted(report["findings"], key=lambda x: x["score"], reverse=True)[:10]]
    sessions = [{"Username": s["username"], "Display Name": s.get("displayName", ""), "User ID": s["userId"], "Place ID": s["placeId"], "Job ID": s["jobId"], "Duration": s["duration"], "Status": s.get("status", "Clean"), "Timestamp": s.get("launchTime", "")} for s in report["sessions"]]
    detect_rows = [{
        "Type": d.get("type", ""),
        "Detection": d.get("detectionName", ""),
        "Severity": d.get("severity", ""),
        "Confidence": d.get("confidenceLevel", ""),
        "Manual Review": "yes" if d.get("manualReviewRequired") else "no",
        "Evidence": d.get("evidencePath") or d.get("artifactSource", ""),
        "Timestamp": d.get("timestamp", ""),
        "Explanation": d.get("explanation", ""),
    } for d in report.get("detectLogs", [])]
    warning_rows = [{
        "Detection": w.get("detectionName", ""),
        "Severity": w.get("severity", ""),
        "Confidence": w.get("confidenceLevel", ""),
        "Manual Review": "yes" if w.get("manualReviewRequired") else "no",
        "Source": w.get("evidencePath", ""),
        "Timestamp": w.get("timestamp", ""),
        "Explanation": w.get("explanation", ""),
    } for w in report.get("warningLogs", [])]
    recovery_rows = [{
        "Name": r.get("name", ""),
        "Path": r.get("path", ""),
        "Source": r.get("source", ""),
        "Timestamp": r.get("timestamp", ""),
        "Manual Review": "yes" if r.get("manualReviewRequired") else "no",
    } for r in report.get("recoveryArtifacts", [])]
    antivirus_rows = [{
        "Source": a.get("antivirusSource", ""),
        "Detection": a.get("detectionName", ""),
        "Severity": a.get("severity", ""),
        "Timestamp": a.get("timestamp", ""),
        "Path": a.get("filePath", ""),
    } for a in report.get("antivirusLogs", [])]
    engine_rows = [{
        "File": e.get("file", ""),
        "Score": e.get("localHeuristicScore", ""),
        "Local Hits": e.get("localEngineHits", ""),
        "Detectability": e.get("detectabilityRange", ""),
        "VirusTotal": e.get("virusTotalStatus", ""),
        "Manual Review": "yes" if e.get("manualReviewRequired") else "no",
    } for e in report.get("engineResults", [])[:60]]
    correlation_html = ""
    if not report.get("correlationFindings"):
        correlation_html = "<p class='muted'>No cross-artifact correlation findings were generated.</p>"
    for item in report.get("correlationFindings", []):
        confidence = item.get("confidenceLevel", "Low")
        confidence_class = {"Critical": "confirmed", "High": "likely", "Medium": "possible", "Low": "possible"}.get(confidence, "possible")
        evidence = "".join(f"<li>{html.escape(str(x))}</li>" for x in item.get("supportingEvidence", [])[:10])
        artifacts = "".join(f"<li>{html.escape(str(x))}</li>" for x in item.get("supportingArtifacts", [])[:10])
        events = "".join(
            f"<li class='report-entry'{html_data_timestamp(e.get('time'))}><time>{html.escape(str(e.get('time', '')))}</time><span>{html.escape(str(e.get('text', '')))}</span><small>{html.escape(str(e.get('source', '')))}</small></li>"
            for e in item.get("timeline", [])[:8]
        )
        correlation_html += (
            f"<details class='report-entry finding-card confidence-{html.escape(confidence_class)}' open{html_data_timestamp((item.get('timeline') or [{}])[0].get('time'))}>"
            f"<summary>{html.escape(item.get('name', 'Correlation Finding'))} - {html.escape(confidence)} - +{html.escape(str(item.get('evidenceScoreContribution', 0)))} points</summary>"
            f"<p><b>Evidence category:</b> {html.escape(item.get('evidenceCategory', ''))}</p>"
            f"<h4>Evidence</h4><ul>{evidence}</ul>"
            f"<h4>Supporting artifacts</h4><ul>{artifacts or '<li>Timeline/log correlation only</li>'}</ul>"
            f"<h4>Timeline</h4><ul class='timeline'>{events or '<li>No dedicated timeline events.</li>'}</ul>"
            f"</details>"
        )
    primary_session = report["sessions"][0] if report["sessions"] else {}
    timeline = "".join(f"<li class='report-entry confidence-{html.escape(str(e.get('confidence', 'Possible')).lower())}'{html_data_timestamp(e.get('time'))}><time>{html.escape(e['time'])}</time><span>{html.escape(e['text'])}</span><small>{html.escape(e['source'])}</small></li>" for e in report["timeline"])
    quality = "".join(f"<li><span>{html.escape(k)}</span><b class='{str(v).lower()}'>{'yes' if v else 'no'}</b></li>" for k, v in report["evidenceSources"].items())
    grouped = defaultdict(list)
    for f in sorted(report["findings"], key=lambda x: x["score"], reverse=True):
        grouped[f.get("confidenceLevel") or confidence_for_classification(f["classification"])].append(f)
    findings_html = ""
    group_labels = [("Confirmed", "Confirmed Findings"), ("Likely", "Likely Findings"), ("Possible", "Possible Findings")]
    for group, label in group_labels:
        findings_html += f"<h3>{label}</h3>"
        if not grouped[group]:
            findings_html += "<p class='muted'>None.</p>"
            continue
        for f in grouped[group]:
            breakdown = "".join(f"<li>{b['points']:+} {html.escape(b['reason'])}</li>" for b in f["scoreBreakdown"])
            evidence = "".join(f"<li>{html.escape(x)}</li>" for x in f["supportingEvidence"])
            warnings = "".join(
                f"<div class='warn'><h4>{html.escape(d.get('category', 'Detection'))}</h4><p><b>File:</b> {html.escape(f['name'])}</p><p><b>Path:</b> {html.escape(f['path'])}</p><p><b>Detection:</b> {html.escape(d.get('category', ''))}</p><p><b>Reason:</b> {html.escape(d.get('reason', ''))}</p><p><b>Risk:</b> {html.escape(d.get('risk', ''))}</p><p><b>SHA256:</b> {html.escape(f['sha256'])}</p><p><b>Signer:</b> {html.escape(str(f['signer']))}</p><p><b>First seen:</b> {html.escape(f['firstSeen'])}</p></div>"
                for d in f.get("detections", [])
            )
            keep_visible = " data-keep-visible='true'" if group == "Confirmed" else ""
            findings_html += f"<details class='report-entry finding-card confidence-{html.escape(group.lower())}' open{html_data_timestamp(f.get('firstSeen'))}{keep_visible}><summary>{html.escape(f['name'])} - {html.escape(group)} - {f['score']} points</summary>{warnings}<p><b>Path:</b> {html.escape(f['path'])}</p><p><b>SHA256:</b> {html.escape(f['sha256'])}</p><p><b>Signer:</b> {html.escape(str(f['signer']))}</p><h4>Score</h4><ul>{breakdown}</ul><h4>Evidence</h4><ul>{evidence}</ul><p>{html.escape(f['attributionExplanation'])}</p></details>"
    session_cards = "".join(
        f"<div class='session report-entry {html.escape((s.get('status') or 'Clean').lower())}'{html_data_timestamp(s.get('launchTime'))}><h3>{html.escape(s.get('username') or 'Unknown')}</h3><p><b>Display Name:</b> {html.escape(s.get('displayName', ''))}</p><p><b>User ID:</b> {html.escape(s.get('userId', ''))}</p><p><b>Place ID:</b> {html.escape(s.get('placeId', ''))}</p><p><b>Job ID:</b> {html.escape(s.get('jobId', ''))}</p><p><b>Duration:</b> {html.escape(s.get('duration', 'unknown'))}</p><p><b>Status:</b> {html.escape(s.get('status', 'Clean'))}</p>{''.join('<p><b>Detection:</b> ' + html.escape(d.get('name','')) + ' ' + html.escape(d.get('path','')) + '</p>' for d in s.get('linkedDetections', []))}</div>"
        for s in report["sessions"]
    )
    raw = html.escape(json.dumps(report, indent=2))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{APP_NAME} Report</title>
<style>
body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f5f7f9;color:#15191f}}header{{background:#111827;color:white;padding:24px 32px}}main{{max-width:1180px;margin:auto;padding:24px}}section{{background:white;border:1px solid #d8dee6;border-radius:8px;margin:16px 0;padding:18px}}.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card{{border:1px solid #d8dee6;border-radius:8px;padding:14px;background:#fbfcfd}}.value{{font-size:24px;font-weight:700}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{border-bottom:1px solid #e7ebf0;padding:8px;text-align:left;vertical-align:top}}th{{background:#f0f3f6}}.timeline li{{display:grid;grid-template-columns:170px minmax(0,1fr) 130px;gap:12px;padding:8px 10px;border-bottom:1px solid #edf0f3;overflow:hidden}}.timeline span{{min-width:0;overflow-wrap:anywhere;word-break:break-word}}.timeline small{{white-space:nowrap;color:#667085}}.muted{{color:#667085}}.true{{color:#157347}}.false{{color:#b42318}}details{{border:1px solid #d8dee6;border-radius:8px;padding:10px;margin:10px 0}}summary{{font-weight:700;cursor:pointer}}pre{{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e5e7eb;padding:12px;border-radius:8px;max-height:520px;overflow:auto}}.warn{{border:1px solid #dc2626;background:#fee2e2;color:#7f1d1d;border-radius:8px;padding:12px;margin:10px 0}}.sessions{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}}.session{{border:1px solid #d8dee6;border-radius:8px;padding:12px;background:#fbfcfd}}.session.suspicious,.session.confirmed{{border-color:#dc2626;background:#fee2e2;color:#7f1d1d}}.confidence-possible{{border-left:4px solid #9ca3af!important;background:#f9fafb}}.confidence-likely{{border-left:4px solid #f59e0b!important;background:#fffbeb}}.confidence-confirmed{{border-left:4px solid #dc2626!important;background:#fee2e2;color:#7f1d1d}}.filters{{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px}}.pill{{border:1px solid #d8dee6;border-radius:999px;padding:5px 10px;background:#fbfcfd;font-size:12px}}.report-controls{{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}}.report-controls label{{font-weight:700}}.report-controls select{{border:1px solid #cfd6df;border-radius:6px;background:white;padding:8px 10px;font:inherit}}.hidden-by-time{{display:none!important}}
</style></head><body><header><h1>{APP_NAME} Report</h1><p>No confirmed result means only that available logs did not prove it. Logging coverage may be incomplete.</p></header><main>
<section><h2>Summary</h2><div class="summary"><div class="card"><div>Scan Date</div><div class="value">{html.escape(report['scanTime'])}</div></div><div class="card"><div>Highest Result</div><div class="value">{report['highestResult']}</div></div><div class="card"><div>Top Score</div><div class="value">{report.get('topScore', 0)}</div></div><div class="card"><div>Roblox Sessions</div><div class="value">{len(report['sessions'])}</div></div></div></section>
<section><div class="report-controls"><div><h2>Report Time Range</h2><p class="muted">Filter visible saved report entries without rescanning.</p></div><label for="report-time-filter">Show <select id="report-time-filter"><option value="30">1 month</option><option value="14">2 weeks</option><option value="7" selected>1 week</option><option value="3">3 days</option><option value="all">All logs</option></select></label></div></section>
<section><h2>Primary Roblox Account</h2><div class="summary"><div class="card"><div>User</div><div class="value">{html.escape(primary_session.get('username', 'Unknown'))}</div></div><div class="card"><div>User ID</div><div class="value">{html.escape(primary_session.get('userId', ''))}</div></div><div class="card"><div>Place ID</div><div class="value">{html.escape(primary_session.get('placeId', ''))}</div></div><div class="card"><div>Injection Evidence</div><div class="value">{html.escape(report['highestResult'] if report['highestResult'] in ['Confirmed Exploit','Suspicious'] else 'Not confirmed')}</div></div></div></section>
<section><h2>Top Suspicious Processes</h2>{html_table(top_rows, ['Process','Path','Score','Classification','Signer','First Seen','Reason'], 'First Seen')}</section>
<section><h2>Forensic Correlation Findings</h2><p class="muted">These findings are built from multiple artifacts lining up in time, not from a single filename, hash, or keyword.</p>{correlation_html}</section>
<section><h2>Interaction / Detect Logs</h2><div class="filters">{''.join(f"<span class='pill'>{x}</span>" for x in DETECT_LOG_TYPES)}</div>{html_table(detect_rows, ['Type','Detection','Severity','Confidence','Manual Review','Evidence','Timestamp','Explanation'], 'Timestamp')}</section>
<section><h2>Warning Logs</h2><p class="muted">Warnings indicate modifications or behaviors that may reduce confidence or require review. They are not automatically cheating evidence.</p>{html_table(warning_rows, ['Detection','Severity','Confidence','Manual Review','Source','Timestamp','Explanation'], 'Timestamp')}</section>
<section><h2>Recovery</h2>{html_table(recovery_rows, ['Name','Path','Source','Timestamp','Manual Review'], 'Timestamp')}</section>
<section><h2>Antivirus Logs</h2>{html_table(antivirus_rows, ['Source','Detection','Severity','Timestamp','Path'], 'Timestamp')}</section>
<section><h2>Engines</h2>{html_table(engine_rows, ['File','Score','Local Hits','Detectability','VirusTotal','Manual Review'])}</section>
<section><h2>Session Information</h2><div class="sessions">{session_cards}</div>{html_table(sessions, ['Username','Display Name','User ID','Place ID','Job ID','Duration','Status'], 'Timestamp')}</section>
<section><h2>Timeline</h2><ul class="timeline">{timeline or "<p class='muted'>No timeline events found.</p>"}</ul></section>
<section><h2>Findings</h2>{findings_html}</section>
<section><h2>Evidence Limitations</h2><ul>{quality}</ul></section>
<section><h2>Raw Artifacts</h2><pre>{raw}</pre></section>
<script>
(function(){{
  function parseEntryDate(entry) {{
    var value = entry.getAttribute("data-timestamp");
    if (!value) return null;
    var parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return null;
    return parsed;
  }}
  function applyReportTimeFilter() {{
    var select = document.getElementById("report-time-filter");
    if (!select) return;
    var selected = select.value;
    var cutoff = null;
    if (selected !== "all") {{
      cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - Number(selected));
    }}
    document.querySelectorAll(".report-entry").forEach(function(entry) {{
      if (entry.getAttribute("data-keep-visible") === "true") {{
        entry.classList.remove("hidden-by-time");
        return;
      }}
      if (selected === "all") {{
        entry.classList.remove("hidden-by-time");
        return;
      }}
      var stamp = parseEntryDate(entry);
      if (!stamp) {{
        entry.classList.remove("hidden-by-time");
        return;
      }}
      entry.classList.toggle("hidden-by-time", stamp < cutoff);
    }});
  }}
  document.addEventListener("DOMContentLoaded", function() {{
    var select = document.getElementById("report-time-filter");
    if (select) select.addEventListener("change", applyReportTimeFilter);
    applyReportTimeFilter();
  }});
}})();
</script>
</main></body></html>"""


def post_json(url: str, payload: dict, headers: dict | None = None, timeout=15, retries=2) -> tuple[bool, dict | str]:
    body = json.dumps(payload).encode("utf-8")
    final_headers = {"Content-Type": "application/json"}
    if headers:
        final_headers.update(headers)
    last_error = ""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=final_headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                try:
                    return True, json.loads(text)
                except json.JSONDecodeError:
                    return False, f"Server returned non-JSON response: {text[:200]}"
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}: {text[:200]}"
        except Exception as exc:
            last_error = str(exc)
    return False, last_error


def verify_pin(api_base_url: str, pin: str) -> tuple[bool, dict | str]:
    url = api_base_url.rstrip("/") + "/api/connect-pin"
    ok, data = post_json(url, {"pin": pin}, timeout=12, retries=2)
    if not ok:
        return False, data
    if not isinstance(data, dict) or not data.get("ok"):
        return False, data.get("error", "invalid_or_expired_pin") if isinstance(data, dict) else "bad_server_response"
    if not data.get("pinId"):
        return False, "bad_server_response"
    return True, {"sessionId": data["pinId"], "uploadToken": pin, "scanProfile": normalize_scan_profile(data.get("scanProfile") or data.get("scan_profile"))}


def upload_report(api_base_url: str, session_id: str, upload_token: str, report: dict) -> tuple[bool, str]:
    url = api_base_url.rstrip("/") + "/api/upload-report"
    payload = {
        "pin": upload_token,
        "hostname": report.get("hostname", ""),
        "riskLevel": report.get("highestResult", ""),
        "evidenceScore": int(report.get("topScore", 0) or 0),
        "reportData": report,
    }
    ok, data = post_json(url, payload, timeout=20, retries=2)
    if ok and isinstance(data, dict) and data.get("ok"):
        return True, "ok"
    if ok:
        return False, json.dumps(data)[:300]
    return False, str(data)


def update_scan_status(api_base_url: str, pin: str, status: str, diagnostics: dict | None = None) -> tuple[bool, str]:
    url = api_base_url.rstrip("/") + "/api/scan-status"
    payload = {"pin": pin, "status": status, "diagnostics": diagnostics or {}}
    ok, data = post_json(url, payload, timeout=3, retries=0)
    if ok and isinstance(data, dict) and data.get("ok"):
        return True, "ok"
    if ok:
        return False, json.dumps(data)[:300]
    return False, str(data)


def parse_args():
    p = argparse.ArgumentParser(description="Read-only Roblox-focused PC evidence checker")
    p.add_argument("--cli", action="store_true", help="Run the old command-line flow")
    p.add_argument("--days", type=int, default=None, help="Number of recent days to scan")
    p.add_argument("--api-base-url", default=None, help="Securo website URL for PIN verification and upload")
    p.add_argument("--pin", default=None, help="PIN from the checker website")
    p.add_argument("--local-only", action="store_true", help="Do not verify PIN or upload; create local reports only")
    p.add_argument("--html-only", action="store_true", help="Only write HTML report")
    p.add_argument("--json-only", action="store_true", help="Only write JSON report")
    p.add_argument("--portable", action="store_true", help="Legacy flag; reports still save to the configured Securo storage folder")
    p.add_argument("--no-color", action="store_true", help="Disable color output")
    p.add_argument("--verbose", action="store_true", help="Print extra progress")
    p.add_argument("--yes", action="store_true", help="Skip interactive consent prompt")
    return p.parse_args()


class SecuroApp:
    def __init__(self, root, config: dict, api_base_url: str, days: int):
        self.root = root
        self.config = config
        self.api_base_url = api_base_url
        self.days = days
        self.session_id = ""
        self.upload_token = ""
        self.running = False
        self.last_status_message = ""
        self.last_status_time = dt.datetime.min
        self.drag_x = 0
        self.drag_y = 0
        self.storage_dirs = ensure_storage_dirs(config)

        root.title("Securo")
        root.geometry("600x400")
        root.resizable(False, False)
        root.configure(bg="#0A0A0A")
        try:
            root.overrideredirect(True)
        except Exception:
            pass

        self.window = tk.Frame(root, bg="#0A0A0A", highlightbackground="#1F2937", highlightthickness=1)
        self.window.pack(fill="both", expand=True)

        self.titlebar = tk.Frame(self.window, bg="#0A0A0A", height=36)
        self.titlebar.pack(fill="x")
        self.titlebar.bind("<ButtonPress-1>", self.start_move)
        self.titlebar.bind("<B1-Motion>", self.do_move)

        tk.Label(self.titlebar, text="Securo", bg="#0A0A0A", fg="#FFFFFF", font=("Segoe UI", 10, "bold")).pack(side="left", padx=14)
        tk.Button(
            self.titlebar,
            text="x",
            command=root.destroy,
            bg="#0A0A0A",
            fg="#A1A1AA",
            activebackground="#161616",
            activeforeground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 12, "bold"),
            width=4,
            cursor="hand2",
        ).pack(side="right")

        self.card = tk.Frame(self.window, bg="#111111", padx=30, pady=20)
        self.card.place(relx=0.5, rely=0.54, anchor="center", width=520, height=330)

        self.logo = tk.Canvas(self.card, width=64, height=64, bg="#111111", highlightthickness=0)
        self.logo.create_oval(6, 6, 58, 58, outline="#00D26A", width=3)
        self.logo.create_text(32, 32, text="S", fill="#00D26A", font=("Segoe UI", 28, "bold"))
        self.logo.pack(pady=(0, 8))

        tk.Label(self.card, text="Securo", bg="#111111", fg="#FFFFFF", font=("Segoe UI", 24, "bold")).pack()
        tk.Label(self.card, text="Enter your check PIN", bg="#111111", fg="#A1A1AA", font=("Segoe UI", 11)).pack(pady=(2, 12))

        self.pin_var = tk.StringVar()
        self.pin_wrap = tk.Frame(self.card, bg="#0A0A0A", highlightbackground="#252525", highlightcolor="#00D26A", highlightthickness=1)
        self.pin_wrap.pack()
        self.pin_entry = tk.Entry(
            self.pin_wrap,
            textvariable=self.pin_var,
            justify="center",
            bg="#0A0A0A",
            fg="#FFFFFF",
            insertbackground="#00D26A",
            relief="flat",
            font=("Segoe UI", 22, "bold"),
            width=12,
            bd=0,
        )
        self.pin_entry.pack(ipady=8, padx=12, pady=2)
        self.pin_entry.focus_set()

        self.start_button = tk.Button(
            self.card,
            text="Start Scan",
            command=self.start_scan,
            bg="#00D26A",
            fg="#061108",
            activebackground="#19E27C",
            activeforeground="#061108",
            relief="flat",
            font=("Segoe UI", 12, "bold"),
            cursor="hand2",
            width=22,
            height=2,
            bd=0,
        )
        self.start_button.pack(pady=(16, 12))

        folder_buttons = tk.Frame(self.card, bg="#111111")
        folder_buttons.pack(fill="x", pady=(0, 8))
        tk.Button(
            folder_buttons,
            text="Open Reports",
            command=lambda: open_folder(self.storage_dirs["reports"]),
            bg="#1F2937",
            fg="#FFFFFF",
            activebackground="#263244",
            activeforeground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            padx=12,
            pady=5,
        ).pack(side="left", expand=True, fill="x", padx=(0, 6))
        tk.Button(
            folder_buttons,
            text="Open History",
            command=lambda: open_folder(self.storage_dirs["history"]),
            bg="#1F2937",
            fg="#FFFFFF",
            activebackground="#263244",
            activeforeground="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            padx=12,
            pady=5,
        ).pack(side="left", expand=True, fill="x", padx=(6, 0))

        self.status = tk.Text(
            self.card,
            height=4,
            bg="#0A0A0A",
            fg="#D4D4D8",
            relief="flat",
            font=("Segoe UI", 9),
            wrap="word",
            bd=0,
            padx=10,
            pady=8,
        )
        self.status.pack(fill="both", expand=True)
        self.status.configure(state="disabled")

        self.details_visible = False
        self.details = tk.Label(
            self.card,
            text=f"API: {self.api_base_url or 'not configured'}\nStorage: {self.storage_dirs['root']}",
            bg="#111111",
            fg="#71717A",
            font=("Segoe UI", 8),
        )
        self.details_link = tk.Label(self.card, text="Advanced", bg="#111111", fg="#00D26A", font=("Segoe UI", 8, "underline"), cursor="hand2")
        self.details_link.bind("<Button-1>", self.toggle_details)
        self.details_link.pack(anchor="e", pady=(6, 0))

        self.close_button = tk.Button(
            self.card,
            text="Close",
            command=root.destroy,
            bg="#1F2937",
            fg="#FFFFFF",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=18,
            pady=7,
        )

    def start_move(self, event):
        self.drag_x = event.x
        self.drag_y = event.y

    def do_move(self, event):
        x = self.root.winfo_x() + event.x - self.drag_x
        y = self.root.winfo_y() + event.y - self.drag_y
        self.root.geometry(f"+{x}+{y}")

    def toggle_details(self, _event=None):
        if self.details_visible:
            self.details.pack_forget()
            self.details_visible = False
        else:
            self.details.pack(anchor="e")
            self.details_visible = True

    def log(self, message: str):
        now = dt.datetime.now()
        if message == self.last_status_message and (now - self.last_status_time).total_seconds() < 0.5:
            return
        self.last_status_message = message
        self.last_status_time = now
        self.safe_after(self._append_status, message)

    def safe_after(self, callback, *args):
        try:
            if self.root.winfo_exists():
                self.root.after(0, callback, *args)
        except Exception:
            pass

    def _append_status(self, message: str):
        if not self.status.winfo_exists():
            return
        self.status.configure(state="normal")
        self.status.insert("end", message + "\n")
        self.status.see("end")
        self.status.configure(state="disabled")

    def set_busy(self, busy: bool):
        def apply():
            if not self.start_button.winfo_exists() or not self.pin_entry.winfo_exists():
                return
            self.start_button.configure(state="disabled" if busy else "normal")
            self.pin_entry.configure(state="disabled" if busy else "normal")

        self.safe_after(apply)

    def start_scan(self):
        if self.running:
            return
        pin = self.pin_var.get().strip()
        if not re.fullmatch(r"\d{6}", pin):
            messagebox.showerror("Securo", "Enter a valid 6-digit PIN.")
            return
        if not self.api_base_url:
            messagebox.showerror("Securo", "Missing api_base_url in config.json.")
            return
        self.running = True
        self.start_button.configure(state="disabled")
        self.pin_entry.configure(state="disabled")
        self.set_busy(True)
        threading.Thread(target=self.worker, args=(pin,), daemon=True).start()

    def worker(self, pin: str):
        try:
            write_app_log(self.config, "Scan started from GUI")
            self.log("Calling POST /api/connect-pin...")
            verified, verify_result = verify_pin(self.api_base_url, pin)
            if not verified:
                self.log(f"Invalid or expired PIN: {verify_result}")
                self.running = False
                self.set_busy(False)
                return

            self.log("PIN verified")
            self.session_id = verify_result["sessionId"]
            self.upload_token = verify_result["uploadToken"]
            self.config = apply_scan_profile(self.config, verify_result.get("scanProfile", "standard"))
            self.days = int(self.config.get("scan_days", self.days) or self.days)
            self.storage_dirs = ensure_storage_dirs(self.config)
            self.log(f"Scan method: {self.config.get('scan_profile', 'standard').title()}")
            update_scan_status(self.api_base_url, pin, "scanning", {
                "stage": f"PIN verified ({self.config.get('scan_profile', 'standard')} scan)",
                "scanProfile": self.config.get("scan_profile", "standard"),
            })

            timeout_seconds = int(self.config.get("scan_timeout_seconds", 900) or 900)
            last_ping = {"time": 0.0, "percent": -1, "stage": ""}

            def gui_progress(message: str):
                self.log(message)
                now = time.monotonic()
                stage = message.split(" (", 1)[0]
                percent_match = re.search(r"\((\d+)%\)", message)
                files_match = re.search(r"files scanned=(\d+)", message)
                percent = int(percent_match.group(1)) if percent_match else last_ping["percent"]
                files_scanned = int(files_match.group(1)) if files_match else 0
                if stage != last_ping["stage"] or percent != last_ping["percent"] or now - last_ping["time"] >= 10:
                    last_ping.update({"time": now, "percent": percent, "stage": stage})
                    update_scan_status(self.api_base_url, pin, "scanning", {
                        "stage": stage,
                        "progressPercent": max(percent, 0),
                        "filesScanned": files_scanned,
                        "lastSuccessfulOperation": message,
                    })

            scan_status, report = run_scan_with_timeout(self.days, self.config, gui_progress, timeout_seconds)
            written = save_local_reports(report, self.config)
            for path in written:
                self.log(f"Saved: {path}")

            self.log("Calling POST /api/upload-report...")
            uploaded, upload_message = upload_report(self.api_base_url, self.session_id, self.upload_token, report)
            if uploaded:
                if scan_status in {"failed", "timeout"}:
                    update_scan_status(self.api_base_url, pin, scan_status, report.get("diagnostics", {}))
                    self.log(f"Diagnostic report uploaded; scan marked {scan_status}")
                    write_app_log(self.config, f"Diagnostic report uploaded; scan marked {scan_status}")
                else:
                    update_scan_status(self.api_base_url, pin, "completed", report.get("diagnostics", {}))
                    self.log("Report uploaded successfully")
                    write_app_log(self.config, "Report uploaded successfully")
                self.safe_after(self.show_close)
            else:
                self.log(f"Upload failed: {upload_message}")
                write_app_log(self.config, f"Upload failed: {upload_message}")
                update_scan_status(self.api_base_url, pin, scan_status if scan_status in {"failed", "timeout"} else "failed", {"uploadError": upload_message, **(report.get("diagnostics", {}) if isinstance(report, dict) else {})})
                self.running = False
                self.set_busy(False)
        except Exception as exc:
            self.log(f"Error: {exc}")
            write_app_log(self.config, f"Error: {exc}")
            update_scan_status(self.api_base_url, pin, "failed", {"error": str(exc)})
            self.running = False
            self.set_busy(False)

    def show_close(self):
        self.running = False
        self.close_button.pack(pady=(10, 0))


def gui_main(args=None):
    init_tk()
    config = load_config()
    days = (args.days if args else None) or int(config.get("scan_days", 7))
    api_base_url = (args.api_base_url if args else None) or os.environ.get("SECURO_API_BASE_URL") or config.get("api_base_url") or DEFAULT_API_BASE_URL
    root = tk.Tk()
    SecuroApp(root, config, api_base_url, days)
    root.mainloop()
    return 0


def cli_main(args):
    config = load_config()
    days = args.days or int(config.get("scan_days", 7))
    api_base_url = args.api_base_url or os.environ.get("SECURO_API_BASE_URL") or config.get("api_base_url") or DEFAULT_API_BASE_URL
    session_id = ""
    upload_token = ""
    website_mode = bool(api_base_url and not args.local_only)
    if not args.yes:
        print("This tool performs read-only Roblox-focused local log checks.")
        print("It does not delete files, upload data, collect credentials, or read Roblox memory.")
        consent = input("Type YES to start scanning: ").strip()
        if consent != "YES":
            print("Scan cancelled.")
            return 2
    if website_mode:
        pin = args.pin or input("Enter the website PIN: ").strip()
        print("PIN verification started")
        verified, verify_result = verify_pin(api_base_url, pin)
        if not verified:
            print(f"PIN verification failed: {verify_result}")
            print("Scan stopped. No scan was run and nothing was uploaded.")
            return 3
        print("PIN verified")
        session_id = verify_result["sessionId"]
        upload_token = verify_result["uploadToken"]
        config = apply_scan_profile(config, verify_result.get("scanProfile", "standard"))
        days = int(config.get("scan_days", days) or days)
        print(f"Scan method: {config.get('scan_profile', 'standard')}")
    elif not args.local_only:
        print("No API base URL configured. Running local-only scan.")
    if args.verbose:
        print("Collecting system info, Roblox logs, event logs, Prefetch, files, Defender, persistence, PowerShell, and browser artifacts...")
    print("scan started")
    write_app_log(config, "Scan started from CLI")
    report = build_scan_report(days, config, verbose=args.verbose)
    print("scan completed")
    written = save_local_reports(report, config, html_only=args.html_only, json_only=args.json_only)
    print("Scan complete.")
    for path in written:
        print(f"Wrote: {path}")
    if website_mode:
        consent = input("This will upload the scan report to the checker's website. Continue? Type YES: ").strip()
        if consent == "YES":
            print("upload started")
            uploaded, upload_message = upload_report(api_base_url, session_id, upload_token, report)
            if uploaded:
                print("upload completed")
            else:
                print(f"upload failed: {upload_message}")
                print("Local report was kept.")
        else:
            print("Upload cancelled by user. Local report was kept.")
    return 0


def main():
    args = parse_args()
    if args.cli:
        return cli_main(args)
    return gui_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
