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
    "Confirmed FastFlag Injector",
    "Confirmed Executor Artifact",
    "Confirmed Prefetch Exploit",
    "Confirmed IOC",
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
    "Suspicious File Deletion/Execution/Modification",
}
SPECIFIC_DETECTION_CATEGORIES = {
    "Possible Roblox Exploit Execution",
    "Possible Game Instance Modification",
    "Possible DLL Injection Activity",
    "Possible FastFlag Modifications",
    "Possible Alternate Roblox Account Usage",
    "Executed-Then-Deleted Application",
    "Executed & Modified",
    "Executed & Deleted",
    "Suspicious Archive-To-Execution Chain",
    "Suspicious External Drive Execution",
    "Packed Or Obfuscated Executable",
    "File Tampering Or Integrity Violation",
    "Generic Bypass Method",
    "Known-Bad Network IOC",
    "Suspicious Persistence IOC",
    "Tampered File",
    "Generic Bypass Method (NVIDIA / Powershell execution log)",
    "Suspicious DLL Deletion",
    "Suspicious File Deletion",
    "Suspicious File Modification",
    "Suspicious File Execution",
    "File Deletion",
    "PREFETCH",
    "Prefetch Execution",
    "USN Journal Event",
    "Deleted Prefetch File",
    "Prefetch Deleted",
    "Duplicate Prefetch Behavior",
    "Impossible Prefetch Behavior",
    "Impossible File Deletion/Execution/Modification",
    "Network File Execution",
    "Generic Bypass Method (Network File)",
    "External Device Execution",
    "Generic Bypass Method (External Device Execution)",
    "External Device Deletion",
    "RAR File Execution",
    "RAM Suspicious Indicator",
    "Game Instance Modification",
    "ActivitiesCache Disabled",
    "Executor Keyword Match",
    "FastFlag Injector",
    "Executor Bundle Artifact",
    "Network Lag Tool / WinDivert Manipulation",
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
    "fastflag",
    "fflag",
    "dfflag",
    "dfint",
    "flog",
    "clientappsettings",
    "clumsy",
    "windivert",
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
    "OpenAI",
    "Codex",
    "Medal",
    "Medal.tv",
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
    "\\medal\\",
    "\\medal.tv\\",
    "\\overwolf\\",
)
DEVELOPER_TOOL_PATH_MARKERS = (
    "\\documents\\codex\\",
    "\\.codex\\",
    "\\.cache\\codex-runtimes\\",
    "\\codex-primary-runtime\\",
    "\\openai\\codex\\",
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
    config.setdefault("prefetch_dir", "C:/Windows/Prefetch")
    config.setdefault("recycle_bin_roots", [])
    config.setdefault("jump_list_roots", [])
    config.setdefault("amcache_path", "C:/Windows/AppCompat/Programs/Amcache.hve")
    config.setdefault("forensic_export_dirs", [])
    config.setdefault("forensic_export_max_files", 80)
    config.setdefault("forensic_export_max_rows", 5000)
    config.setdefault("prefetch_parser_enabled", True)
    config.setdefault("prefetch_parser_timeout_seconds", 25)
    config.setdefault("shellbag_parser_enabled", True)
    config.setdefault("shellbag_parser_timeout_seconds", 30)
    config.setdefault("registry_parser_enabled", True)
    config.setdefault("registry_parser_timeout_seconds", 45)
    config.setdefault("eventlog_parser_enabled", True)
    config.setdefault("eventlog_parser_timeout_seconds", 45)
    config.setdefault("shortcut_parser_enabled", True)
    config.setdefault("shortcut_parser_timeout_seconds", 30)
    config.setdefault("recycle_parser_enabled", True)
    config.setdefault("recycle_parser_timeout_seconds", 30)
    config.setdefault("timeline_parser_enabled", True)
    config.setdefault("timeline_parser_timeout_seconds", 35)
    config.setdefault("shellbag_max_records", 5000)
    config.setdefault("usn_journal_enabled", True)
    config.setdefault("usn_journal_max_records", 5000)
    config.setdefault("usn_journal_window_bytes", 4_000_000)
    config.setdefault("usn_journal_timeout_seconds", 12)
    config.setdefault("external_forensic_tools_enabled", False)
    config.setdefault("external_forensic_tools_dir", "")
    config.setdefault("external_forensic_tool_timeout_seconds", 55)
    config.setdefault("collect_safe_account_identifiers", True)
    config.setdefault("account_log_max_files", 600)
    config.setdefault("account_log_max_bytes", 4_000_000)
    config.setdefault("account_log_total_bytes", 32_000_000)
    config.setdefault("account_scan_time_budget_seconds", 12)
    config.setdefault("collect_system_reset_evidence", True)
    config.setdefault("ioc_file", "securo_iocs.json")
    config.setdefault("iocs", load_iocs(config.get("ioc_file", "securo_iocs.json")))
    return config


def load_iocs(filename: str | None = None) -> dict:
    ioc_file = str(filename or "securo_iocs.json").strip() or "securo_iocs.json"
    candidates = []
    configured = Path(os.path.expandvars(ioc_file)).expanduser()
    if configured.is_absolute():
        candidates.append(configured)
    else:
        candidates.extend([app_dir() / configured, resource_path(str(configured))])
    for path in candidates:
        try:
            if path.exists():
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                return normalize_iocs(data)
        except Exception:
            continue
    return normalize_iocs({})


def scan_transparency_metadata() -> dict:
    return {
        "readOnly": True,
        "automaticFileUpload": False,
        "automaticFileDeletion": False,
        "automaticQuarantine": False,
        "credentialCollection": False,
        "privateMessageCollection": False,
        "scannedScope": [
            "Running process metadata, process names, paths, parent process IDs, and command lines when available",
            "Startup folders, Run registry keys, scheduled tasks, services, and WMI persistence metadata",
            "Downloads, Desktop, Documents, AppData, Temp, ProgramData, and Roblox-related folders",
            "Prefetch, deleted-file metadata, Jump Lists, Amcache string context, Windows Security/Sysmon event logs when available, Defender artifacts, browser download metadata, ShellBag context, and Recycle Bin metadata",
            "A bounded recent slice of the NTFS USN Change Journal for file create, delete, rename, and modification metadata",
            "Optional forensic parser CSV exports from PECmd, MFTECmd, SBECmd, JLECmd, SrumECmd, AmcacheParser, and AppCompatCacheParser when placed in the configured Securo ToolOutput folders",
            "Roblox logs including user ID, username, display name when available, place ID/game ID, job ID, session time, duration, LoadClientSettings lines, and FastFlags",
            "Roblox account identifier context from retained Roblox logs and registry artifacts",
            "Windows install/reset context such as install date, setup logs, recovery folders, and setup event-log entries",
            "Suspicious executable/script metadata including SHA-256, Authenticode signer status, timestamps, and file path",
            "Optional IOC matches loaded from the local Securo IOC JSON file",
        ],
        "notCollected": [
            "Passwords",
            "Browser cookies",
            "Authentication tokens",
            "Discord tokens or private Discord data",
            "Private messages",
            "Raw private documents unrelated to suspicious artifacts",
        ],
    }


def normalize_iocs(data: dict) -> dict:
    data = data if isinstance(data, dict) else {}
    aliases = {
        "filenames": ("filenames", "file_names", "files"),
        "folder_names": ("folder_names", "folders", "directories"),
        "hashes": ("hashes", "sha256", "sha256s"),
        "publisher_names": ("publisher_names", "publishers", "signers"),
        "registry_keys": ("registry_keys", "registry"),
        "mutexes": ("mutexes",),
        "domains": ("domains",),
        "ips": ("ips", "ip_addresses"),
    }
    normalized = {}
    for key, names in aliases.items():
        values = []
        for name in names:
            raw = data.get(name, [])
            if isinstance(raw, str):
                values.append(raw)
            elif isinstance(raw, list):
                values.extend(str(item) for item in raw if str(item).strip())
        normalized[key] = sorted({value.strip() for value in values if value.strip()})
    return normalized


def ioc_values(config: dict, key: str) -> list[str]:
    iocs = config.get("iocs") or {}
    values = iocs.get(key, [])
    return values if isinstance(values, list) else []


def ioc_text_matches(text: str, config: dict) -> list[tuple[str, str]]:
    low = (text or "").lower()
    matches = []
    for key in ("filenames", "folder_names", "registry_keys", "mutexes", "domains", "ips"):
        for value in ioc_values(config, key):
            needle = str(value).strip().lower()
            if needle and needle in low:
                matches.append((key, value))
    return matches


def apply_ioc_matches(finding: dict, config: dict, extra_text: str = ""):
    if finding.get("suppressed"):
        return
    digest = (finding.get("sha256") or "").lower()
    known_hashes = {str(value).lower() for value in ioc_values(config, "hashes")}
    if digest and digest in known_hashes:
        add_detection(finding, "Confirmed IOC", "SHA-256 matched an external IOC entry.", "High Risk", 70)
        finding.setdefault("evidence_types", []).append("ioc_hash")
    signer_text = " ".join(str(finding.get("signer", {}).get(field, "")) for field in ("subject", "issuer"))
    for publisher in ioc_values(config, "publisher_names"):
        if publisher.lower() in signer_text.lower():
            add_detection(finding, "Confirmed IOC", f"Publisher/signer matched IOC: {publisher}", "High Risk", 55)
            finding.setdefault("evidence_types", []).append("ioc_publisher")
    text = " ".join([finding.get("name", ""), finding.get("path", ""), extra_text] + finding.get("supporting_evidence", []))
    for key, value in ioc_text_matches(text, config):
        if key in {"domains", "ips"}:
            category = "Known-Bad Network IOC"
            points = 40
        elif key == "registry_keys":
            category = "Suspicious Persistence IOC"
            points = 35
        else:
            category = "Confirmed IOC"
            points = 45
        add_detection(finding, category, f"{key} matched external IOC: {value}", "High Risk", points)
        finding.setdefault("evidence_types", []).append(f"ioc_{key}")


def scan_profiles() -> dict:
    return {
        "quick": {
            "scan_days": 3,
            "scan_timeout_seconds": 120,
            "scan_finish_buffer_seconds": 20,
            "max_files_scanned": 5000,
            "file_artifact_time_budget_seconds": 35,
            "skip_browser_artifacts": True,
            "skip_recovery_metadata": True,
            "external_forensic_tools_enabled": False,
            "collect_safe_account_identifiers": True,
            "collect_system_reset_evidence": True,
            "usn_journal_max_records": 1500,
            "usn_journal_window_bytes": 1_500_000,
            "usn_journal_timeout_seconds": 5,
            "shellbag_max_records": 1000,
            "description": "Faster triage scan. Some slower artifact sources are skipped and listed as limitations.",
        },
        "standard": {
            "scan_days": 10,
            "scan_timeout_seconds": 360,
            "scan_finish_buffer_seconds": 35,
            "max_files_scanned": 10000,
            "file_artifact_time_budget_seconds": 90,
            "skip_browser_artifacts": False,
            "skip_recovery_metadata": False,
            "external_forensic_tools_enabled": False,
            "collect_safe_account_identifiers": True,
            "collect_system_reset_evidence": True,
            "usn_journal_max_records": 5000,
            "usn_journal_window_bytes": 4_000_000,
            "usn_journal_timeout_seconds": 12,
            "shellbag_max_records": 5000,
            "description": "Balanced scan with broad Roblox, execution, file, AV, browser, and artifact coverage.",
        },
        "deep": {
            "scan_days": 90,
            "scan_timeout_seconds": 480,
            "scan_finish_buffer_seconds": 55,
            "max_files_scanned": 60000,
            "file_artifact_time_budget_seconds": 210,
            "skip_browser_artifacts": False,
            "skip_recovery_metadata": False,
            "external_forensic_tools_enabled": True,
            "collect_safe_account_identifiers": True,
            "collect_system_reset_evidence": True,
            "usn_journal_max_records": 12000,
            "usn_journal_window_bytes": 12_000_000,
            "usn_journal_timeout_seconds": 24,
            "shellbag_max_records": 12000,
            "description": "Maximum coverage scan with an 8 minute hard stop and terminal report upload.",
        },
    }


def normalize_scan_profile(profile: str | None) -> str:
    value = str(profile or "standard").strip().lower()
    return value if value in {"quick", "standard", "deep"} else "standard"


def apply_scan_profile(config: dict, profile: str | None) -> dict:
    selected = normalize_scan_profile(profile or config.get("default_scan_profile"))
    merged = dict(config)
    for key in ("skip_browser_artifacts", "skip_recovery_metadata", "max_files_scanned", "file_artifact_time_budget_seconds", "scan_finish_buffer_seconds", "scan_profile", "scan_profile_description"):
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
    if any(marker in lowered for marker in DEVELOPER_TOOL_PATH_MARKERS):
        return True
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
        "tool_output": root / "ToolOutput",
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
    try:
        exists = bool(path and Path(path).exists())
    except OSError:
        return {"status": "inaccessible", "subject": "", "issuer": ""}
    if not exists:
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
        if value.tzinfo is not None:
            return value.astimezone().replace(tzinfo=None)
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


def json_safe(value):
    if isinstance(value, dt.datetime):
        parsed = parse_dt(value)
        return parsed.isoformat(sep=" ", timespec="seconds") if parsed else str(value)
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    return value


def key_artifacts_from_report_parts(findings: list[dict], timeline: list[dict], recovery_artifacts: list[dict]) -> list[dict]:
    artifacts = []
    seen = set()

    def add(kind: str, label: str, path: str = "", timestamp: str = "", source: str = "", confidence: str = "Possible"):
        label = str(label or "").strip()
        if not label:
            return
        key = (kind, label.lower(), str(timestamp or ""))
        if key in seen:
            return
        seen.add(key)
        artifacts.append({
            "type": kind,
            "label": label,
            "path": str(path or ""),
            "timestamp": str(timestamp or ""),
            "source": str(source or ""),
            "confidence": str(confidence or "Possible"),
        })

    for finding in findings:
        confidence = finding.get("confidence_level") or confidence_for_classification(finding.get("classification", "Indicator Found"))
        timestamp = finding.get("first_seen", "")
        for evidence in finding.get("supporting_evidence", []):
            text = str(evidence)
            if text.startswith("PREFETCH FILE:"):
                add("Prefetch", text, finding.get("path", ""), timestamp, "Finding evidence", confidence)
            elif text.startswith("DELETED FILE:"):
                add("Deleted File", text, finding.get("path", ""), timestamp, "Finding evidence", confidence)

    for event in timeline:
        text = str(event.get("text", ""))
        if text.startswith("PREFETCH FILE:"):
            add("Prefetch", text, "", event.get("time", ""), event.get("source", "Timeline"), event.get("confidence", "Possible"))
        elif text.startswith("DELETED FILE:"):
            add("Deleted File", text, "", event.get("time", ""), event.get("source", "Timeline"), event.get("confidence", "Possible"))

    for item in recovery_artifacts:
        path = item.get("path", "")
        if path:
            add("Deleted File", f"DELETED FILE: {path}", path, item.get("timestamp", ""), item.get("source", "Recovery"), "Possible")

    return sorted(artifacts, key=lambda item: parse_dt(item.get("timestamp")) or dt.datetime.min, reverse=True)


def make_finding(path: str, name: str, source: str, config: dict) -> dict:
    norm = path if "://" in (path or "") or str(path or "").startswith(NETWORK_PATH_PREFIXES) else (normalize_path(path) if path else "")
    suppressed = securo_internal_path(norm, config)
    signer = signer_info(norm) if Path(norm).suffix.lower() in [".exe", ".dll"] else {"status": "not checked", "subject": "", "issuer": ""}
    try:
        hashable = Path(norm).is_file() and Path(norm).suffix.lower() in [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".zip", ".rar", ".7z"]
    except OSError:
        hashable = False
    finding = {
        "name": Path(norm).name if norm else name,
        "path": norm,
        "sha256": sha256_file(norm) if hashable else "",
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
    apply_ioc_matches(finding, config)
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
        if Path(filename).suffix.lower() in {".exe", ".dll"}:
            candidates.append(Path(filename).stem)
    return any(normalize_executor_keyword(candidate) in normalized_keywords for candidate in candidates)


def executor_keyword_match(finding: dict, config: dict) -> bool:
    if not already_flagged_by_detection(finding):
        return False
    return executor_filename_keyword_match(finding, config)


def flagged_executor_binary_match(finding: dict, config: dict) -> bool:
    return already_flagged_by_detection(finding) and executor_filename_keyword_match(finding, config)


def prefetch_confirmation_match(exe_name: str, referenced_paths: list[str], parsed_strings: list[str], config: dict) -> tuple[bool, str]:
    text = " ".join([exe_name, *referenced_paths, *parsed_strings]).lower()
    normalized_exe = normalize_executor_keyword(Path(exe_name or "").stem)
    executor_names = {
        normalize_executor_keyword(str(keyword))
        for keyword in config.get("executor_confirmation_keywords", [])
        if str(keyword).strip()
    }
    if normalized_exe and normalized_exe in executor_names:
        return True, f"Prefetch executable name matches known exploit family: {exe_name}"
    if re.search(r"(?<![a-z0-9])(clumsy|windivert)(?![a-z0-9])", text, re.I):
        return True, "Prefetch contains Clumsy/WinDivert network-manipulation evidence."
    fastflag_terms = ("fastflag", "fflag", "dfflag", "dfint", "flog", "clientappsettings")
    if any(term in text for term in fastflag_terms) and ROBLOX_EXE.lower() not in (exe_name or "").lower():
        return True, "Prefetch contains FastFlag or ClientAppSettings evidence for a non-Roblox executable."
    return False, ""


def prefetch_only_without_confirmed_indicator(finding: dict) -> bool:
    types = set(finding.get("evidence_types", []))
    if "prefetch_execution" not in types or "prefetch_confirmed_indicator" in types:
        return False
    direct_types = {
        "sysmon_remote_thread",
        "sysmon_process_access",
        "suspicious_module_load",
        "confirmed_fastflag_injector",
        "confirmed_executor_artifact",
        "ioc_hash",
    }
    return not bool(types & direct_types)


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


def finding_tokens(finding: dict) -> set[str]:
    values = {str(finding.get("name", "")).lower(), str(finding.get("path", "")).lower()}
    path = str(finding.get("path", "") or "")
    name = Path(path).name.lower() if path else ""
    if name:
        values.add(name)
    return {value for value in values if value}


def related_artifacts(left: dict, right: dict) -> bool:
    left_path = str(left.get("path", "") or "").lower()
    right_path = str(right.get("path", "") or "").lower()
    if left_path and right_path and left_path == right_path:
        return True
    left_name = str(left.get("name", "") or Path(left_path).name).lower()
    right_name = str(right.get("name", "") or Path(right_path).name).lower()
    return bool(left_name and right_name and left_name == right_name)


def finding_has_execution(finding: dict) -> bool:
    return bool(set(finding.get("evidence_types", [])) & {"process_execution", "prefetch_execution", "powershell_history"})


def finding_has_deletion(finding: dict) -> bool:
    categories = set(finding.get("detection_categories", []))
    types = set(finding.get("evidence_types", []))
    evidence_text = " ".join(str(x) for x in finding.get("supporting_evidence", [])).lower()
    return bool(types & {"recovery", "possible_context"} and ("delet" in evidence_text or categories & {"Recycle Bin", "Recovered File Metadata", "Suspicious File Deletion", "Suspicious DLL Deletion"}))


def parse_file_metadata_times(finding: dict) -> tuple[dt.datetime | None, dt.datetime | None, dt.datetime | None]:
    text = " ".join(str(x) for x in finding.get("supporting_evidence", []))
    match = re.search(r"created=([^ ]+ [^ ]+) modified=([^ ]+ [^ ]+) accessed=([^ ]+ [^ ]+)", text)
    if not match:
        return None, None, None
    return parse_dt(match.group(1)), parse_dt(match.group(2)), parse_dt(match.group(3))


def finding_has_later_modification(finding: dict) -> bool:
    created, modified, accessed = parse_file_metadata_times(finding)
    first_seen = parse_dt(finding.get("first_seen"))
    if modified and created and modified > created + dt.timedelta(seconds=60):
        return True
    if modified and first_seen and modified > first_seen + dt.timedelta(seconds=60):
        return True
    return bool(accessed and first_seen and accessed > first_seen + dt.timedelta(seconds=60))


def matching_prefetch_exists(finding: dict, config: dict | None = None) -> bool:
    config = config or {}
    folder = Path(config.get("prefetch_dir") or "C:/Windows/Prefetch")
    if not safe_exists(folder):
        return True
    stem = Path(finding.get("name") or finding.get("path") or "").stem
    if not stem:
        return True
    try:
        return any(pf.name.lower().startswith(stem.lower() + "-") for pf in folder.glob("*.pf"))
    except OSError:
        return True


def enrich_artifact_relationships(findings: list[dict], config: dict) -> None:
    visible = [f for f in findings if not f.get("suppressed") and not securo_internal_path(f.get("path", ""), config)]
    executed = [f for f in visible if finding_has_execution(f)]
    deleted = [f for f in visible if finding_has_deletion(f)]

    for finding in visible:
        if not detection_triggered(finding):
            continue
        path = finding.get("path", "")
        low_path = str(path).lower()
        suffix = Path(path or finding.get("name", "")).suffix.lower()
        categories = set(finding.get("detection_categories", []))
        if finding_has_execution(finding) and finding_has_later_modification(finding):
            add_detection(finding, "Executed & Modified", "Executed artifact has file metadata showing later modification; possible self-destruct or update behavior.", "Medium", 25)
            finding["evidence_types"].append("executed_modified")
        if (finding_has_execution(finding) or finding_has_deletion(finding) or finding_has_later_modification(finding)) and (suspicious_name(finding.get("name", ""), config) or categories & HIGH_CONFIDENCE_CHEAT_CATEGORIES or categories & CONFIRMED_EXPLOIT_CATEGORIES):
            add_detection(finding, "Suspicious File Deletion/Execution/Modification", "A highly suspicious artifact had execution, deletion, or modification evidence.", "High", 30)
            finding["evidence_types"].append("suspicious_file_activity")
        if (finding_has_execution(finding) or finding_has_deletion(finding) or finding_has_later_modification(finding)) and ("\\windows\\system32\\" in low_path or "\\windows\\syswow64\\" in low_path):
            add_detection(finding, "Impossible File Deletion/Execution/Modification", "Suspicious activity references a protected system location where normal user-driven modification/deletion is unlikely.", "High", 35)
            finding["evidence_types"].append("impossible_file_activity")
        if finding_has_deletion(finding):
            add_detection(finding, "Suspicious File Deletion/Execution/Modification", "Suspicious deleted-file artifact requires manual review.", "Medium", 20)
            finding["evidence_types"].append("deletion_artifact")
            if suffix == ".dll":
                add_detection(finding, "Suspicious DLL Deletion", "Deleted suspicious DLL metadata was observed.", "High", 30)
                finding["evidence_types"].append("suspicious_dll_deleted")
            if str(path).startswith(NETWORK_PATH_PREFIXES):
                add_detection(finding, "Generic Bypass Method (Network File)", "Deleted/modified suspicious artifact was located on a network resource.", "High", 35)
                finding["evidence_types"].append("network_artifact")
            if len(str(path)) > 2 and str(path)[1] == ":" and str(path)[0].upper() in EXTERNAL_DRIVE_LETTERS:
                add_detection(finding, "External Device Deletion", "Deleted suspicious artifact was located on an external/removable-drive style letter.", "Medium", 25)
                finding["evidence_types"].append("external_device_deletion")
        if str(path).startswith(NETWORK_PATH_PREFIXES):
            finding["evidence_types"].append("network_artifact")
        if len(str(path)) > 2 and str(path)[1] == ":" and str(path)[0].upper() in EXTERNAL_DRIVE_LETTERS:
            finding["evidence_types"].append("external_device")
        if "network_artifact" in finding.get("evidence_types", []):
            add_detection(finding, "Generic Bypass Method (Network File)", "Suspicious file activity involved a network resource.", "High", 35)
        if "external_device" in finding.get("evidence_types", []):
            add_detection(finding, "Generic Bypass Method (External Device Execution)", "Suspicious execution involved an external/removable-drive style path.", "High", 30)
        local_hits = len(set(finding.get("detection_categories", [])))
        signer_status = (finding.get("signer", {}) or {}).get("status", "").lower()
        if local_hits >= 4 and signer_status in {"notsigned", "unknown", "missing", ""} and not allowlisted_finding(finding, config):
            add_detection(finding, "Untrusted File", "Multiple local heuristic flags matched an unsigned or untrusted artifact.", "High", 30)
        if {"packed", "ruin_mode"} <= set(finding.get("evidence_types", [])):
            add_detection(finding, "Generic Packed Mod", "Game/mod artifact shows packed or obfuscated traits.", "Medium", 25)
        if finding_has_execution(finding) and not matching_prefetch_exists(finding, config) and (suspicious_name(finding.get("name", ""), config) or exploit_specific_artifact(finding, config)):
            add_detection(finding, "Prefetch Deleted", "Suspicious execution was observed but no matching Prefetch file is currently present.", "Medium", 25)
            finding["evidence_types"].append("prefetch_deleted")

    for run in executed:
        for gone in deleted:
            if not related_artifacts(run, gone):
                continue
            add_detection(run, "Executed & Deleted", "Execution evidence and deleted-file metadata refer to the same suspicious artifact.", "High", 35)
            run["evidence_types"].append("executed_deleted")
            add_detection(gone, "Executed & Deleted", "Deleted-file metadata matches a suspicious executed artifact.", "High", 35)
            gone["evidence_types"].append("executed_deleted")
            if str(gone.get("path", "")).startswith(NETWORK_PATH_PREFIXES) or str(run.get("path", "")).startswith(NETWORK_PATH_PREFIXES):
                add_detection(run, "Generic Bypass Method (Network File)", "Executed/deleted chain involved a network resource.", "High", 35)
                run["evidence_types"].append("network_artifact")


def cheap_artifact_candidate(path_text: str, times: list[dt.datetime], sessions: list[dict], config: dict) -> bool:
    name = Path(path_text).name.lower()
    low = path_text.lower()
    suffix = Path(path_text).suffix.lower()
    if suspicious_name(name, config):
        return True
    if ioc_text_matches(path_text, config):
        return True
    if any(near_any_session(t, sessions) for t in times):
        return True
    if risky_source_path(path_text) and suffix in {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".ahk", ".rar", ".7z", ".zip", ".jar"}:
        return True
    if path_text.startswith(NETWORK_PATH_PREFIXES):
        return True
    if len(path_text) > 2 and path_text[1] == ":" and path_text[0].upper() in EXTERNAL_DRIVE_LETTERS:
        return True
    if re.search(r"\.(jpg|png|gif|txt|pdf|docx?)\.(exe|dll|scr|bat|cmd|ps1)$", name):
        return True
    if any(term in low for term in ["clientsettings", "fastflag", "fflag", "dfflag", "dfint", "flog", "robloxplayerbeta", "clumsy", "windivert", "potassium", "\\monaco\\", "\\basic-languages\\lua\\", "rbxscriptsignal"]):
        return True
    if ".minecraft" in low or "\\mods\\" in low:
        return True
    return False


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


def sample_verified_exploit_artifact(finding: dict) -> bool:
    categories = set(finding.get("detection_categories", []))
    return bool(categories & {"Confirmed FastFlag Injector", "Confirmed Executor Artifact"})


def confirmed_exploit_artifact(finding: dict, config: dict) -> bool:
    categories = set(finding.get("detection_categories", []))
    if prefetch_only_without_confirmed_indicator(finding):
        return False
    if "prefetch_confirmed_indicator" in set(finding.get("evidence_types", [])):
        return True
    if flagged_executor_binary_match(finding, config):
        return True
    if sample_verified_exploit_artifact(finding):
        return True
    if not confirmed_verification_gate(finding, config):
        return False
    if known_bad_hash(finding, config):
        return True
    if "Confirmed IOC" in categories:
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
    if prefetch_only_without_confirmed_indicator(finding):
        return "Possible"
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
    search_text = lower[:300000].decode("latin1", errors="ignore")

    fastflag_terms = [b"fflag", b"dfflag", b"dfint", b"flog", b"fastflag", b"clientappsettings"]
    fastflag_hits = [term.decode("latin1") for term in fastflag_terms if term in lower]
    roblox_memory_hits = [term for term in [b"robloxplayerbeta.exe", b"openprocess", b"writeprocessmemory", b"fvar container"] if term in lower]
    if fastflag_hits and (b"roblox" in lower or roblox_memory_hits):
        add_detection(finding, "FastFlag Injector", "File contains Roblox FastFlag modification/injection strings.", "High", 45)
        finding["evidence_types"].append("fastflag_injector")
        finding["supporting_evidence"].append("FastFlag indicators: " + ", ".join(sorted(set(fastflag_hits))[:8]))
        if len(roblox_memory_hits) >= 2 or (b"robloxplayerbeta.exe" in lower and b"fvar container" in lower):
            add_detection(finding, "Confirmed FastFlag Injector", "Roblox process targeting, FastFlag strings, and memory/injection indicators were found together.", "High Risk", 75)
            finding["evidence_types"].append("confirmed_fastflag_injector")

    executor_layout_hits = []
    if "potassium" in path_lower or b"potassium" in lower:
        executor_layout_hits.append("Potassium name")
    for marker in ["\\monaco\\", "\\basic-languages\\lua\\", "rbxscriptsignal", "drawing.js", "crypt.js", "raknet.js", "\\scripts\\", "decompiler.exe", "loader.js"]:
        if marker in path_lower or marker.encode("latin1", errors="ignore") in lower:
            executor_layout_hits.append(marker.strip("\\"))
    if len(set(executor_layout_hits)) >= 2 or ("potassium" in path_lower and suffix in {".exe", ".dll"}):
        add_detection(finding, "Executor Bundle Artifact", "File or surrounding path matches a Roblox script executor bundle layout.", "High", 45)
        finding["evidence_types"].append("executor_bundle")
        finding["supporting_evidence"].append("Executor bundle indicators: " + ", ".join(sorted(set(executor_layout_hits))[:10]))
        if "potassium" in path_lower and (suffix in {".exe", ".dll"} or len(set(executor_layout_hits)) >= 3):
            add_detection(finding, "Confirmed Executor Artifact", "Known executor binary/layout indicators were found on an already-flagged artifact.", "High Risk", 75)
            finding["evidence_types"].append("confirmed_executor_artifact")

    windivert_hits = []
    for marker in ["clumsy", "windivert", "windivert64.sys", "packet lag", "drop", "throttle", "duplicate", "tamper"]:
        if marker in path_lower or marker in search_text:
            windivert_hits.append(marker)
    if "clumsy" in path_lower or "windivert" in path_lower or len(set(windivert_hits)) >= 2:
        add_detection(finding, "Network Lag Tool / WinDivert Manipulation", "Network lag or WinDivert traffic manipulation artifact found.", "High", 45)
        finding["evidence_types"].append("network_lag_tool")
        finding["supporting_evidence"].append("Network manipulation indicators: " + ", ".join(sorted(set(windivert_hits))[:10]))

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
    if prefetch_only_without_confirmed_indicator(finding):
        return "Indicator Found"
    if "possible_context" in types and categories & {"Network Lag Tool / WinDivert Manipulation", "Suspicious File Deletion", "Suspicious DLL Deletion", "Prefetch Deleted"}:
        return "Suspicious"
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
    if "Network Lag Tool / WinDivert Manipulation" in categories:
        return "Suspicious"
    if score >= config["category_thresholds"]["suspicious"]:
        return "Suspicious"
    if score >= config["category_thresholds"]["weak"]:
        return "Indicator Found"
    return "Indicator Found"


def finalize_findings(findings: list[dict], config: dict) -> list[dict]:
    visible = [f for f in findings if not f.get("suppressed") and not securo_internal_path(f.get("path", ""), config)]
    enrich_artifact_relationships(visible, config)
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


def extract_fastflags_from_line(line: str, timestamp: str, source_log: str) -> list[dict]:
    results = []
    seen = set()
    patterns = [
        r"\b((?:D?F(?:Flag|Int|String|Log)|SFFlag)[A-Za-z0-9_]+)\b\s*(?:=|:|,)\s*([^\s,\]}\"']+)",
        r"[\"']((?:D?F(?:Flag|Int|String|Log)|SFFlag)[A-Za-z0-9_]+)[\"']\s*:\s*[\"']?([^,\"'}\]]+)",
        r"\b((?:D?F(?:Flag|Int|String|Log)|SFFlag)[A-Za-z0-9_]+)\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, line, re.I):
            name = match.group(1)
            value = match.group(2).strip() if len(match.groups()) >= 2 and match.group(2) is not None else ""
            key = (name.lower(), value)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "name": name,
                "value": value,
                "sourceLog": source_log,
                "timestamp": timestamp,
                "line": line.strip(),
            })
    return results


def roblox_event_from_line(line: str, timestamp: str, source_log: str) -> dict | None:
    low = line.lower()
    event_terms = {
        "teleport": "Teleport",
        "reconnect": "Reconnect",
        "server": "Server",
        "placeid": "Place",
        "place id": "Place",
        "jobid": "Job",
        "job id": "Job",
        "join": "Join",
        "leave": "Leave",
        "disconnect": "Disconnect",
        "loadclientsettings": "ClientSettings",
        "fflag": "FastFlag",
        "dfint": "FastFlag",
        "ffint": "FastFlag",
        "dfflag": "FastFlag",
    }
    kind = next((label for term, label in event_terms.items() if term in low), "")
    if not kind:
        return None
    return {
        "timestamp": timestamp,
        "type": kind,
        "sourceLog": source_log,
        "message": line.strip(),
    }


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
                "fast_flags": [],
                "events": [],
                "raw_log": "",
                "raw_lines": [],
                "all_logs": [],
                "suspicious_lines": [],
            }
            try:
                raw_text = path.read_text(encoding="utf-8", errors="replace")
                lines = raw_text.splitlines()
                session["raw_log"] = raw_text
                session["raw_lines"] = lines
            except Exception:
                lines = []
            seen_times = []
            for line in lines:
                ts = parse_log_timestamp(line, mtime)
                if ts:
                    seen_times.append(ts)
                line_time = (ts or mtime).isoformat(sep=" ", timespec="seconds")
                event = roblox_event_from_line(line, line_time, str(path))
                if event:
                    session["events"].append(event)
                if "LoadClientSettings" in line:
                    session["load_client_settings"].append(line.strip())
                if re.search(r"\b(error|warn|failed|exception)\b", line, re.I):
                    session["errors"].append(line.strip())
                if re.search(r"\b(crash|fatal|minidump|stack trace)\b", line, re.I):
                    session["crashes"].append(line.strip())
                if re.search(r"\b(fflag|dfint|fflag|flag)\b", line, re.I):
                    session["flags"].append(line.strip())
                fast_flags = extract_fastflags_from_line(line, line_time, str(path))
                if fast_flags:
                    session["fast_flags"].extend(fast_flags)
                if suspicious_text(line, config):
                    session["suspicious_lines"].append(line.strip())
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
            session["all_logs"] = [{
                "logFile": str(path),
                "modifiedTime": mtime.isoformat(sep=" ", timespec="seconds"),
                "startTime": session["start_time"],
                "endTime": session["end_time"],
                "duration": session["duration"],
                "placeId": session["place_id"],
                "jobId": session["job_id"],
                "userId": session["user_id"],
                "username": session["username"] or "Unknown",
                "displayName": session["display_name"],
                "version": session["version"],
                "events": session["events"],
                "fastFlags": session["fast_flags"],
                "loadClientSettings": session["load_client_settings"],
                "errors": session["errors"],
                "crashes": session["crashes"],
                "rawLog": session["raw_log"],
            }]
            sessions.append(session)
            for line in session["crashes"][:3]:
                timeline.append({"time": session["start_time"], "source": "Roblox log", "text": f"Roblox crash/fatal line: {line[:160]}"})
    deduped = {}
    for s in sessions:
        key = (s.get("start_time"), s.get("end_time"), s.get("place_id"), s.get("job_id"), s.get("user_id"), s.get("username"))
        if key not in deduped:
            deduped[key] = s
            continue
        existing = deduped[key]
        for field in ["load_client_settings", "errors", "crashes", "flags", "fast_flags", "events", "suspicious_lines", "all_logs"]:
            existing[field] = existing.get(field, []) + s.get(field, [])
        existing["log_file"] = "; ".join(sorted(set([existing.get("log_file", ""), s.get("log_file", "")]) - {""}))
    return list(deduped.values()), timeline


def collect_safe_account_identifiers(sessions: list[dict], config: dict) -> dict:
    # This collects non-secret account identifiers only. It deliberately skips browser-style stores that may contain tokens/cookies.
    roblox_accounts = {}
    for session in sessions:
        user_id = str(session.get("user_id") or "").strip()
        username = str(session.get("username") or "Unknown").strip() or "Unknown"
        if not user_id and username == "Unknown":
            continue
        key = user_id or username.lower()
        row = roblox_accounts.setdefault(key, {
            "platform": "Roblox",
            "userId": user_id,
            "username": username,
            "displayName": session.get("display_name", ""),
            "firstSeen": session.get("start_time", ""),
            "lastSeen": session.get("end_time") or session.get("start_time", ""),
            "places": set(),
            "jobs": set(),
            "sources": set(),
        })
        row["firstSeen"] = first_time(row.get("firstSeen"), session.get("start_time")) or row.get("firstSeen", "")
        row["lastSeen"] = max([v for v in [row.get("lastSeen"), session.get("end_time"), session.get("start_time")] if v] or [""], default="")
        if session.get("place_id"):
            row["places"].add(session["place_id"])
        if session.get("job_id"):
            row["jobs"].add(session["job_id"])
        if session.get("log_file"):
            row["sources"].add(session["log_file"])

    if config.get("collect_safe_account_identifiers", True):
        for item in collect_historical_roblox_identifiers(config):
            user_id = str(item.get("userId") or "").strip()
            username = str(item.get("username") or "Unknown").strip() or "Unknown"
            key = user_id or username.lower()
            if not key:
                continue
            row = roblox_accounts.setdefault(key, {
                "platform": "Roblox",
                "userId": user_id,
                "username": username,
                "displayName": item.get("displayName", ""),
                "firstSeen": item.get("timestamp", ""),
                "lastSeen": item.get("timestamp", ""),
                "places": set(),
                "jobs": set(),
                "sources": set(),
            })
            if row.get("username") in {"", "Unknown"} and username != "Unknown":
                row["username"] = username
            if not row.get("displayName") and item.get("displayName"):
                row["displayName"] = item["displayName"]
            row["firstSeen"] = first_time(row.get("firstSeen"), item.get("timestamp")) or row.get("firstSeen", "")
            row["lastSeen"] = max([v for v in [row.get("lastSeen"), item.get("timestamp")] if v] or [""], default="")
            if item.get("source"):
                row["sources"].add(item["source"])

    def clean(row: dict) -> dict:
        result = dict(row)
        for key in ("places", "jobs", "sources"):
            if key in result:
                result[key] = sorted(result[key])
        return result

    discord_accounts = collect_safe_discord_identifiers(config) if config.get("collect_safe_account_identifiers", True) else []
    return {
        "privacyNote": "Only non-secret Roblox and Discord account identifiers from retained logs/artifacts are included. Discord collection excludes tokens, cookies, Local Storage, IndexedDB, Session Storage, cache, private messages, DMs, friend lists, and server lists.",
        "roblox": [clean(row) for row in roblox_accounts.values()],
        "discord": discord_accounts,
        "discordStatus": config.get("_discord_account_status", {}),
    }


def discord_log_roots() -> list[Path]:
    appdata = Path(os.environ.get("APPDATA", ""))
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roots = []
    for app in ["discord", "discordptb", "discordcanary"]:
        if appdata:
            roots.append(appdata / app / "logs")
        if local:
            roots.append(local / app / "logs")
    return [path for path in roots if safe_exists(path)]


def collect_safe_discord_identifiers(config: dict) -> list[dict]:
    # Privacy boundary: only plain Discord log files are inspected. Token/cookie/storage/cache/message stores are intentionally skipped.
    status = {
        "rootsChecked": [],
        "logFilesFound": 0,
        "logFilesScanned": 0,
        "bytesRead": 0,
        "candidateIdsFound": 0,
        "skippedUnsafeLines": 0,
        "skippedNoAccountContextLines": 0,
        "note": "Only Discord log .log/.txt files are scanned. Token/cookie/storage/cache/message databases are excluded.",
    }
    config["_discord_account_status"] = status
    max_files = max(1, int(config.get("discord_log_max_files", 180) or 180))
    max_bytes = max(32_000, int(config.get("discord_log_max_bytes", 500_000) or 500_000))
    max_total_bytes = max(max_bytes, int(config.get("discord_log_total_bytes", 6_000_000) or 6_000_000))
    deadline = time.monotonic() + max(2, int(config.get("discord_account_scan_time_budget_seconds", 5) or 5))
    candidates = []
    for root in discord_log_roots():
        status["rootsChecked"].append(str(root))
        try:
            candidates.extend(path for path in root.glob("*.log") if path.is_file())
            candidates.extend(path for path in root.glob("*.txt") if path.is_file())
        except OSError:
            continue

    def modified_time(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0

    candidates = sorted(set(candidates), key=modified_time, reverse=True)[:max_files]
    status["logFilesFound"] = len(candidates)
    snowflake_pattern = re.compile(r"\b([1-9]\d{16,19})\b")
    account_context_pattern = re.compile(
        r"(?i)\b("
        r"user[_\s-]?id|userid|userId|current[_\s-]?user|currentUser|account[_\s-]?id|"
        r"discord[_\s-]?id|global[_\s-]?name|username|display[_\s-]?name|me[_\s-]?store|"
        r"user[_\s-]?settings|authenticated[_\s-]?user|login[_\s-]?user|self"
        r")\b"
    )
    unsafe_context_pattern = re.compile(r"(?i)\b(token|authorization|cookie|session[_\s-]?storage|local[_\s-]?storage|indexeddb|cache|message|dm|direct message|guild|channel)\b")
    username_pattern = re.compile(r"(?i)(?:username|global[_\s-]?name|display[_\s-]?name)[\"'\s:=,-]{0,24}([A-Za-z0-9_.@-]{2,64})")
    current_user_json_pattern = re.compile(
        r"(?i)(?:currentUser|current_user|authenticatedUser|authenticated_user|me|self)[^\n\r]{0,240}?"
        r"(?:\"id\"|id|userId|user_id)[\"'\s:=,-]{0,16}([1-9]\d{16,19})"
    )
    accounts: dict[str, dict] = {}
    bytes_read = 0

    def remember_account(user_id: str, line: str, path: Path, timestamp: str) -> None:
        window_match = re.search(re.escape(user_id), line)
        if window_match:
            window = line[max(0, window_match.start() - 160):window_match.end() + 160]
        else:
            window = line[:320]
        username_match = username_pattern.search(window)
        row = accounts.setdefault(user_id, {
            "platform": "Discord",
            "userId": user_id,
            "username": "Unknown",
            "displayName": "",
            "firstSeen": timestamp,
            "lastSeen": timestamp,
            "places": set(),
            "jobs": set(),
            "sources": set(),
            "confidenceLevel": "Possible",
            "evidenceNote": "Safe Discord log identifier evidence only. This is not token/cookie/session data and may require manual review.",
        })
        if username_match and row.get("username") == "Unknown":
            row["username"] = username_match.group(1).strip().strip('"').strip("'")
        row["firstSeen"] = first_time(row.get("firstSeen"), timestamp) or row.get("firstSeen", "")
        row["lastSeen"] = max([v for v in [row.get("lastSeen"), timestamp] if v] or [""], default="")
        row["sources"].add(str(path))

    for path in candidates:
        if time.monotonic() >= deadline or bytes_read >= max_total_bytes:
            break
        try:
            stat = path.stat()
        except OSError:
            continue
        read_size = min(max_bytes, max(0, max_total_bytes - bytes_read))
        if read_size <= 0:
            break
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(read_size)
        except OSError:
            continue
        bytes_read += len(text.encode("utf-8", errors="replace"))
        status["logFilesScanned"] += 1
        status["bytesRead"] = bytes_read
        timestamp = dt.datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds")
        for line in text.splitlines():
            if unsafe_context_pattern.search(line):
                status["skippedUnsafeLines"] += 1
                continue
            direct_ids = [match.group(1) for match in current_user_json_pattern.finditer(line)]
            if not direct_ids and not account_context_pattern.search(line):
                status["skippedNoAccountContextLines"] += 1
                continue
            ids = direct_ids or [match.group(1) for match in snowflake_pattern.finditer(line)]
            for user_id in ids:
                remember_account(user_id, line, path, timestamp)

    cleaned = []
    for row in accounts.values():
        result = dict(row)
        for key in ("places", "jobs", "sources"):
            if key in result:
                result[key] = sorted(result[key])
        cleaned.append(result)
    status["candidateIdsFound"] = len(cleaned)
    return sorted(cleaned, key=lambda item: item.get("lastSeen", ""), reverse=True)


def collect_historical_roblox_identifiers(config: dict) -> list[dict]:
    # Account history is independent from the selected session window. Only IDs/names and artifact timestamps are retained.
    max_files = max(1, int(config.get("account_log_max_files", 600) or 600))
    max_bytes = max(64_000, int(config.get("account_log_max_bytes", 4_000_000) or 4_000_000))
    max_total_bytes = max(max_bytes, int(config.get("account_log_total_bytes", 32_000_000) or 32_000_000))
    deadline = time.monotonic() + max(2, int(config.get("account_scan_time_budget_seconds", 12) or 12))
    candidates = []
    for folder in get_common_roblox_log_dirs():
        try:
            candidates.extend(path for path in folder.rglob("*.log") if path.is_file())
        except OSError:
            continue
    def modified_time(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0

    candidates = sorted(set(candidates), key=modified_time, reverse=True)[:max_files]
    results = []
    seen = set()
    bytes_read = 0
    account_pattern = re.compile(
        r"(?i)(?:userid|user[_\s-]?id|userId)[^\d]{0,40}(\d{2,20})"
    )
    username_pattern = re.compile(
        r"(?i)(?:username|user[_\s-]?name)[^\w@.-]{0,20}([\w@.-]{2,64})"
    )
    display_pattern = re.compile(
        r"(?i)(?:displayname|display[_\s-]?name)[^\w@.-]{0,20}([\w @.-]{2,64})"
    )
    for path in candidates:
        if time.monotonic() >= deadline or bytes_read >= max_total_bytes:
            break
        try:
            stat = path.stat()
        except OSError:
            continue
        read_size = min(max_bytes, max(0, max_total_bytes - bytes_read))
        if read_size <= 0:
            break
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(read_size)
        except OSError:
            continue
        bytes_read += len(text.encode("utf-8", errors="replace"))
        timestamp = dt.datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds")
        for match in account_pattern.finditer(text):
            user_id = match.group(1)
            window = text[max(0, match.start() - 500):match.end() + 500]
            username_match = username_pattern.search(window)
            display_match = display_pattern.search(window)
            key = (user_id, str(path))
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "platform": "Roblox",
                "userId": user_id,
                "username": username_match.group(1).strip() if username_match else "Unknown",
                "displayName": display_match.group(1).strip() if display_match else "",
                "timestamp": timestamp,
                "source": str(path),
            })

    registry_text = ""
    if time.monotonic() < deadline:
        registry_text = run_command(["reg", "query", r"HKCU\Software\Roblox", "/s"], timeout=3)
    registry_ids = set(re.findall(r"(?i)(?:roblox\.com/users/|user[_\s-]?id\D{0,20})(\d{2,20})", registry_text))
    for user_id in registry_ids:
        key = (user_id, "Roblox registry")
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "platform": "Roblox",
            "userId": user_id,
            "username": "Unknown",
            "displayName": "",
            "timestamp": "",
            "source": r"HKCU\Software\Roblox",
        })
    return results


def collect_system_reset_evidence(days: int, config: dict) -> tuple[list[dict], list[dict]]:
    # Windows usually preserves install/reset context, not a definitive factory-reset ledger.
    evidence = []
    timeline = []
    cut = cutoff(max(days, 3650))
    install_raw = run_command(
        ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "/v", "InstallDate"],
        timeout=3,
    ).strip()
    install_match = re.search(r"InstallDate\s+REG_DWORD\s+(0x[0-9a-f]+|\d+)", install_raw, re.I)
    if install_match:
        raw_value = install_match.group(1)
        try:
            installed_at = dt.datetime.fromtimestamp(int(raw_value, 16 if raw_value.lower().startswith("0x") else 10))
            stamp = installed_at.isoformat(sep=" ", timespec="seconds")
            evidence.append({
                "type": "Possible Windows Reset/Reinstall",
                "timestamp": stamp,
                "source": "Windows CurrentVersion InstallDate",
                "details": "Windows installation timestamp. This may represent a factory reset, clean install, or major reinstall.",
            })
            timeline.append({"time": stamp, "source": "System reset/install", "text": "Windows installation timestamp observed."})
        except (ValueError, OSError, OverflowError):
            pass
    paths = [
        Path("C:/Windows/Panther/setupact.log"),
        Path("C:/Windows/Panther/setuperr.log"),
        Path("C:/Windows.old"),
        Path("C:/$Windows.~BT"),
        Path("C:/$SysReset"),
        Path("C:/$GetCurrent"),
        Path("C:/Recovery"),
        Path("C:/Windows/System32/Recovery"),
    ]
    for path in paths:
        if not safe_exists(path):
            continue
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            mtime = None
        stamp = mtime.isoformat(sep=" ", timespec="seconds") if mtime else ""
        evidence.append({
            "type": "Reset/Install Artifact",
            "timestamp": stamp,
            "source": str(path),
            "details": "Windows reset, recovery, or installation artifact exists. Manual review is required.",
        })
        if mtime and mtime >= cut:
            timeline.append({"time": stamp, "source": "System reset/install", "text": f"Reset/install artifact observed: {path}"})
    setup_events = query_events("Setup", [1, 2, 3, 4, 13, 17, 19, 20, 31], max(days, 3650), max_events=40, timeout=8)
    for event in setup_events[:40]:
        text = " ".join(str(v) for v in event.get("data", {}).values())[:500]
        if not text or not re.search(r"\b(reset|install|reinstall|upgrade|recovery|rollback|setup)\b", text, re.I):
            continue
        stamp = event.get("time") or iso_now()
        event_id = event.get("event_id")
        evidence.append({"type": "Windows Setup Event", "timestamp": stamp, "source": "Windows Setup Event Log", "eventId": event_id, "details": text})
        timeline.append({"time": stamp, "source": "System reset/install", "text": f"Windows Setup event {event_id}: {text[:160]}"})
    return evidence, timeline


def parse_windows_install_record(key: str, text: str) -> dict | None:
    def reg_value(name: str) -> str:
        match = re.search(rf"^\s*{re.escape(name)}\s+REG_\w+\s+(.+?)\s*$", text, re.I | re.M)
        return match.group(1).strip() if match else ""

    product = reg_value("ProductName")
    release = reg_value("DisplayVersion") or reg_value("ReleaseId")
    build = reg_value("CurrentBuild") or reg_value("CurrentBuildNumber")
    install_raw = reg_value("InstallDate")
    installed = ""
    if install_raw:
        try:
            value = int(install_raw, 16 if install_raw.lower().startswith("0x") else 10)
            installed = dt.datetime.fromtimestamp(value).isoformat(sep=" ", timespec="seconds")
        except (ValueError, OSError, OverflowError):
            installed = install_raw
    if not any((product, release, build, installed)):
        return None
    return {
        "productName": product or "Unknown Windows edition",
        "releaseId": release,
        "currentBuild": build,
        "installDate": installed,
        "source": key,
    }


def collect_windows_install_history() -> list[dict]:
    keys = [r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"]
    setup_keys = run_command(["reg", "query", r"HKLM\SYSTEM\Setup"], timeout=5)
    for line in setup_keys.splitlines():
        key = line.strip()
        if re.search(r"\\Source OS\s*\(", key, re.I):
            keys.append(key)
    rows = []
    seen = set()
    for key in keys[:40]:
        text = run_command(["reg", "query", key], timeout=4)
        row = parse_windows_install_record(key, text)
        if not row:
            continue
        identity = (row["productName"].lower(), row["releaseId"].lower(), row["currentBuild"].lower(), row["installDate"])
        if identity in seen:
            continue
        seen.add(identity)
        rows.append(row)
    return sorted(rows, key=lambda item: parse_dt(item.get("installDate")) or dt.datetime.min, reverse=True)


def collect_sysmain_service_info(days: int) -> dict:
    query = run_command(["sc.exe", "query", "SysMain"], timeout=5)
    config = run_command(["sc.exe", "qc", "SysMain"], timeout=5)
    state_match = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", query, re.I)
    start_match = re.search(r"START_TYPE\s*:\s*\d+\s+([A-Z_]+)", config, re.I)
    state = state_match.group(1).replace("_", " ").title() if state_match else "Unavailable"
    startup = start_match.group(1).replace("_", " ").title() if start_match else "Unavailable"
    last_changed = ""
    change_detail = ""
    for event in query_events("System", [7036, 7040], max(days, 3650), max_events=120, timeout=8):
        event_text = " ".join(str(value) for value in event.get("data", {}).values())
        if "sysmain" not in (event_text + " " + event.get("raw", "")).lower():
            continue
        last_changed = str(event.get("time") or "")
        change_detail = event_text[:300]
        break
    return {
        "serviceName": "SysMain",
        "currentState": state,
        "startupType": startup,
        "lastChanged": last_changed,
        "changeDetail": change_detail,
        "manualReviewRequired": startup.lower() == "disabled",
    }


def query_events(log_name: str, event_ids: list[int], days: int, max_events=300, timeout=45) -> list[dict]:
    ms = days * 24 * 60 * 60 * 1000
    ids = " or ".join([f"EventID={i}" for i in event_ids])
    query = f"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    out = run_command(["wevtutil", "qe", log_name, "/q:" + query, "/f:xml", "/rd:true", "/c:" + str(max_events)], timeout=timeout)
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


def jump_list_roots(config: dict | None = None) -> list[Path]:
    configured = (config or {}).get("jump_list_roots") or []
    if configured:
        return [Path(os.path.expandvars(str(root))).expanduser() for root in configured]
    appdata = Path(os.environ.get("APPDATA", ""))
    base = appdata / "Microsoft" / "Windows" / "Recent"
    return [base / "AutomaticDestinations", base / "CustomDestinations"]


def forensic_parser_tools_available() -> bool:
    return bool(available_forensic_tools({}))


FORENSIC_TOOL_NAMES = {
    "PECmd.exe",
    "MFTECmd.exe",
    "SBECmd.exe",
    "JLECmd.exe",
    "SrumECmd.exe",
    "AmcacheParser.exe",
    "AppCompatCacheParser.exe",
    "RECmd.exe",
    "RBCmd.exe",
    "EvtxECmd.exe",
    "LECmd.exe",
    "WxTCmd.exe",
    "RecentFileCacheParser.exe",
    "SQLECmd.exe",
}


def forensic_tool_dirs(config: dict | None = None) -> list[Path]:
    configured = str((config or {}).get("external_forensic_tools_dir") or "").strip()
    roots = []
    if configured:
        roots.append(Path(os.path.expandvars(configured)).expanduser())
    roots.extend([app_dir() / "Tools", app_dir()])
    deduped = []
    seen = set()
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(root)
    return deduped


def available_forensic_tools(config: dict | None = None) -> dict[str, Path]:
    found = {}
    for root in forensic_tool_dirs(config or {}):
        for name in FORENSIC_TOOL_NAMES:
            candidate = root / name
            if safe_exists(candidate) and name not in found:
                found[name] = candidate
                continue
            try:
                nested = next(root.rglob(name))
            except (OSError, StopIteration):
                nested = None
            if nested and safe_exists(nested) and name not in found:
                found[name] = nested
    return found


def run_forensic_tool(args: list[str], config: dict, timeout: int) -> str:
    try:
        write_app_log(config, "running forensic helper: " + " ".join(args[:4]))
    except Exception:
        pass
    return run_command(args, timeout=timeout)


def recmd_batch_file(tool_path: Path, name: str) -> Path | None:
    for base in [tool_path.parent / "BatchExamples", tool_path.parent]:
        candidate = base / name
        if safe_exists(candidate):
            return candidate
    return None


def windows_recent_root() -> Path:
    return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"


def activities_cache_dbs() -> list[Path]:
    base = Path(os.environ.get("LOCALAPPDATA", "")) / "ConnectedDevicesPlatform"
    if not safe_exists(base):
        return []
    try:
        return [path for path in base.rglob("ActivitiesCache.db") if path.is_file()]
    except OSError:
        return []


def selected_event_log_files() -> list[Path]:
    log_dir = Path("C:/Windows/System32/winevt/Logs")
    names = [
        "Microsoft-Windows-Windows Defender%4Operational.evtx",
        "Microsoft-Windows-Sysmon%4Operational.evtx",
        "Security.evtx",
        "System.evtx",
        "Application.evtx",
    ]
    return [log_dir / name for name in names if safe_exists(log_dir / name)]


def execute_external_forensic_tools(days: int, config: dict) -> list[str]:
    # Runs only known read-only parser tools, with short timeouts, into Securo's local ToolOutput folder.
    run_prefetch_parser = bool(config.get("prefetch_parser_enabled", True))
    run_shellbag_parser = bool(config.get("shellbag_parser_enabled", True))
    run_all_parsers = bool(config.get("external_forensic_tools_enabled"))
    if not run_prefetch_parser and not run_shellbag_parser and not run_all_parsers:
        return []
    tools = available_forensic_tools(config)
    if not tools:
        return []
    output_root = ensure_storage_dirs(config)["tool_output"] / now_stamp()
    output_root.mkdir(parents=True, exist_ok=True)
    timeout = max(10, int(config.get("external_forensic_tool_timeout_seconds") or 55))
    prefetch_timeout = max(8, int(config.get("prefetch_parser_timeout_seconds") or 25))
    shellbag_timeout = max(8, int(config.get("shellbag_parser_timeout_seconds") or 30))
    registry_timeout = max(10, int(config.get("registry_parser_timeout_seconds") or 45))
    eventlog_timeout = max(10, int(config.get("eventlog_parser_timeout_seconds") or 45))
    shortcut_timeout = max(8, int(config.get("shortcut_parser_timeout_seconds") or 30))
    recycle_timeout = max(8, int(config.get("recycle_parser_timeout_seconds") or 30))
    timeline_timeout = max(8, int(config.get("timeline_parser_timeout_seconds") or 35))
    notes = []

    def note(message: str):
        notes.append(message)
        write_app_log(config, message)

    prefetch_dir = Path(os.path.expandvars(str(config.get("prefetch_dir") or "C:/Windows/Prefetch"))).expanduser()
    if (run_prefetch_parser or run_all_parsers) and "PECmd.exe" in tools and safe_exists(prefetch_dir):
        out = run_forensic_tool([str(tools["PECmd.exe"]), "-d", str(prefetch_dir), "--csv", str(output_root)], config, prefetch_timeout)
        note("PECmd Prefetch parser completed." if "COMMAND_ERROR" not in out else f"PECmd Prefetch parser issue: {out[:180]}")

    if run_shellbag_parser and "SBECmd.exe" in tools:
        out = run_forensic_tool(
            [str(tools["SBECmd.exe"]), "-l", "--csv", str(output_root), "--csvf", "SBECmd_ShellBags.csv"],
            config,
            shellbag_timeout,
        )
        if "requires administrator" in out.lower():
            note("SBECmd ShellBag parser requires administrator access.")
        else:
            note("SBECmd live ShellBag parser completed." if "COMMAND_ERROR" not in out else f"SBECmd ShellBag parser issue: {out[:180]}")

    if not run_all_parsers:
        if notes:
            config["_external_forensic_output_dir"] = str(output_root)
        return notes

    mft_path = Path("C:/$MFT")
    if "MFTECmd.exe" in tools and safe_exists(mft_path):
        out = run_forensic_tool([str(tools["MFTECmd.exe"]), "-f", str(mft_path), "--csv", str(output_root)], config, timeout)
        note("MFTECmd MFT parser completed." if "COMMAND_ERROR" not in out else f"MFTECmd MFT parser issue: {out[:180]}")

    for root in jump_list_roots(config):
        if "JLECmd.exe" not in tools or not safe_exists(root):
            continue
        out = run_forensic_tool([str(tools["JLECmd.exe"]), "-d", str(root), "--csv", str(output_root)], config, timeout)
        note("JLECmd Jump List parser completed." if "COMMAND_ERROR" not in out else f"JLECmd Jump List parser issue: {out[:180]}")

    srum = Path("C:/Windows/System32/sru/SRUDB.dat")
    if "SrumECmd.exe" in tools and safe_exists(srum):
        out = run_forensic_tool([str(tools["SrumECmd.exe"]), "-f", str(srum), "--csv", str(output_root)], config, timeout)
        note("SrumECmd SRUM parser completed." if "COMMAND_ERROR" not in out else f"SrumECmd SRUM parser issue: {out[:180]}")

    amcache = Path(os.path.expandvars(str(config.get("amcache_path") or "C:/Windows/AppCompat/Programs/Amcache.hve"))).expanduser()
    if "AmcacheParser.exe" in tools and safe_exists(amcache):
        out = run_forensic_tool([str(tools["AmcacheParser.exe"]), "-f", str(amcache), "--csv", str(output_root)], config, timeout)
        note("AmcacheParser completed." if "COMMAND_ERROR" not in out else f"AmcacheParser issue: {out[:180]}")

    system_hive = Path("C:/Windows/System32/config/SYSTEM")
    if "AppCompatCacheParser.exe" in tools and safe_exists(system_hive):
        out = run_forensic_tool([str(tools["AppCompatCacheParser.exe"]), "-f", str(system_hive), "--csv", str(output_root)], config, timeout)
        note("AppCompatCacheParser completed." if "COMMAND_ERROR" not in out else f"AppCompatCacheParser issue: {out[:180]}")

    recycle_root = Path("C:/$Recycle.Bin")
    if config.get("recycle_parser_enabled", True) and "RBCmd.exe" in tools and safe_exists(recycle_root):
        out = run_forensic_tool([str(tools["RBCmd.exe"]), "-d", str(recycle_root), "--csv", str(output_root)], config, recycle_timeout)
        note("RBCmd Recycle Bin parser completed." if "COMMAND_ERROR" not in out else f"RBCmd Recycle Bin parser issue: {out[:180]}")

    recent_root = windows_recent_root()
    if config.get("shortcut_parser_enabled", True) and "LECmd.exe" in tools and safe_exists(recent_root):
        out = run_forensic_tool([str(tools["LECmd.exe"]), "-d", str(recent_root), "--csv", str(output_root)], config, shortcut_timeout)
        note("LECmd shortcut parser completed." if "COMMAND_ERROR" not in out else f"LECmd shortcut parser issue: {out[:180]}")

    recent_cache = Path("C:/Windows/AppCompat/Programs/RecentFileCache.bcf")
    if "RecentFileCacheParser.exe" in tools and safe_exists(recent_cache):
        out = run_forensic_tool([str(tools["RecentFileCacheParser.exe"]), "-f", str(recent_cache), "--csv", str(output_root)], config, timeout)
        note("RecentFileCacheParser completed." if "COMMAND_ERROR" not in out else f"RecentFileCacheParser issue: {out[:180]}")

    if config.get("timeline_parser_enabled", True) and "WxTCmd.exe" in tools:
        for db in activities_cache_dbs()[:3]:
            out = run_forensic_tool([str(tools["WxTCmd.exe"]), "-f", str(db), "--csv", str(output_root)], config, timeline_timeout)
            note("WxTCmd ActivitiesCache parser completed." if "COMMAND_ERROR" not in out else f"WxTCmd ActivitiesCache parser issue: {out[:180]}")

    if config.get("eventlog_parser_enabled", True) and "EvtxECmd.exe" in tools:
        for evtx in selected_event_log_files()[:5]:
            out = run_forensic_tool([str(tools["EvtxECmd.exe"]), "-f", str(evtx), "--csv", str(output_root)], config, eventlog_timeout)
            note(f"EvtxECmd parsed {evtx.name}." if "COMMAND_ERROR" not in out else f"EvtxECmd issue for {evtx.name}: {out[:180]}")

    if config.get("registry_parser_enabled", True) and "RECmd.exe" in tools:
        batch_files = [
            recmd_batch_file(tools["RECmd.exe"], "UserActivity.reb"),
            recmd_batch_file(tools["RECmd.exe"], "AllRegExecutablesFoundOrRun.reb"),
        ]
        for batch in [path for path in batch_files if path]:
            out = run_forensic_tool([str(tools["RECmd.exe"]), "-d", "C:/Users", "--bn", str(batch), "--csv", str(output_root)], config, registry_timeout)
            note(f"RECmd registry parser completed ({batch.name})." if "COMMAND_ERROR" not in out else f"RECmd registry parser issue ({batch.name}): {out[:180]}")

    if notes:
        config["_external_forensic_output_dir"] = str(output_root)
    return notes


def forensic_export_dirs(config: dict | None = None) -> list[Path]:
    configured = (config or {}).get("forensic_export_dirs") or []
    roots = [Path(os.path.expandvars(str(root))).expanduser() for root in configured]
    generated = (config or {}).get("_external_forensic_output_dir")
    if generated:
        roots.append(Path(os.path.expandvars(str(generated))).expanduser())
    roots.extend([
        storage_root(config or {}) / "ToolOutput",
        app_dir() / "ToolOutput",
    ])
    deduped = []
    seen = set()
    for root in roots:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(root)
    return deduped


def forensic_exports_available(config: dict | None = None) -> bool:
    for root in forensic_export_dirs(config or {}):
        try:
            if root.exists() and any(root.rglob("*.csv")):
                return True
        except OSError:
            continue
    return False


def forensic_export_family(path: Path, headers: list[str]) -> str:
    name = path.name.lower()
    header_text = " ".join(headers).lower()
    text = name + " " + header_text
    if "pecmd" in text or "prefetch" in text:
        return "PECmd"
    if "rbcmd" in text or "recycle" in text or "$i" in text:
        return "RBCmd"
    if "mftecmd" in text or "mft" in text or "deleted" in text:
        return "MFTECmd"
    if "sbecmd" in text or "shellbag" in text or "shell bag" in text:
        return "SBECmd"
    if "jlecmd" in text or "jumplist" in text or "jump list" in text:
        return "JLECmd"
    if "srum" in text:
        return "SrumECmd"
    if "amcache" in text:
        return "AmcacheParser"
    if "appcompat" in text or "shimcache" in text:
        return "AppCompatCacheParser"
    if "recmd" in text or "userassist" in text or "muicache" in text or "recentdocs" in text or "bam" in text or "dam" in text or "runmru" in text:
        return "RECmd"
    if "evtxecmd" in text or "evtx" in text or "eventlog" in text:
        return "EvtxECmd"
    if "lecmd" in text or "lnk" in text or "shortcut" in text:
        return "LECmd"
    if "wxtcmd" in text or "activitiescache" in text or "activity" in text:
        return "WxTCmd"
    if "recentfilecache" in text:
        return "RecentFileCacheParser"
    if "sqlecmd" in text:
        return "SQLECmd"
    return "Forensic Export"


def csv_value(row: dict, *names: str) -> str:
    folded = {str(k).strip().lower().replace(" ", "").replace("_", ""): v for k, v in row.items()}
    for name in names:
        key = name.strip().lower().replace(" ", "").replace("_", "")
        value = folded.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def forensic_row_time(row: dict) -> dt.datetime | None:
    for key in (
        "Timestamp", "Time", "Created", "Created0x10", "Modified", "LastModified", "LastModified0x30",
        "LastRun", "LastRun0", "LastRunTime", "LastWriteTime", "KeyLastWriteTimestamp",
        "SourceCreated", "SourceModified", "DeletedTime", "DeletionTime", "FirstInteracted",
        "LastInteracted", "CreatedOn", "ModifiedOn", "AccessedOn", "LastExecutionTime",
        "LastExecuted", "LastRunTimeUTC", "LastModifiedTime", "LastWriteTimestamp",
        "CreationTime", "ModifiedTime", "AccessedTime", "EventTime", "ActivityTime",
    ):
        parsed = parse_dt(csv_value(row, key))
        if parsed:
            return parsed
    return None


def forensic_row_path(row: dict) -> str:
    for key in (
        "FullPath", "Path", "FilePath", "TargetPath", "LocalPath", "ExecutablePath",
        "ProgramPath", "ApplicationPath", "Name", "Filename", "FileName", "ExecutableName",
        "SourceFile", "SourceFilename", "Application", "AppId", "AbsolutePath", "FolderPath",
        "FolderName", "Value", "Target", "TargetName", "TargetPath", "CommandLine",
        "Executable", "ProgramName", "ItemName", "File", "Data", "ValueData", "Details",
    ):
        value = csv_value(row, key)
        if value:
            return value
    return ""


def forensic_row_deleted(row: dict) -> bool:
    text = " ".join(str(v) for v in row.values()).lower()
    if any(marker in text for marker in ("isdeleted=true", "deleted=true", " in use=false")):
        return True
    for key in ("IsDeleted", "Deleted", "FileDeleted", "DeletedTime", "DeletionTime"):
        value = csv_value(row, key).lower()
        if value in {"true", "yes", "1", "deleted"} or (key.lower().endswith("time") and value):
            return True
    return False


def collect_external_forensic_exports(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Optional CSV exports from common forensic tools give Securo stronger artifact coverage without slow full-disk brute force.
    findings = {}
    timeline = []
    cut = cutoff(days)
    max_files = int(config.get("forensic_export_max_files") or 80)
    max_rows = int(config.get("forensic_export_max_rows") or 5000)
    scanned_files = 0
    scanned_rows = 0
    for root in forensic_export_dirs(config):
        if not safe_exists(root):
            continue
        try:
            csv_files = sorted(root.rglob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            continue
        for csv_path in csv_files:
            if scanned_files >= max_files or scanned_rows >= max_rows:
                break
            scanned_files += 1
            try:
                with csv_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
                    reader = csv.DictReader(f)
                    headers = list(reader.fieldnames or [])
                    family = forensic_export_family(csv_path, headers)
                    if family == "SBECmd":
                        continue
                    for row in reader:
                        if scanned_rows >= max_rows:
                            break
                        scanned_rows += 1
                        when = forensic_row_time(row)
                        if when and when < cut:
                            continue
                        path_text = forensic_row_path(row)
                        row_blob = " ".join([str(csv_path), family, path_text] + [str(v) for v in row.values()])
                        if not path_text and not suspicious_text(row_blob, config) and not ioc_text_matches(row_blob, config):
                            continue

                        is_prefetch = family == "PECmd" or path_text.lower().endswith(".pf") or "prefetch" in row_blob.lower()
                        is_deleted = forensic_row_deleted(row) or family == "RBCmd"
                        is_suspicious = (
                            suspicious_text(row_blob, config)
                            or bool(ioc_text_matches(row_blob, config))
                            or (path_text and user_writable_path(path_text) and suspicious_extension(path_text, config))
                            or is_deleted
                            or is_prefetch
                        )
                        if family not in {"PECmd", "MFTECmd"} and not is_suspicious:
                            continue

                        source = f"{family} Export"
                        name = Path(path_text).name if path_text else source
                        reason = f"{source} row references {path_text or 'artifact context'}"
                        finding = make_possible_context_finding(path_text or str(csv_path), name, source, reason, when, config)
                        finding["supporting_evidence"].append(f"Forensic export CSV: {csv_path}")
                        finding["supporting_evidence"].append(f"Forensic export source: {family}")
                        finding["evidence_types"].append("external_forensic_export")
                        if is_prefetch:
                            exe = prefetch_executable_name(name) if name.lower().endswith(".pf") else name
                            add_detection(finding, "PREFETCH", "External PECmd/Prefetch export indicates this executable ran.", "Info", 5)
                            finding["supporting_evidence"].append(f"PREFETCH FILE: {exe}")
                            finding["evidence_types"].append("prefetch_execution")
                            confirmed, reason = prefetch_confirmation_match(exe, [path_text] if path_text else [], [row_blob], config)
                            if confirmed:
                                add_detection(finding, "Confirmed Prefetch Exploit", reason, "High Risk", 70)
                                finding["evidence_types"].append("prefetch_confirmed_indicator")
                            timeline.append({"time": finding["first_seen"], "source": source, "text": f"PREFETCH FILE: {exe} from {csv_path.name}"})
                        if is_deleted:
                            add_detection(finding, "File Deletion", "External forensic export indicates this file was deleted.", "Info", 5)
                            finding["supporting_evidence"].append(f"DELETED FILE: {path_text or name}")
                            finding["evidence_types"].append("recovery")
                            timeline.append({"time": finding["first_seen"], "source": source, "text": f"DELETED FILE: {path_text or name}"})
                        if family == "MFTECmd" and is_deleted and (suspicious_text(row_blob, config) or ioc_text_matches(row_blob, config)):
                            add_detection(finding, "Suspicious File Deletion/Execution/Modification", "MFT export shows a suspicious deleted or modified file artifact.", "High", 30)
                            finding["evidence_types"].append("executed_deleted")
                        if family == "SBECmd":
                            add_detection(finding, "ShellBag Analyzer Context", "ShellBag export shows folder browsing context for a suspicious or review-worthy path.", "Medium", 15)
                            finding["evidence_types"].append("shellbag_context")
                        elif family == "JLECmd":
                            add_detection(finding, "Jump List Recent Item Context", "Jump List export referenced a suspicious or review-worthy recent item.", "Medium", 15)
                            finding["evidence_types"].append("jump_list_context")
                        elif family == "SrumECmd":
                            add_detection(finding, "SRUM App/Network Usage Context", "SRUM export referenced app or network usage context for a suspicious item.", "Medium", 15)
                            finding["evidence_types"].append("srum_context")
                        elif family == "AmcacheParser":
                            add_detection(finding, "Amcache Execution/Install Context", "Amcache export referenced execution or install context.", "Medium", 20)
                            finding["evidence_types"].append("amcache_context")
                        elif family == "AppCompatCacheParser":
                            add_detection(finding, "ShimCache/AppCompat Context", "AppCompat/ShimCache export referenced execution compatibility context.", "Medium", 20)
                            finding["evidence_types"].append("appcompat_context")
                        elif family == "RECmd":
                            add_detection(finding, "Registry User Activity Context", "RECmd registry export referenced user activity or execution-related registry artifacts.", "Medium", 20)
                            finding["evidence_types"].append("registry_user_activity")
                        elif family == "RBCmd":
                            add_detection(finding, "Recycle Bin Parser Artifact", "RBCmd export provided structured deleted-file metadata.", "Info", 10)
                            finding["evidence_types"].append("recycle_bin_parser")
                        elif family == "EvtxECmd":
                            add_detection(finding, "Event Log Parser Context", "EvtxECmd export referenced security, Defender, Sysmon, or Windows event-log context.", "Medium", 20)
                            finding["evidence_types"].append("eventlog_parser")
                        elif family == "LECmd":
                            add_detection(finding, "Shortcut / LNK Context", "LECmd export referenced shortcut/opened-file context for a suspicious or review-worthy path.", "Medium", 15)
                            finding["evidence_types"].append("lnk_context")
                        elif family == "WxTCmd":
                            add_detection(finding, "ActivitiesCache Timeline Context", "WxTCmd export referenced Windows Timeline/ActivitiesCache activity context.", "Medium", 15)
                            finding["evidence_types"].append("activitiescache_context")
                        elif family == "RecentFileCacheParser":
                            add_detection(finding, "RecentFileCache Context", "RecentFileCache export referenced a recently seen executable path.", "Medium", 15)
                            finding["evidence_types"].append("recentfilecache_context")
                        elif family == "SQLECmd":
                            add_detection(finding, "SQLite Artifact Context", "SQLECmd export referenced scoped SQLite activity/download metadata.", "Medium", 10)
                            finding["evidence_types"].append("sqlite_artifact_context")
                        if near_any_session(when, sessions):
                            add_score(finding, config["score_rules"].get("near_roblox_session", 25), f"{family} export timestamp is near Roblox activity")
                        apply_ioc_matches(finding, config, row_blob)
                        merge_findings(findings, finding)
                        if not is_prefetch and not is_deleted:
                            timeline.append({"time": finding["first_seen"], "source": source, "text": reason})
            except (OSError, csv.Error):
                continue
    return list(findings.values()), timeline


def shellbag_artifact_classification(path_text: str, shell_type: str) -> str:
    text = f"{path_text} {shell_type}".lower()
    if path_text.startswith("\\\\") or any(term in text for term in ("network", "removable", "external", "usb")):
        return "Network / External Folder"
    if re.match(r"^[A-Za-z]:[\\/]", path_text):
        try:
            return "Existing Folder" if Path(path_text).exists() else "Old / Deleted Folder"
        except OSError:
            return "Old / Deleted Folder"
    return "System / Shell Namespace"


def collect_sbecmd_shellbags(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    # SBECmd reads live ShellBag registry data and exports reconstructed paths without modifying the registry.
    findings = {}
    timeline = []
    artifacts = []
    seen = set()
    cut = cutoff(days)
    max_records = max(100, int(config.get("shellbag_max_records") or 5000))
    csv_files = []
    for root in forensic_export_dirs(config):
        if not safe_exists(root):
            continue
        try:
            csv_files.extend(
                path for path in root.rglob("*.csv")
                if "sbecmd" in path.name.lower() or "shellbag" in path.name.lower()
            )
        except OSError:
            continue
    try:
        csv_files = sorted(set(csv_files), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        pass
    for csv_path in csv_files[:20]:
        if len(artifacts) >= max_records:
            break
        try:
            with csv_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
                for row in csv.DictReader(handle):
                    if len(artifacts) >= max_records:
                        break
                    when = forensic_row_time(row)
                    if when and when < cut:
                        continue
                    path_text = (
                        csv_value(row, "AbsolutePath", "FolderPath", "Path", "FullPath")
                        or csv_value(row, "FolderName", "Value", "Name")
                    )
                    if not path_text:
                        continue
                    shell_type = csv_value(row, "ShellType", "Type", "BagType")
                    source_hive = csv_value(row, "SourceFile", "SourceFilename", "HivePath")
                    first_interacted = csv_value(row, "FirstInteracted", "CreatedOn", "Created")
                    last_interacted = csv_value(row, "LastInteracted", "ModifiedOn", "LastWriteTime")
                    slot = csv_value(row, "Slot", "NodeSlot")
                    mru = csv_value(row, "MruPosition", "MRUPosition", "MRU")
                    classification = shellbag_artifact_classification(path_text, shell_type)
                    stamp = when.isoformat(sep=" ", timespec="seconds") if when else (last_interacted or first_interacted)
                    identity = (path_text.lower(), stamp, source_hive.lower())
                    if identity in seen:
                        continue
                    seen.add(identity)
                    artifact = {
                        "path": path_text,
                        "classification": classification,
                        "shellType": shell_type,
                        "timestamp": stamp,
                        "firstInteracted": first_interacted,
                        "lastInteracted": last_interacted,
                        "slot": slot,
                        "mruPosition": mru,
                        "sourceHive": source_hive,
                        "sourceExport": str(csv_path),
                        "manualReviewRequired": classification != "Existing Folder",
                    }
                    artifacts.append(artifact)
                    suspicious = suspicious_text(path_text, config) or bool(ioc_text_matches(path_text, config))
                    if not suspicious:
                        continue
                    reason = f"SBECmd ShellBag path requires review: {path_text} ({classification})"
                    finding = make_possible_context_finding(
                        path_text,
                        Path(path_text).name or "ShellBag path",
                        "ShellBag Analyzer",
                        reason,
                        when or parse_dt(stamp),
                        config,
                    )
                    finding["evidence_types"].append("shellbag_context")
                    finding["supporting_evidence"].append(f"SBECmd source hive: {source_hive or 'live registry'}")
                    add_detection(finding, "ShellBag Analyzer Context", reason, "Medium", 15)
                    if classification == "Old / Deleted Folder":
                        add_detection(finding, "Old / Deleted Folder Trace", "ShellBag retained a suspicious folder path that is no longer present.", "Medium", 15)
                    elif classification == "Network / External Folder":
                        add_detection(finding, "Network / External Folder Trace", "ShellBag retained a suspicious network or external-device folder path.", "Medium", 15)
                    if near_any_session(stamp, sessions):
                        add_score(finding, config["score_rules"].get("near_roblox_session", 25), "ShellBag interaction timestamp is near Roblox activity")
                    merge_findings(findings, finding)
                    timeline.append({
                        "time": finding["first_seen"],
                        "source": "SBECmd ShellBag",
                        "text": f"ShellBag {classification}: {path_text}",
                    })
        except (OSError, csv.Error):
            continue
    return list(findings.values()), timeline, artifacts


def extract_artifact_strings(path: Path, max_bytes: int = 2_000_000) -> dict:
    info = {"referenced_paths": [], "strings": [], "size": 0}
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        info["size"] = len(data)
    except OSError:
        return info
    texts = []
    for encoding in ("utf-16-le", "latin1"):
        for blob in (data, data[1:]):
            try:
                texts.append(blob.decode(encoding, errors="ignore"))
            except Exception:
                continue
    joined = "\n".join(texts)
    path_pattern = r"(?:[A-Za-z]:\\|\\\\|\\Device\\HarddiskVolume\d+\\)[^\x00\r\n\t\"<>|]{3,260}"
    paths = []
    for match in re.finditer(path_pattern, joined, re.I):
        value = match.group(0).strip()
        if value and len(value) <= 260:
            paths.append(value)
    string_hits = []
    suspicious_terms = list(EXPLOIT_FAMILY_TERMS) + ["inject", "loader", "executor", "bypass", "roblox", "dll", "powershell"]
    for token in re.findall(r"[A-Za-z0-9_ .:\\/()$%#@+\-]{5,160}", joined):
        if suspicious_text(token, {"suspicious_name_terms": suspicious_terms}):
            string_hits.append(token.strip())
    info["referenced_paths"] = sorted(set(paths))[:80]
    info["strings"] = sorted(set(s for s in string_hits if s))[:40]
    return info


def evidence_quality(days: int) -> dict:
    sysmon_exists = event_log_exists("Microsoft-Windows-Sysmon/Operational")
    security_exists = event_log_exists("Security")
    defender_exists = event_log_exists("Microsoft-Windows-Windows Defender/Operational")
    prefetch = prefetch_inventory({})
    usn_state = query_usn_journal_state("C:") if os.name == "nt" else {"available": False}
    q = {
        "Sysmon installed": sysmon_exists,
        "Sysmon Event ID 1 available": False,
        "Sysmon Event ID 7 available": False,
        "Sysmon Event ID 8 available": False,
        "Sysmon Event ID 10 available": False,
        "Security 4688 available": False,
        "Security 4688 command line available": False,
        "Prefetch available": bool(prefetch.get("readable")),
        "Prefetch enabled": prefetch.get("enabled"),
        "Prefetch administrator access": prefetch.get("administrator"),
        "Prefetch file count": prefetch.get("count", 0),
        "Prefetch oldest entry": prefetch.get("oldest", ""),
        "Prefetch newest entry": prefetch.get("newest", ""),
        "USN Change Journal available": bool(usn_state.get("available")),
        "Amcache available": safe_exists(Path("C:/Windows/AppCompat/Programs/Amcache.hve")),
        "Jump Lists available": any(safe_exists(path) for path in jump_list_roots({})),
        "SRUM database available": safe_exists(Path("C:/Windows/System32/sru/SRUDB.dat")),
        "AppCompat/ShimCache hive available": safe_exists(Path("C:/Windows/System32/config/SYSTEM")),
        "MFT direct access available": safe_exists(Path("C:/$MFT")),
        "External forensic parser tools bundled": forensic_parser_tools_available(),
        "External forensic parser exports available": forensic_exports_available({}),
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
            apply_ioc_matches(findings[key], config)
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


def prefetch_executable_name(pf_name: str) -> str:
    name = Path(pf_name).name
    match = re.match(r"^(.+?\.exe)-[0-9A-F]{6,}\.pf$", name, re.I)
    if match:
        return match.group(1)
    stem = Path(name).stem
    if "-" in stem:
        return stem.rsplit("-", 1)[0] + ".exe"
    return stem + ".exe"


def is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_windows_admin() -> bool:
    """Relaunch the GUI through Windows UAC before any scan UI is created."""
    if os.name != "nt" or is_windows_admin():
        return True
    try:
        import ctypes

        if getattr(sys, "frozen", False):
            executable = sys.executable
            arguments = list(sys.argv[1:])
        else:
            executable = sys.executable
            arguments = [str(Path(__file__).resolve()), *sys.argv[1:]]
        parameters = subprocess.list2cmdline(arguments)
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            parameters,
            str(app_dir()),
            1,
        )
        if int(result) > 32:
            return False
        ctypes.windll.user32.MessageBoxW(
            None,
            "Securo requires administrator access to inspect Windows Prefetch and protected forensic artifacts.",
            "Securo",
            0x10,
        )
    except Exception as exc:
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                f"Securo could not request administrator access.\n\n{exc}",
                "Securo",
                0x10,
            )
        except Exception:
            pass
    return False


def prefetch_registry_enabled() -> bool | None:
    out = run_command(
        [
            "reg",
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            "/v",
            "EnablePrefetcher",
        ],
        timeout=3,
    )
    match = re.search(r"EnablePrefetcher\s+REG_DWORD\s+(0x[0-9a-f]+|\d+)", out, re.I)
    if not match:
        return None
    try:
        value = int(match.group(1), 16 if match.group(1).lower().startswith("0x") else 10)
    except ValueError:
        return None
    return value != 0


def windows_install_time() -> dt.datetime | None:
    out = run_command(
        ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "/v", "InstallDate"],
        timeout=3,
    )
    match = re.search(r"InstallDate\s+REG_DWORD\s+(0x[0-9a-f]+|\d+)", out, re.I)
    if not match:
        return None
    try:
        value = int(match.group(1), 16 if match.group(1).lower().startswith("0x") else 10)
        return dt.datetime.fromtimestamp(value)
    except (ValueError, OSError, OverflowError):
        return None


def prefetch_inventory(config: dict | None = None) -> dict:
    folder = Path(os.path.expandvars(str((config or {}).get("prefetch_dir") or "C:/Windows/Prefetch"))).expanduser()
    result = {
        "path": str(folder),
        "exists": safe_exists(folder),
        "readable": False,
        "enabled": prefetch_registry_enabled(),
        "administrator": is_windows_admin(),
        "count": 0,
        "oldest": "",
        "newest": "",
        "installGapDays": None,
        "error": "",
    }
    if not result["exists"]:
        result["error"] = "Prefetch directory does not exist."
        return result
    try:
        entries = list(folder.glob("*.pf"))
        result["count"] = len(entries)
        timestamps = []
        for entry in entries:
            try:
                timestamps.append(dt.datetime.fromtimestamp(entry.stat().st_mtime))
            except OSError:
                continue
        result["readable"] = bool(entries)
        if timestamps:
            oldest = min(timestamps)
            newest = max(timestamps)
            result["oldest"] = oldest.isoformat(sep=" ", timespec="seconds")
            result["newest"] = newest.isoformat(sep=" ", timespec="seconds")
            installed = windows_install_time()
            if installed:
                result["installGapDays"] = max(0, (oldest.date() - installed.date()).days)
        elif not result["administrator"]:
            result["error"] = "No Prefetch files were readable without administrator access."
        else:
            result["error"] = "Prefetch directory is empty."
    except (OSError, PermissionError) as exc:
        result["error"] = f"Prefetch access failed: {exc}"
    return result


def parse_prefetch_artifact(path: Path) -> dict:
    # This is intentionally heuristic: it reads Prefetch metadata and embedded strings without modifying anything.
    info = {"referenced_paths": [], "strings": [], "size": 0}
    try:
        data = path.read_bytes()
        info["size"] = len(data)
    except OSError:
        return info
    texts = []
    for encoding in ("utf-16-le", "latin1"):
        for blob in (data, data[1:]):
            try:
                decoded = blob.decode(encoding, errors="ignore")
            except Exception:
                continue
            texts.append(decoded)
    joined = "\n".join(texts)
    path_pattern = r"(?:[A-Za-z]:\\|\\\\|\\Device\\HarddiskVolume\d+\\)[^\x00\r\n\t\"<>|]{3,260}"
    paths = []
    for match in re.finditer(path_pattern, joined, re.I):
        value = match.group(0).strip()
        if not value or len(value) > 260:
            continue
        if not re.search(r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|ahk|jar|zip|rar|7z)\b", value, re.I):
            continue
        paths.append(value)
    string_hits = []
    for token in re.findall(r"[A-Za-z0-9_ .:\\/()$%-]{5,120}", joined):
        if suspicious_text(token, {"suspicious_name_terms": list(EXPLOIT_FAMILY_TERMS) + ["inject", "loader", "executor", "bypass", "roblox"]}):
            string_hits.append(token.strip())
    info["referenced_paths"] = sorted(set(paths))[:40]
    info["strings"] = sorted(set(s for s in string_hits if s))[:20]
    return info


def collect_running_processes(config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Live process inventory is read-only and captures path/hash/signer/command-line context.
    findings = {}
    timeline = []
    out = run_command(["wmic", "process", "get", "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine", "/format:csv"], timeout=25)
    try:
        rows = list(csv.DictReader(line for line in out.splitlines() if line.strip()))
    except Exception:
        rows = []
    roblox_running = any(ROBLOX_EXE.lower() in (row.get("Name", "") or "").lower() for row in rows)
    for row in rows:
        name = row.get("Name", "") or ""
        path = row.get("ExecutablePath", "") or ""
        command = row.get("CommandLine", "") or ""
        text = " ".join([name, path, command])
        ioc_hit = bool(ioc_text_matches(text, config))
        if not (suspicious_text(text, config) or ioc_hit or risky_source_path(path)):
            continue
        finding = make_finding(path, name or "Running process", "running_process", config)
        finding["first_seen"] = iso_now()
        finding["parent_process"] = row.get("ParentProcessId", "")
        finding["process_id"] = row.get("ProcessId", "")
        finding["command_line"] = command[:1000]
        finding["supporting_evidence"].append(f"Running process pid={row.get('ProcessId', '')} ppid={row.get('ParentProcessId', '')} command={command[:500]}")
        finding["evidence_types"].append("running_process")
        if finding.get("signer", {}).get("status", "").lower() in {"notsigned", "unknown", "missing"}:
            add_detection(finding, "Executed Suspicious File", "Running unsigned or unverifiable process in suspicious context.", "High", 25)
        if roblox_running and (suspicious_text(text, config) or ioc_hit):
            add_score(finding, config["score_rules"].get("executor_behavior", 30), "Suspicious process was running while Roblox was present")
            finding["supporting_evidence"].append(f"{ROBLOX_EXE} was present in the live process list during scan.")
        apply_ioc_matches(finding, config, command)
        merge_findings(findings, finding)
        timeline.append({"time": finding["first_seen"], "source": "Running process", "text": f"Suspicious running process observed: {name or path}"})
    return finalize_findings(list(findings.values()), config), timeline


def collect_network_ioc_evidence(config: dict) -> tuple[list[dict], list[dict]]:
    # Network collection only checks live connection metadata against configured IOC domains/IPs.
    indicators = {str(value).lower() for value in ioc_values(config, "domains") + ioc_values(config, "ips") if str(value).strip()}
    if not indicators:
        return [], []
    findings = {}
    timeline = []
    out = run_command(["netstat", "-ano"], timeout=15)
    when = iso_now()
    for line in out.splitlines():
        low = line.lower()
        matched = [ioc for ioc in indicators if ioc in low]
        if not matched:
            continue
        parts = line.split()
        pid = parts[-1] if parts and parts[-1].isdigit() else ""
        finding = make_finding("", f"Network connection PID {pid or 'unknown'}", "network_ioc", config)
        finding["first_seen"] = when
        finding["process_id"] = pid
        finding["supporting_evidence"].append(f"netstat: {line}")
        finding["evidence_types"].append("network_connection")
        for ioc in matched:
            add_detection(finding, "Known-Bad Network IOC", f"Network connection matched external IOC: {ioc}", "High Risk", 40)
        merge_findings(findings, finding)
        timeline.append({"time": when, "source": "Network IOC", "text": f"Network connection matched IOC: {', '.join(matched)}"})
    return finalize_findings(list(findings.values()), config), timeline


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
    folder = Path(config.get("prefetch_dir") or "C:/Windows/Prefetch")
    inventory = prefetch_inventory(config)
    config["_prefetch_inventory"] = inventory
    if not inventory.get("readable"):
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
        exe_name = prefetch_executable_name(pf.name)
        if ROBLOX_EXE.lower().replace(".exe", "") in pf.name.lower():
            roblox_times.append(mtime)
            timeline.append({"time": mtime.isoformat(sep=" ", timespec="seconds"), "source": "Prefetch", "text": f"Prefetch execution hint for {ROBLOX_EXE}"})
    suspicious_prefetch_by_name = defaultdict(int)
    for pf in entries:
        try:
            mtime = dt.datetime.fromtimestamp(pf.stat().st_mtime)
        except OSError:
            continue
        if mtime < cut:
            continue
        exe_name = prefetch_executable_name(pf.name)
        parsed = parse_prefetch_artifact(pf)
        referenced_paths = parsed.get("referenced_paths", [])
        executor_terms = [str(term).lower() for term in config.get("executor_confirmation_keywords", []) if str(term).strip()]
        matched_paths = [
            item for item in referenced_paths
            if suspicious_text(item, config)
            or ioc_text_matches(item, config)
            or any(term in item.lower() for term in executor_terms)
            or (user_writable_path(item) and suspicious_extension(item, config))
        ]
        matched_paths = sorted(matched_paths, key=lambda item: (Path(item).suffix.lower() != ".exe", item.lower()))
        text_blob = " ".join([pf.name, exe_name] + referenced_paths + parsed.get("strings", []))
        ioc_hit = bool(ioc_text_matches(text_blob, config))
        executor_prefetch_hit = any(term in text_blob.lower() for term in executor_terms)
        suspicious_hit = suspicious_name(exe_name, config) or suspicious_text(text_blob, config) or executor_prefetch_hit or bool(matched_paths) or ioc_hit
        if suspicious_hit:
            suspicious_prefetch_by_name[exe_name.lower()] += 1
        near = find_near_roblox_launch(mtime, roblox_times) or near_any_session(mtime, sessions)
        primary_path = matched_paths[0] if matched_paths else ""
        finding = make_finding(primary_path, exe_name, "prefetch", config)
        finding["first_seen"] = mtime.isoformat(sep=" ", timespec="seconds")
        add_detection(finding, "PREFETCH", "Prefetch indicates this executable ran.", "Info", 5)
        confirmed_prefetch, confirmed_reason = prefetch_confirmation_match(
            exe_name,
            referenced_paths,
            parsed.get("strings", []),
            config,
        )
        if confirmed_prefetch:
            add_detection(finding, "Confirmed Prefetch Exploit", confirmed_reason, "High Risk", 70)
            finding["evidence_types"].append("prefetch_confirmed_indicator")
        if suspicious_hit:
            add_score(finding, config["score_rules"]["prefetch_execution"], "Prefetch indicates suspicious executable ran")
            add_detection(finding, "Executed Suspicious File", "Prefetch indicates a suspicious executable or script was executed.", "High", 25)
        if near:
            add_score(finding, config["score_rules"]["near_roblox_session"], "Prefetch timestamp is within 30 minutes of Roblox activity")
        finding["supporting_evidence"].append(f"PREFETCH FILE: {exe_name}")
        finding["supporting_evidence"].append(f"Prefetch artifact: {pf}")
        if referenced_paths:
            finding["supporting_evidence"].append("Prefetch referenced paths: " + "; ".join(referenced_paths[:8]))
        if parsed.get("strings"):
            finding["supporting_evidence"].append("Prefetch suspicious strings: " + "; ".join(parsed.get("strings", [])[:8]))
        finding["evidence_types"].append("prefetch_execution")
        if matched_paths:
            finding["evidence_types"].append("prefetch_path_context")
        for path_text in matched_paths[:4]:
            if re.match(r"^[A-Za-z]:\\", path_text) and not Path(path_text).exists():
                add_detection(finding, "Executed & Deleted", f"Prefetch references suspicious executable path that is no longer present: {path_text}", "High", 35)
                finding["evidence_types"].append("executed_deleted")
                break
        apply_ioc_matches(finding, config, text_blob)
        merge_findings(findings, finding)
        timeline_text = f"PREFETCH FILE: {exe_name} from {pf.name}"
        if suspicious_hit:
            timeline_text = f"PREFETCH FILE: {exe_name} from {pf.name} (suspicious execution)"
        timeline.append({"time": finding["first_seen"], "source": "Prefetch", "text": timeline_text})
    for finding in findings.values():
        count = suspicious_prefetch_by_name.get(str(finding.get("name", "")).lower(), 0)
        if count >= 3:
            add_detection(finding, "Duplicate Prefetch Behavior", f"Multiple Prefetch variants were present for the same suspicious executable name ({count}).", "Medium", 15)
            finding["evidence_types"].append("duplicate_prefetch")
    return list(findings.values()), timeline


def query_usn_journal_state(volume: str = "C:") -> dict:
    out = run_command(["fsutil", "usn", "queryJournal", volume], timeout=5)
    state = {"available": False, "volume": volume, "firstUsn": 0, "nextUsn": 0, "error": ""}
    if "COMMAND_ERROR" in out or re.search(r"(access is denied|error \d+)", out, re.I):
        state["error"] = out.strip()[:300]
        return state
    first = re.search(r"First\s*Usn\s*:\s*(0x[0-9a-f]+|\d+)", out, re.I)
    next_value = re.search(r"Next\s*Usn\s*:\s*(0x[0-9a-f]+|\d+)", out, re.I)
    try:
        if first:
            state["firstUsn"] = int(first.group(1), 0)
        if next_value:
            state["nextUsn"] = int(next_value.group(1), 0)
    except ValueError:
        state["error"] = "USN journal boundaries could not be parsed."
        return state
    state["available"] = state["nextUsn"] > 0
    if not state["available"]:
        state["error"] = "USN journal was not available on this volume."
    return state


def parse_usn_timestamp(value: str) -> dt.datetime | None:
    parsed = parse_dt(value)
    if parsed:
        return parsed
    clean = str(value or "").strip().strip('"')
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S.%f"):
        try:
            return dt.datetime.strptime(clean, fmt)
        except ValueError:
            continue
    return None


def usn_event_type(reason: str) -> str:
    low = str(reason or "").lower().replace("_", " ")
    if "delete" in low:
        return "Deleted"
    if "rename" in low:
        return "Renamed"
    if "create" in low:
        return "Created"
    if any(term in low for term in ("overwrite", "extend", "truncation", "basic info", "security change", "compression change", "reparse point change")):
        return "Modified"
    return "Changed"


def parse_usn_journal_csv(text: str, volume: str, max_records: int, days: int) -> list[dict]:
    events = []
    cut = cutoff(days)
    reader = csv.DictReader(line for line in text.lstrip("\ufeff").splitlines() if line.strip())
    if not reader.fieldnames:
        return events
    for row in reader:
        if len(events) >= max_records:
            break
        name = csv_value(row, "File name", "FileName", "Name", "SourceFilename", "FullPath", "Path")
        if not name:
            continue
        timestamp_text = csv_value(row, "Time stamp", "Timestamp", "TimeStamp", "Time")
        when = parse_usn_timestamp(timestamp_text)
        if when and when < cut:
            continue
        reason = csv_value(row, "Reason", "Reasons", "ChangeReason")
        file_id = csv_value(row, "File ID", "FileId", "FileReferenceNumber", "FRN")
        parent_id = csv_value(row, "Parent file ID", "ParentFileId", "ParentFileReferenceNumber", "ParentFRN")
        usn = csv_value(row, "USN", "UpdateSequenceNumber")
        display_path = name if re.match(r"^[A-Za-z]:[\\/]", name) else f"{volume}\\{name}"
        events.append({
            "timestamp": when.isoformat(sep=" ", timespec="seconds") if when else timestamp_text,
            "eventType": usn_event_type(reason),
            "fileName": Path(name).name or name,
            "path": display_path,
            "reason": reason,
            "usn": usn,
            "fileId": file_id,
            "parentFileId": parent_id,
            "volume": volume,
            "source": "NTFS USN Change Journal",
        })
    return events


def parse_usn_journal_text(text: str, volume: str, max_records: int, days: int) -> list[dict]:
    events = []
    cut = cutoff(days)
    current = {}

    def finish():
        if len(events) >= max_records:
            return
        name = current.get("filename", "")
        if not name:
            return
        when = parse_usn_timestamp(current.get("timestamp", ""))
        if when and when < cut:
            return
        reason = current.get("reason", "")
        display_path = name if re.match(r"^[A-Za-z]:[\\/]", name) else f"{volume}\\{name}"
        events.append({
            "timestamp": when.isoformat(sep=" ", timespec="seconds") if when else current.get("timestamp", ""),
            "eventType": usn_event_type(reason),
            "fileName": Path(name).name or name,
            "path": display_path,
            "reason": reason,
            "usn": current.get("usn", ""),
            "fileId": current.get("fileid", ""),
            "parentFileId": current.get("parentfileid", ""),
            "volume": volume,
            "source": "NTFS USN Change Journal",
        })

    aliases = {
        "filename": {"filename", "name"},
        "timestamp": {"timestamp", "time"},
        "reason": {"reason", "reasons", "changereason"},
        "usn": {"usn", "updatesequencenumber"},
        "fileid": {"fileid", "fileref", "filereference", "filereferencenumber", "frn"},
        "parentfileid": {"parentfileid", "parentfileref", "parentfilereference", "parentfilereferencenumber", "parentfrn"},
    }
    for raw_line in text.lstrip("\ufeff").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        label, value = line.split(":", 1)
        normalized = re.sub(r"[^a-z0-9]+", "", label.lower())
        target = next((key for key, names in aliases.items() if normalized in names), "")
        if not target:
            continue
        if target in {"usn", "filename"} and current.get("filename") and (target == "usn" or normalized == "filename"):
            finish()
            current = {}
            if len(events) >= max_records:
                break
        current[target] = value.strip()
    if len(events) < max_records:
        finish()
    return events


def collect_usn_journal_events(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    # The USN journal is a bounded, read-only source of recent NTFS create/delete/rename/modify activity.
    if not config.get("usn_journal_enabled", True) or os.name != "nt":
        return [], [], []
    volume = str(config.get("usn_journal_volume") or "C:").rstrip("\\/")
    state = query_usn_journal_state(volume)
    config["_usn_journal_status"] = state
    if not state.get("available"):
        return [], [], []
    window = max(64_000, int(config.get("usn_journal_window_bytes") or 4_000_000))
    max_records = max(100, int(config.get("usn_journal_max_records") or 5000))
    timeout = max(3, int(config.get("usn_journal_timeout_seconds") or 12))
    start_usn = max(int(state.get("firstUsn") or 0), int(state.get("nextUsn") or 0) - window)
    read_errors = []
    output = ""
    for args in (
        ["fsutil", "usn", "readJournal", volume, f"startUsn=0x{start_usn:x}", "csv"],
        ["fsutil", "usn", "readJournal", volume, "csv", f"startUsn=0x{start_usn:x}"],
    ):
        output = run_command(args, timeout=timeout)
        if "COMMAND_ERROR" not in output and not re.search(r"(access is denied|error \d+|invalid parameter|invalid syntax)", output, re.I):
            state["readCommand"] = " ".join(args)
            break
        read_errors.append(output.strip()[:240])
    if "COMMAND_ERROR" in output or re.search(r"(access is denied|error \d+)", output, re.I):
        state["error"] = " | ".join(error for error in read_errors if error)[:500] or output.strip()[:300]
        state["readable"] = False
        return [], [], []
    events = parse_usn_journal_csv(output, volume, max_records, days)
    if not events:
        for args in (
            ["fsutil", "usn", "readJournal", volume, f"startUsn=0x{start_usn:x}"],
            ["fsutil", "usn", "readJournal", volume],
        ):
            plain_output = run_command(args, timeout=timeout)
            if "COMMAND_ERROR" not in plain_output and not re.search(r"(access is denied|error \d+|invalid parameter|invalid syntax)", plain_output, re.I):
                state["readCommand"] = " ".join(args)
                events = parse_usn_journal_text(plain_output, volume, max_records, days)
                if events:
                    break
    state["readable"] = bool(events)
    state["recordsCollected"] = len(events)
    if not events:
        state["error"] = "USN journal was available, but no records could be parsed from the requested recent range."
    findings = {}
    timeline = []
    for event in events:
        name = event.get("fileName", "")
        path_text = event.get("path", "")
        reason = event.get("reason", "")
        suspicious = suspicious_name(name, config) or bool(ioc_text_matches(f"{name} {path_text}", config))
        if not suspicious:
            continue
        finding = make_finding(path_text, name, "usn_journal", config)
        finding["first_seen"] = event.get("timestamp") or iso_now()
        finding["supporting_evidence"].append(
            f"USN Journal: {event.get('eventType')} {path_text}; reason={reason}; usn={event.get('usn', '')}"
        )
        finding["evidence_types"].append("usn_journal")
        add_detection(finding, "USN Journal Event", f"USN journal recorded suspicious file activity: {event.get('eventType')}.", "Medium", 15)
        if event.get("eventType") == "Deleted":
            add_detection(finding, "Suspicious File Deletion", "USN journal recorded deletion of a suspiciously named file.", "Medium", 20)
            finding["evidence_types"].append("deletion_artifact")
        elif event.get("eventType") == "Modified":
            add_detection(finding, "Suspicious File Modification", "USN journal recorded modification of a suspiciously named file.", "Medium", 20)
            finding["evidence_types"].append("modified_artifact")
        if near_any_session(event.get("timestamp"), sessions):
            add_score(finding, config["score_rules"].get("near_roblox_session", 25), "USN event occurred near Roblox activity")
        apply_ioc_matches(finding, config, reason)
        merge_findings(findings, finding)
        timeline.append({
            "time": finding["first_seen"],
            "source": "USN Journal",
            "text": f"USN {event.get('eventType', 'Changed').upper()}: {name}",
        })
    return list(findings.values()), timeline, events


def collect_jump_list_context(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Jump Lists record recently opened apps/files. Treat as context, not proof by itself.
    findings = {}
    timeline = []
    cut = cutoff(days)
    for root in jump_list_roots(config):
        if not safe_exists(root):
            continue
        try:
            entries = list(root.glob("*.automaticDestinations-ms")) + list(root.glob("*.customDestinations-ms"))
        except OSError:
            continue
        for entry in entries[:2500]:
            try:
                mtime = dt.datetime.fromtimestamp(entry.stat().st_mtime)
            except OSError:
                continue
            if mtime < cut:
                continue
            parsed = extract_artifact_strings(entry)
            text_blob = " ".join([str(entry)] + parsed.get("referenced_paths", []) + parsed.get("strings", []))
            matched_paths = [
                path for path in parsed.get("referenced_paths", [])
                if suspicious_text(path, config)
                or ioc_text_matches(path, config)
                or (user_writable_path(path) and suspicious_extension(path, config))
            ]
            suspicious_strings = [item for item in parsed.get("strings", []) if suspicious_text(item, config) or ioc_text_matches(item, config)]
            if not matched_paths and not suspicious_strings:
                continue
            target = matched_paths[0] if matched_paths else str(entry)
            reason = f"Jump List artifact references suspicious recent item: {target}"
            finding = make_possible_context_finding(target, Path(target).name or entry.name, "Jump List", reason, mtime, config)
            finding["supporting_evidence"].append(f"Jump List artifact: {entry}")
            if matched_paths:
                finding["supporting_evidence"].append("Jump List referenced paths: " + "; ".join(matched_paths[:8]))
            if suspicious_strings:
                finding["supporting_evidence"].append("Jump List suspicious strings: " + "; ".join(suspicious_strings[:8]))
            finding["evidence_types"].append("jump_list_context")
            add_detection(finding, "Jump List Recent Item Context", "Jump List metadata referenced a suspicious executable/script/archive path.", "Medium", 15)
            if near_any_session(mtime, sessions):
                add_score(finding, config["score_rules"].get("near_roblox_session", 25), "Jump List artifact timestamp is near Roblox activity")
            apply_ioc_matches(finding, config, text_blob)
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": "Jump List", "text": reason})
    return list(findings.values()), timeline


def collect_amcache_context(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict]]:
    # Amcache can retain program execution/install traces. This lightweight pass extracts suspicious strings only.
    findings = {}
    timeline = []
    path = Path(os.path.expandvars(str(config.get("amcache_path") or "C:/Windows/AppCompat/Programs/Amcache.hve"))).expanduser()
    if not safe_exists(path):
        return [], []
    try:
        mtime = dt.datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        mtime = dt.datetime.now()
    parsed = extract_artifact_strings(path, max_bytes=int(config.get("amcache_scan_max_bytes") or 3_000_000))
    text_blob = " ".join([str(path)] + parsed.get("referenced_paths", []) + parsed.get("strings", []))
    matched_paths = [
        item for item in parsed.get("referenced_paths", [])
        if suspicious_text(item, config)
        or ioc_text_matches(item, config)
        or (user_writable_path(item) and suspicious_extension(item, config))
    ][:25]
    suspicious_strings = [item for item in parsed.get("strings", []) if suspicious_text(item, config) or ioc_text_matches(item, config)][:25]
    for item in matched_paths or suspicious_strings[:10]:
        target = item if re.match(r"^(?:[A-Za-z]:\\|\\\\)", item) else str(path)
        name = Path(target).name if target != str(path) else "Amcache suspicious context"
        reason = f"Amcache artifact references suspicious program context: {item}"
        finding = make_possible_context_finding(target, name, "Amcache", reason, mtime, config)
        finding["supporting_evidence"].append(f"Amcache hive: {path}")
        finding["supporting_evidence"].append(f"Amcache reference: {item}")
        finding["evidence_types"].append("amcache_context")
        add_detection(finding, "Amcache Execution/Install Context", "Amcache string context referenced a suspicious executable/script/archive.", "Medium", 20)
        apply_ioc_matches(finding, config, text_blob)
        merge_findings(findings, finding)
        timeline.append({"time": finding["first_seen"], "source": "Amcache", "text": reason})
    return list(findings.values()), timeline


def collect_file_artifacts(days: int, config: dict, sessions: list[dict], verbose=False, progress=None) -> tuple[list[dict], list[dict]]:
    # File-system artifacts are indirect: they show exploit-like files existed, especially near Roblox play sessions.
    findings = {}
    timeline = []
    cut = cutoff(days)
    max_files = int(config.get("max_files_scanned") or 25000)
    time_budget = int(config.get("file_artifact_time_budget_seconds") or 240)
    started = time.monotonic()
    stage_deadline = started + max(1, time_budget)
    seen_files = 0

    def record_limit(reason: str):
        config["_file_artifact_status"] = {
            "truncated": True,
            "reason": reason,
            "filesScanned": seen_files,
        }
        if progress:
            progress(f"Checking file artifacts {reason} after {seen_files} files", files_scanned=seen_files)

    def time_limit_reached() -> bool:
        if time.monotonic() < stage_deadline:
            return False
        record_limit("hit time cap")
        return True

    skipped_dirs = {
        "node_modules", ".git", "windowsapps", "packages", "__pycache__", ".next", "cache2",
        "inetsim", "installer", "winsxs", "softwaredistribution", "temporary internet files",
    }
    noisy_dir_markers = (
        "\\appdata\\local\\packages\\",
        "\\appdata\\local\\microsoft\\windowsapps\\",
        "\\appdata\\local\\google\\chrome\\user data\\",
        "\\appdata\\local\\microsoft\\edge\\user data\\",
        "\\appdata\\roaming\\mozilla\\firefox\\profiles\\",
        "\\program files\\windowsapps\\",
        "\\windows\\winsxs\\",
        "\\windows\\servicing\\",
    )
    for root in scan_roots():
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            if time_limit_reached():
                return list(findings.values()), timeline
            low_dir = str(dirpath).lower()
            if any(marker in low_dir for marker in noisy_dir_markers):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d.lower() not in skipped_dirs]
            dirnames[:] = [d for d in dirnames if not securo_internal_path(str(Path(dirpath) / d), config)]
            if securo_internal_path(dirpath, config):
                continue
            if seen_files >= max_files:
                record_limit("hit file cap")
                return list(findings.values()), timeline
            for filename in filenames:
                # A single large or slow directory must not overrun the entire
                # scan. Every detection performed before this point is retained.
                if time_limit_reached():
                    return list(findings.values()), timeline
                seen_files += 1
                if progress and seen_files % 500 == 0:
                    progress(f"Checking file artifacts... files scanned={seen_files}", files_scanned=seen_files)
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
                if not cheap_artifact_candidate(path_text, times, sessions, config):
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
    recycle_roots = recycle_bin_roots(config)
    for root in recycle_roots:
        try:
            entries = list(root.rglob("*"))
        except OSError:
            continue
        for entry in entries[:5000]:
            if entry.is_dir():
                continue
            try:
                mtime = dt.datetime.fromtimestamp(entry.stat().st_mtime)
            except OSError:
                continue
            if mtime < cut:
                continue
            meta = recycle_metadata_for_entry(entry)
            original = meta.get("original_path") or str(entry)
            deleted_when = parse_dt(meta.get("deleted_time")) or mtime
            text = " ".join([str(entry), original])
            is_prefetch = original.lower().endswith(".pf") or "\\prefetch\\" in original.lower()
            executor_terms = [str(term).lower() for term in config.get("executor_confirmation_keywords", []) if str(term).strip()]
            executor_deleted = any(term in text.lower() for term in executor_terms)
            suspicious_deleted = suspicious_text(text, config) or ioc_text_matches(text, config) or executor_deleted
            reason = f"DELETED FILE: {original}"
            finding = make_possible_context_finding(original, Path(original).name or entry.name, "Recycle Bin", reason, deleted_when, config)
            finding["supporting_evidence"].append(f"DELETED FILE: {original}")
            finding["supporting_evidence"].append(f"Recycle Bin metadata file: {entry}")
            finding["evidence_types"].append("recovery")
            if meta:
                finding["supporting_evidence"].append(f"deleted_time={meta.get('deleted_time', '')} size={meta.get('size', '')}")
                if meta.get("recovered_content_file"):
                    finding["supporting_evidence"].append(f"Recoverable Recycle Bin content file: {meta.get('recovered_content_file')}")
            add_detection(finding, "File Deletion", "Recycle Bin metadata shows this file was deleted.", "Info", 5)
            if is_prefetch:
                add_detection(finding, "Deleted Prefetch File", "Recycle Bin metadata shows a Prefetch artifact was deleted.", "High", 30)
                add_detection(finding, "Prefetch Deleted", "Deleted Prefetch metadata can indicate anti-forensic cleanup after execution.", "High", 30)
                finding["evidence_types"].append("prefetch_deleted")
            elif suspicious_deleted:
                add_detection(finding, "Suspicious File Deletion", "Recycle Bin metadata shows a suspicious file was deleted.", "Medium", 25)
                if Path(original).suffix.lower() == ".dll":
                    add_detection(finding, "Suspicious DLL Deletion", "Recycle Bin metadata shows a suspicious DLL was deleted.", "High", 30)
                    finding["evidence_types"].append("suspicious_dll_deleted")
            if near_any_session(deleted_when, sessions):
                add_score(finding, config["score_rules"].get("near_roblox_session", 25), "Deletion timestamp is within 30 minutes of Roblox activity")
            apply_ioc_matches(finding, config, text)
            merge_findings(findings, finding)
            timeline.append({"time": finding["first_seen"], "source": "Recycle Bin", "text": reason})
    return list(findings.values()), timeline


def recycle_bin_roots(config: dict | None = None) -> list[Path]:
    configured = (config or {}).get("recycle_bin_roots") or []
    if configured:
        return [Path(os.path.expandvars(str(root))).expanduser() for root in configured]
    return [Path(drive + ":\\$Recycle.Bin") for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(drive + ":\\").exists()]


def recycle_metadata_for_entry(path: Path) -> dict:
    if path.name.lower().startswith("$i"):
        return parse_recycle_i_record(path)
    if path.name.lower().startswith("$r") and len(path.name) > 2:
        sibling = path.with_name("$I" + path.name[2:])
        meta = parse_recycle_i_record(sibling)
        if meta.get("original_path"):
            meta["recovered_content_file"] = str(path)
            return meta
    return {}


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
    result = {"original_path": original, "deleted_time": deleted_time, "size": size, "metadata_file": str(path)}
    if path.name.lower().startswith("$i") and len(path.name) > 2:
        content = path.with_name("$R" + path.name[2:])
        if safe_exists(content):
            result["recovered_content_file"] = str(content)
            result["recoverable"] = True
        else:
            result["recoverable"] = False
    return result


def collect_recovery_artifacts(days: int, config: dict, sessions: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    findings = {}
    timeline = []
    recovered = []
    cut = cutoff(days)
    roots = recycle_bin_roots(config)
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
            when = meta.get("deleted_time") or mtime.isoformat(sep=" ", timespec="seconds")
            suspicious_deleted = suspicious_text(original, config) or ioc_text_matches(original, config)
            finding = make_possible_context_finding(
                original,
                Path(original).name or entry.name,
                "Recovered File Metadata",
                f"DELETED FILE: {original}",
                parse_dt(when) or mtime,
                config,
            )
            finding["supporting_evidence"].append(f"DELETED FILE: {original}")
            finding["evidence_types"].append("recovery")
            finding["manual_review_required"] = True
            finding["recovered_metadata"] = meta
            if meta.get("recovered_content_file"):
                finding["supporting_evidence"].append(f"Recoverable Recycle Bin content file: {meta.get('recovered_content_file')}")
            add_detection(finding, "File Deletion", "Deleted file metadata recovered from Recycle Bin", "Info", 5)
            if original.lower().endswith(".pf") or "\\prefetch\\" in original.lower():
                add_detection(finding, "Deleted Prefetch File", "Deleted Prefetch metadata recovered from Recycle Bin", "High", 30)
                add_detection(finding, "Prefetch Deleted", "Deleted Prefetch metadata can indicate anti-forensic cleanup after execution.", "High", 30)
                finding["evidence_types"].append("prefetch_deleted")
            elif suspicious_deleted:
                add_detection(finding, "Suspicious File Deletion", "Deleted suspicious file metadata recovered from Recycle Bin", "Medium", 20)
                if Path(original).suffix.lower() == ".dll":
                    add_detection(finding, "Suspicious DLL Deletion", "Deleted suspicious DLL metadata recovered from Recycle Bin", "High", 30)
                    finding["evidence_types"].append("suspicious_dll_deleted")
            merge_findings(findings, finding)
            recovered.append({
                "name": finding["name"],
                "path": original,
                "source": "Recycle Bin",
                "timestamp": when,
                "metadata": meta,
                "manualReviewRequired": True,
            })
            timeline.append({"time": when, "source": "Recovery", "text": f"DELETED FILE: {original}"})
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

    prefetch = config.get("_prefetch_inventory") or prefetch_inventory(config)
    prefetch_warning = None
    if prefetch.get("enabled") is False:
        prefetch_warning = (
            "Prefetch Disabled",
            "Medium",
            "Windows Prefetch is disabled. This reduces execution-history coverage but is not proof of cheating.",
        )
    elif not prefetch.get("readable"):
        explanation = prefetch.get("error") or "Windows Prefetch files were not readable."
        prefetch_warning = (
            "Prefetch Access Unavailable",
            "Medium",
            f"{explanation} This is a coverage limitation, not proof of cheating.",
        )
    elif int(prefetch.get("count") or 0) < 5:
        prefetch_warning = (
            "Prefetch Unusually Sparse",
            "Low",
            f"Only {prefetch.get('count', 0)} Prefetch files were found. This may result from normal cleanup, Windows settings, or manual clearing.",
        )
    elif isinstance(prefetch.get("installGapDays"), int) and prefetch["installGapDays"] >= 14:
        prefetch_warning = (
            "Prefetch History Gap",
            "Low",
            f"The oldest retained Prefetch entry begins about {prefetch['installGapDays']} days after the recorded Windows installation date. Manual review may be useful.",
        )
    if prefetch_warning:
        name, severity, explanation = prefetch_warning
        when = iso_now()
        warning = {
            "detectionName": name,
            "severity": severity,
            "explanation": explanation,
            "evidencePath": prefetch.get("path", "C:/Windows/Prefetch"),
            "timestamp": when,
            "manualReviewRequired": True,
            "confidenceLevel": "medium" if severity == "Medium" else "low",
            "type": "Warning",
        }
        warnings.append(warning)
        finding = make_possible_context_finding(
            warning["evidencePath"],
            name,
            "Prefetch Integrity",
            explanation,
            parse_dt(when),
            config,
        )
        finding["evidence_types"].extend(["warning", "prefetch_integrity"])
        add_detection(finding, name, explanation, severity, 10 if severity == "Medium" else 5)
        merge_findings(findings, finding)
        timeline.append({"time": when, "source": "Prefetch integrity", "text": explanation})

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
    delete_modify_terms = re.compile(r"(remove-item|del\s|erase\s|move-item|rename-item|set-content|add-content|clear-content)", re.I)
    for hist in files:
        try:
            mtime = dt.datetime.fromtimestamp(hist.stat().st_mtime)
            lines = hist.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if mtime < cutoff(days):
            continue
        for i, line in enumerate(lines, start=1):
            if not (download_terms.search(line) or delete_modify_terms.search(line)):
                continue
            name = f"PowerShell history line {i}"
            finding = make_finding(str(hist), name, "powershell_history", config)
            finding["first_seen"] = mtime.isoformat(sep=" ", timespec="seconds")
            add_score(finding, config["score_rules"]["powershell_download_execute"], "PowerShell history contains download/execute pattern")
            if near_any_session(mtime, sessions):
                add_score(finding, config["score_rules"]["near_roblox_session"], "PowerShell history timestamp is within 30 minutes of Roblox activity")
            finding["supporting_evidence"].append(f"{hist}:{i}: {line[:500]}")
            finding["evidence_types"].append("powershell_history")
            if "\\\\" in line or "file://" in line.lower():
                add_detection(finding, "Generic Bypass Method (Network File)", "PowerShell history references execution/modification/deletion from a network resource.", "High", 35)
                finding["evidence_types"].append("network_artifact")
            if ".rar" in line.lower() and re.search(r"(start-process|&\s*|invoke-item|ii\s)", line, re.I):
                add_detection(finding, "RAR File Execution", "PowerShell history indicates direct execution involving a RAR archive path.", "Medium", 25)
                finding["evidence_types"].append("archive_artifact")
            if "nvidia" in line.lower() and delete_modify_terms.search(line):
                add_detection(finding, "Generic Bypass Method (NVIDIA / Powershell execution log)", "PowerShell history references modification/deletion of NVIDIA-related execution/log artifacts.", "High", 35)
                finding["evidence_types"].append("bypass_method")
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


def defender_exclusion_reasons(kind: str, value: str, config: dict) -> list[str]:
    text = str(value or "").strip()
    lowered = text.lower()
    reasons = []
    if not text:
        return reasons
    if kind in {"Path", "Process"} and user_writable_path(text):
        reasons.append("points to a user-writable location")
    if kind in {"Path", "Process"} and suspicious_text(text, config):
        reasons.append("contains Roblox/executor-style suspicious terms")
    if kind == "Extension" and lowered.strip(".") in {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js"}:
        reasons.append("excludes a high-risk executable/script extension")
    if any(token in lowered for token in ["roblox", "executor", "inject", "loader", "bypass", "xeno", "solara", "wave", "potassium", "synapse"]):
        reasons.append("matches Roblox exploit review terms")
    if lowered.startswith("\\\\") or lowered.startswith("file://"):
        reasons.append("references a network location")
    return sorted(set(reasons))


def collect_defender_exclusions(config: dict) -> tuple[list[dict], list[dict]]:
    # Read-only Defender preference check. Exclusions can hide executor folders from AV, so they are review context.
    exclusions: list[dict] = []
    seen = set()

    def add(kind: str, value: str, source: str):
        value = str(value or "").strip()
        if not value:
            return
        key = (kind.lower(), value.lower())
        if key in seen:
            return
        seen.add(key)
        reasons = defender_exclusion_reasons(kind, value, config)
        exclusions.append({
            "type": kind,
            "value": value,
            "source": source,
            "severity": "Review" if reasons else "Info",
            "manualReviewRequired": bool(reasons),
            "reasons": reasons,
        })

    def values_list(value) -> list:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    ps = (
        "$p=Get-MpPreference;"
        "[pscustomobject]@{"
        "ExclusionPath=@($p.ExclusionPath);"
        "ExclusionProcess=@($p.ExclusionProcess);"
        "ExclusionExtension=@($p.ExclusionExtension);"
        "ExclusionIpAddress=@($p.ExclusionIpAddress)"
        "} | ConvertTo-Json -Depth 4 -Compress"
    )
    output = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=12)
    try:
        parsed = json.loads(output[output.find("{"):]) if "{" in output else {}
    except (json.JSONDecodeError, ValueError):
        parsed = {}
    if isinstance(parsed, dict):
        for value in values_list(parsed.get("ExclusionPath")):
            add("Path", value, "Get-MpPreference")
        for value in values_list(parsed.get("ExclusionProcess")):
            add("Process", value, "Get-MpPreference")
        for value in values_list(parsed.get("ExclusionExtension")):
            add("Extension", value, "Get-MpPreference")
        for value in values_list(parsed.get("ExclusionIpAddress")):
            add("IP Address", value, "Get-MpPreference")

    registry_keys = [
        ("Path", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"),
        ("Process", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"),
        ("Extension", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"),
        ("IP Address", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses"),
    ]
    for kind, key in registry_keys:
        out = run_command(["reg", "query", key], timeout=8)
        if "ERROR:" in out or "COMMAND_ERROR" in out:
            continue
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("HKEY_"):
                continue
            parts = re.split(r"\s+REG_\w+\s+", stripped, maxsplit=1)
            if parts[0].strip().lower() == "(default)":
                continue
            add(kind, parts[0].strip(), "Defender exclusion registry")

    timeline = []
    for item in exclusions:
        if item.get("manualReviewRequired"):
            timeline.append({
                "time": iso_now(),
                "source": "Defender exclusions",
                "text": f"Defender exclusion requires review: {item['type']} {item['value']}",
                "confidence": "Possible",
            })
    return exclusions, timeline


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
        if not (suspicious_text(text, config) or user_writable_path(text) or ioc_text_matches(" ".join([source, location, text]), config)):
            continue
        paths = re.findall(r"[A-Za-z]:\\[^\"<>|]+?\.(?:exe|dll|ps1|bat|cmd|vbs|js)", text, re.I)
        path = paths[0] if paths else location
        finding = make_finding(path, source, "persistence", config)
        finding["first_seen"] = dt.datetime.now().isoformat(sep=" ", timespec="seconds")
        add_score(finding, config["score_rules"]["persistence"], f"Suspicious persistence entry: {source}")
        finding["supporting_evidence"].append(text[:800])
        finding["evidence_types"].append("persistence")
        apply_ioc_matches(finding, config, " ".join([source, location, text]))
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
        if quality.get("Prefetch enabled") is False:
            limits.append("Windows Prefetch appears to be disabled, so execution-history coverage is incomplete.")
        elif not quality.get("Prefetch administrator access"):
            limits.append("Prefetch files were not readable. Run the packaged Securo application with its requested administrator access.")
        else:
            limits.append("Prefetch was empty, unavailable, or inaccessible.")
    if not quality.get("USN Change Journal available"):
        limits.append("The NTFS USN Change Journal was unavailable or inaccessible, so recent file create/delete/rename/modify coverage may be incomplete.")
    elif quality.get("USN Change Journal readable") is False:
        limits.append("The NTFS USN Change Journal exists, but Securo could not parse records from the requested recent range.")
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
        "events": session.get("events", []),
        "fastFlags": session.get("fast_flags", []),
        "robloxLogs": session.get("all_logs", []),
        "errors": session.get("errors", [])[:20],
        "crashes": session.get("crashes", [])[:20],
        "suspiciousLines": session.get("suspicious_lines", [])[:20],
    }


def roblox_logs_for_report(sessions: list[dict]) -> list[dict]:
    logs = []
    for session in sessions:
        for item in session.get("all_logs", []):
            logs.append(item)
    return sorted(logs, key=lambda item: parse_dt(item.get("startTime") or item.get("modifiedTime")) or dt.datetime.min)


def fastflags_for_report(sessions: list[dict]) -> list[dict]:
    flags = []
    for session in sessions:
        for flag in session.get("fast_flags", []):
            row = dict(flag)
            row.setdefault("placeId", session.get("place_id", ""))
            row.setdefault("jobId", session.get("job_id", ""))
            row.setdefault("userId", session.get("user_id", ""))
            flags.append(row)
    return sorted(flags, key=lambda item: parse_dt(item.get("timestamp")) or dt.datetime.min)


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
    running_findings, running_timeline = collect_running_processes(config, sessions_raw)
    network_findings, network_timeline = collect_network_ioc_evidence(config)
    prefetch_findings, prefetch_timeline = collect_prefetch_evidence(days, config, sessions_raw)
    usn_findings, usn_timeline, usn_events = collect_usn_journal_events(days, config, sessions_raw)
    recycle_findings, recycle_timeline = collect_recycle_bin_context(days, config, sessions_raw)
    jump_list_findings, jump_list_timeline = collect_jump_list_context(days, config, sessions_raw)
    amcache_findings, amcache_timeline = collect_amcache_context(days, config, sessions_raw)
    external_tool_notes = execute_external_forensic_tools(days, config)
    sbecmd_findings, sbecmd_timeline, shellbag_artifacts = collect_sbecmd_shellbags(days, config, sessions_raw)
    external_forensic_findings, external_forensic_timeline = collect_external_forensic_exports(days, config, sessions_raw)
    file_findings, file_timeline = collect_file_artifacts(days, config, sessions_raw, verbose=verbose)
    ps_findings, ps_timeline = collect_powershell_history(days, config, sessions_raw)
    defender_findings, defender_timeline = collect_defender_history(days, config, sessions_raw)
    defender_exclusions, defender_exclusion_timeline = collect_defender_exclusions(config)
    persistence_findings, persistence_timeline = collect_persistence(days, config, sessions_raw)
    if config.get("skip_browser_artifacts"):
        browser_findings, browser_timeline = [], []
    else:
        browser_findings, browser_timeline = collect_browser_downloads(days, config, sessions_raw)
    shellbag_findings, shellbag_timeline = collect_shellbag_context(days, config, sessions_raw)
    if config.get("skip_recovery_metadata"):
        recovery_findings, recovery_timeline, recovery_artifacts = [], [], []
    else:
        recovery_findings, recovery_timeline, recovery_artifacts = collect_recovery_artifacts(days, config, sessions_raw)
    warning_findings, warning_timeline, warning_logs = collect_warning_logs(days, config, sessions_raw)
    account_identifiers = collect_safe_account_identifiers(sessions_raw, config)
    if config.get("collect_system_reset_evidence"):
        reset_evidence, reset_timeline = collect_system_reset_evidence(days, config)
        windows_install_history = collect_windows_install_history()
        sysmain_service = collect_sysmain_service_info(days)
    else:
        reset_evidence, reset_timeline = [], []
        windows_install_history, sysmain_service = [], {}
    raw_timeline = (
        roblox_timeline
        + process_timeline
        + running_timeline
        + network_timeline
        + prefetch_timeline
        + usn_timeline
        + recycle_timeline
        + jump_list_timeline
        + amcache_timeline
        + sbecmd_timeline
        + external_forensic_timeline
        + file_timeline
        + ps_timeline
        + defender_timeline
        + defender_exclusion_timeline
        + persistence_timeline
        + browser_timeline
        + shellbag_timeline
        + recovery_timeline
        + warning_timeline
    )
    findings = combine_findings(
        [process_findings, running_findings, network_findings, prefetch_findings, usn_findings, recycle_findings, jump_list_findings, amcache_findings, sbecmd_findings, external_forensic_findings, file_findings, ps_findings, defender_findings, persistence_findings, browser_findings, shellbag_findings, recovery_findings, warning_findings],
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
    quality["Defender exclusions collected"] = bool(defender_exclusions)
    quality["Defender exclusions needing review"] = sum(1 for item in defender_exclusions if item.get("manualReviewRequired"))
    usn_status = config.get("_usn_journal_status", {})
    quality["USN Change Journal available"] = bool(usn_status.get("available"))
    quality["USN Change Journal readable"] = bool(usn_status.get("readable"))
    quality["USN Journal records collected"] = int(usn_status.get("recordsCollected", 0) or 0)
    if usn_status.get("error"):
        quality["USN Journal status"] = str(usn_status.get("error"))[:240]
    timeline = annotate_timeline_confidence(filter_customer_timeline(dedupe_timeline(raw_timeline), config), findings)
    key_artifacts = key_artifacts_from_report_parts(findings, timeline, recovery_artifacts)
    partial = {"findings": findings, "evidence_quality": quality}
    highest_result = determine_overall_category(partial)
    top_score = max([f.get("score", 0) for f in findings], default=0)
    system = collect_system_info()
    system["scan_time"] = scan_time
    limitations = limitations_from_quality(quality)
    limitations.extend(external_tool_notes)
    file_status = config.get("_file_artifact_status", {})
    if file_status.get("truncated"):
        limitations.append(
            f"File artifact coverage was bounded: {file_status.get('reason')} after "
            f"{file_status.get('filesScanned', 0)} files. Other forensic stages continued normally."
        )
    if str(sysmain_service.get("startupType", "")).lower() == "disabled":
        limitations.append("The SysMain service is disabled. Prefetch generation and execution-history coverage may be reduced; this is not proof of cheating.")
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
        "keyArtifacts": key_artifacts,
        "sessions": [camel_session(s) for s in sessions_raw],
        "robloxLogs": roblox_logs_for_report(sessions_raw),
        "detectedFastFlags": fastflags_for_report(sessions_raw),
        "usnJournalEvents": usn_events,
        "usnJournalStatus": usn_status,
        "shellBagArtifacts": shellbag_artifacts,
        "findings": [camel_finding(f) for f in findings],
        "detectLogs": detect_logs,
        "correlationFindings": correlation_findings_for_report(findings),
        "warningLogs": warning_logs,
        "recoveryArtifacts": recovery_artifacts,
        "antivirusLogs": antivirus_logs,
        "defenderExclusions": defender_exclusions,
        "engineResults": engine_results,
        "accountIdentifiers": account_identifiers,
        "systemResetEvidence": reset_evidence,
        "windowsInstallHistory": windows_install_history,
        "sysMainService": sysmain_service,
        "limitations": limitations,
        "scanDays": days,
        "scanProfile": config.get("scan_profile", "standard"),
        "scanProfileDescription": config.get("scan_profile_description", ""),
        "topScore": top_score,
        "systemInfo": system,
        "scanTransparency": scan_transparency_metadata(),
        "finalStatement": "No confirmed Roblox injection evidence was found in available logs. Logging coverage may not be sufficient to rule it out."
        if highest_result not in ["Confirmed Exploit", "Suspicious"]
        else "Confirmed exploit or suspicious Roblox exploit/injection evidence was found in available artifacts.",
    }
    return json_safe(report)


def emit_progress(progress, stage: str, percent: int | None = None, files_scanned: int | None = None):
    message = stage if percent is None else f"{stage} ({percent}%)"
    try:
        progress(message, stage=stage, percent=percent, files_scanned=files_scanned)
    except TypeError:
        progress(message)


def scan_time_remaining(config: dict) -> float | None:
    deadline = config.get("_scan_deadline_monotonic")
    if not deadline:
        return None
    try:
        return float(deadline) - time.monotonic()
    except (TypeError, ValueError):
        return None


def has_scan_time_for(config: dict, seconds: int) -> bool:
    remaining = scan_time_remaining(config)
    return remaining is None or remaining > seconds


def note_stage_skipped(config: dict, progress, stage: str, limitations: list[str], min_remaining: int, percent: int):
    remaining = scan_time_remaining(config)
    detail = f"{stage} skipped so Securo can finish and upload before the configured scan timeout."
    if remaining is not None:
        detail += f" Remaining scan budget was about {max(0, int(remaining))} seconds; this stage needs about {min_remaining} seconds."
    limitations.append(detail)
    emit_progress(progress, detail, percent)


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
        "defenderExclusions": [],
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
    worker_config = dict(config)
    timeout_seconds = max(1, int(timeout_seconds or 900))
    finish_buffer = max(15, int(worker_config.get("scan_finish_buffer_seconds", 35) or 35))
    worker_config["_scan_deadline_monotonic"] = time.monotonic() + max(1, timeout_seconds - finish_buffer)

    def tracked_progress(message: str, stage: str | None = None, percent: int | None = None, files_scanned: int | None = None):
        diagnostics.progress(message, stage=stage, percent=percent, files_scanned=files_scanned)
        try:
            progress(message)
        except TypeError:
            progress(str(message))

    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def scan_target():
        try:
            report = build_scan_report_with_progress(days, worker_config, tracked_progress)
            report["scanStatus"] = "completed"
            report["diagnostics"] = diagnostics.snapshot()
            try:
                result_queue.put_nowait(("completed", report))
            except queue.Full:
                pass
        except Exception as exc:
            diagnostics.fail(str(exc))
            try:
                result_queue.put_nowait(("failed", diagnostic_report("failed", str(exc), diagnostics, worker_config)))
            except queue.Full:
                pass

    diagnostics.progress("Scan started", stage="scanning", percent=0)
    worker = threading.Thread(target=scan_target, daemon=True)
    worker.start()
    try:
        return result_queue.get(timeout=timeout_seconds)
    except queue.Empty:
        reason = f"Scan exceeded configured timeout of {timeout_seconds} seconds while at stage '{diagnostics.stage}'."
        diagnostics.fail(reason)
        return "timeout", diagnostic_report("timeout", reason, diagnostics, worker_config)


def build_scan_report_with_progress(days: int, config: dict, progress) -> dict:
    days = int(config.get("scan_days", days) or days)
    scan_time = iso_now()
    stage_limitations: list[str] = []
    emit_progress(progress, "Scan started", 0)
    emit_progress(progress, "Collecting Roblox logs", 5)
    sessions_raw, roblox_timeline = parse_roblox_logs(days, config)
    emit_progress(progress, "Checking account history", 8)
    account_identifiers = collect_safe_account_identifiers(sessions_raw, config)
    emit_progress(progress, "Checking reset and reinstall history", 10)
    reset_evidence, reset_timeline = collect_system_reset_evidence(days, config) if config.get("collect_system_reset_evidence", True) else ([], [])
    windows_install_history = collect_windows_install_history() if config.get("collect_system_reset_evidence", True) else []
    sysmain_service = collect_sysmain_service_info(days) if config.get("collect_system_reset_evidence", True) else {}
    emit_progress(progress, "Checking event logs", 12)
    process_findings, process_timeline = collect_process_evidence(days, config, sessions_raw)
    emit_progress(progress, "Checking running processes", 16)
    running_findings, running_timeline = collect_running_processes(config, sessions_raw)
    network_findings, network_timeline = collect_network_ioc_evidence(config)
    emit_progress(progress, "Checking Prefetch artifacts", 22)
    prefetch_findings, prefetch_timeline = collect_prefetch_evidence(days, config, sessions_raw)
    emit_progress(progress, "Checking USN Change Journal", 25)
    usn_findings, usn_timeline, usn_events = collect_usn_journal_events(days, config, sessions_raw)
    emit_progress(progress, "Checking deleted file artifacts", 28)
    recycle_findings, recycle_timeline = collect_recycle_bin_context(days, config, sessions_raw)
    emit_progress(progress, "Checking forensic app artifacts", 31)
    jump_list_findings, jump_list_timeline = collect_jump_list_context(days, config, sessions_raw)
    amcache_findings, amcache_timeline = collect_amcache_context(days, config, sessions_raw)
    emit_progress(progress, "Running optional forensic parser tools", 32)
    if has_scan_time_for(config, 30):
        external_tool_notes = execute_external_forensic_tools(days, config)
    else:
        external_tool_notes = []
        note_stage_skipped(config, progress, "Optional forensic parser tools", stage_limitations, 30, 32)
    emit_progress(progress, "Checking forensic parser exports", 32)
    sbecmd_findings, sbecmd_timeline, shellbag_artifacts = collect_sbecmd_shellbags(days, config, sessions_raw)
    external_forensic_findings, external_forensic_timeline = collect_external_forensic_exports(days, config, sessions_raw)
    emit_progress(progress, "Checking file artifacts", 34)
    file_findings, file_timeline = collect_file_artifacts(days, config, sessions_raw, verbose=False, progress=progress)
    emit_progress(progress, "Checking PowerShell history", 50)
    if has_scan_time_for(config, 170):
        ps_findings, ps_timeline = collect_powershell_history(days, config, sessions_raw)
    else:
        ps_findings, ps_timeline = [], []
        note_stage_skipped(config, progress, "PowerShell history", stage_limitations, 170, 50)
    emit_progress(progress, "Checking Defender artifacts", 58)
    if has_scan_time_for(config, 145):
        defender_findings, defender_timeline = collect_defender_history(days, config, sessions_raw)
    else:
        defender_findings, defender_timeline = [], []
        note_stage_skipped(config, progress, "Defender artifacts", stage_limitations, 145, 58)
    defender_exclusions, defender_exclusion_timeline = collect_defender_exclusions(config)
    emit_progress(progress, "Checking persistence entries", 66)
    if has_scan_time_for(config, 120):
        persistence_findings, persistence_timeline = collect_persistence(days, config, sessions_raw)
    else:
        persistence_findings, persistence_timeline = [], []
        note_stage_skipped(config, progress, "Persistence entries", stage_limitations, 120, 66)
    emit_progress(progress, "Checking browser artifacts", 74)
    if config.get("skip_browser_artifacts"):
        browser_findings, browser_timeline = [], []
        emit_progress(progress, "Browser artifacts skipped by scan profile", 74)
    elif not has_scan_time_for(config, 100):
        browser_findings, browser_timeline = [], []
        note_stage_skipped(config, progress, "Browser artifacts", stage_limitations, 100, 74)
    else:
        browser_findings, browser_timeline = collect_browser_downloads(days, config, sessions_raw)
    emit_progress(progress, "Checking ShellBag Analyzer context", 80)
    if has_scan_time_for(config, 80):
        shellbag_findings, shellbag_timeline = collect_shellbag_context(days, config, sessions_raw)
    else:
        shellbag_findings, shellbag_timeline = [], []
        note_stage_skipped(config, progress, "ShellBag Analyzer context", stage_limitations, 80, 80)
    emit_progress(progress, "Checking recovery metadata", 88)
    if config.get("skip_recovery_metadata"):
        recovery_findings, recovery_timeline, recovery_artifacts = [], [], []
        emit_progress(progress, "Recovery metadata skipped by scan profile", 88)
    elif not has_scan_time_for(config, 55):
        recovery_findings, recovery_timeline, recovery_artifacts = [], [], []
        note_stage_skipped(config, progress, "Recovery metadata", stage_limitations, 55, 88)
    else:
        recovery_findings, recovery_timeline, recovery_artifacts = collect_recovery_artifacts(days, config, sessions_raw)
    emit_progress(progress, "Checking warning indicators", 92)
    if has_scan_time_for(config, 45):
        warning_findings, warning_timeline, warning_logs = collect_warning_logs(days, config, sessions_raw)
    else:
        warning_findings, warning_timeline, warning_logs = [], [], []
        note_stage_skipped(config, progress, "Warning indicators", stage_limitations, 45, 92)
    emit_progress(progress, "Building report", 96)
    raw_timeline = (
        roblox_timeline
        + process_timeline
        + running_timeline
        + network_timeline
        + prefetch_timeline
        + usn_timeline
        + recycle_timeline
        + jump_list_timeline
        + amcache_timeline
        + sbecmd_timeline
        + external_forensic_timeline
        + file_timeline
        + ps_timeline
        + defender_timeline
        + defender_exclusion_timeline
        + persistence_timeline
        + browser_timeline
        + shellbag_timeline
        + recovery_timeline
        + warning_timeline
    )
    findings = combine_findings(
        [process_findings, running_findings, network_findings, prefetch_findings, usn_findings, recycle_findings, jump_list_findings, amcache_findings, sbecmd_findings, external_forensic_findings, file_findings, ps_findings, defender_findings, persistence_findings, browser_findings, shellbag_findings, recovery_findings, warning_findings],
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
    quality["Defender exclusions collected"] = bool(defender_exclusions)
    quality["Defender exclusions needing review"] = sum(1 for item in defender_exclusions if item.get("manualReviewRequired"))
    usn_status = config.get("_usn_journal_status", {})
    quality["USN Change Journal available"] = bool(usn_status.get("available"))
    quality["USN Change Journal readable"] = bool(usn_status.get("readable"))
    quality["USN Journal records collected"] = int(usn_status.get("recordsCollected", 0) or 0)
    if usn_status.get("error"):
        quality["USN Journal status"] = str(usn_status.get("error"))[:240]
    timeline = annotate_timeline_confidence(filter_customer_timeline(dedupe_timeline(raw_timeline), config), findings)
    key_artifacts = key_artifacts_from_report_parts(findings, timeline, recovery_artifacts)
    partial = {"findings": findings, "evidence_quality": quality}
    highest_result = determine_overall_category(partial)
    top_score = max([f.get("score", 0) for f in findings], default=0)
    system = collect_system_info()
    system["scan_time"] = scan_time
    limitations = limitations_from_quality(quality)
    limitations.extend(stage_limitations)
    limitations.extend(external_tool_notes)
    file_status = config.get("_file_artifact_status", {})
    if file_status.get("truncated"):
        limitations.append(
            f"File artifact coverage was bounded: {file_status.get('reason')} after "
            f"{file_status.get('filesScanned', 0)} files. Other forensic stages continued normally."
        )
    if str(sysmain_service.get("startupType", "")).lower() == "disabled":
        limitations.append("The SysMain service is disabled. Prefetch generation and execution-history coverage may be reduced; this is not proof of cheating.")
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
        "keyArtifacts": key_artifacts,
        "sessions": [camel_session(s) for s in sessions_raw],
        "robloxLogs": roblox_logs_for_report(sessions_raw),
        "detectedFastFlags": fastflags_for_report(sessions_raw),
        "usnJournalEvents": usn_events,
        "usnJournalStatus": usn_status,
        "shellBagArtifacts": shellbag_artifacts,
        "findings": [camel_finding(f) for f in findings],
        "detectLogs": detect_logs,
        "correlationFindings": correlation_findings_for_report(findings),
        "warningLogs": warning_logs,
        "recoveryArtifacts": recovery_artifacts,
        "antivirusLogs": antivirus_logs,
        "defenderExclusions": defender_exclusions,
        "engineResults": engine_results,
        "accountIdentifiers": account_identifiers,
        "systemResetEvidence": reset_evidence,
        "windowsInstallHistory": windows_install_history,
        "sysMainService": sysmain_service,
        "limitations": limitations,
        "scanDays": days,
        "scanProfile": config.get("scan_profile", "standard"),
        "scanProfileDescription": config.get("scan_profile_description", ""),
        "topScore": top_score,
        "systemInfo": system,
        "scanTransparency": scan_transparency_metadata(),
        "finalStatement": "No confirmed Roblox injection evidence was found in available logs. Logging coverage may not be sufficient to rule it out."
        if highest_result not in ["Confirmed Exploit", "Suspicious"]
        else "Confirmed exploit or suspicious Roblox exploit/injection evidence was found in available artifacts.",
    }
    emit_progress(progress, "Scan completed", 100)
    return json_safe(report)


def save_local_reports(report: dict, config: dict, html_only=False, json_only=False) -> list[Path]:
    report = json_safe(report)
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
        parsed_time = parse_dt(e.get("time"))
        if not parsed_time:
            continue
        item = dict(e)
        item["time"] = parsed_time.isoformat(sep=" ", timespec="seconds")
        key = (item.get("time", ""), item.get("source", ""), item.get("text", ""))
        if key in seen:
            continue
        seen.add(key)
        clean.append(item)
    return sorted(clean, key=lambda x: parse_dt(x.get("time")) or dt.datetime.min)


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
    account_context = report.get("accountIdentifiers", {}) if isinstance(report.get("accountIdentifiers"), dict) else {}
    lines += ["", "Account History", "---------------", account_context.get("privacyNote", "Only non-secret account identifiers are included.")]
    lines += ["Played / Historical Roblox IDs:"]
    if not account_context.get("roblox"):
        lines.append("No Roblox account identifiers found.")
    for account in account_context.get("roblox", []):
        lines.append(
            f"Roblox ID={account.get('userId') or 'unknown'} Username={account.get('username') or 'Unknown'} "
            f"First={account.get('firstSeen') or ''} Last={account.get('lastSeen') or ''} Sources={'; '.join(account.get('sources', [])[:4])}"
        )
    lines += ["Discord Account Evidence:"]
    if not account_context.get("discord"):
        lines.append("No Discord account identifiers found.")
    for account in account_context.get("discord", []):
        lines.append(
            f"Discord ID={account.get('userId') or 'unknown'} Username={account.get('username') or 'Unknown'} "
            f"First={account.get('firstSeen') or ''} Last={account.get('lastSeen') or ''} Sources={'; '.join(account.get('sources', [])[:4])}"
        )
    discord_status = account_context.get("discordStatus", {}) if isinstance(account_context.get("discordStatus"), dict) else {}
    if discord_status:
        lines.append(
            f"Discord log scan status: files_found={discord_status.get('logFilesFound', 0)} "
            f"files_scanned={discord_status.get('logFilesScanned', 0)} "
            f"candidate_ids={discord_status.get('candidateIdsFound', 0)} bytes_read={discord_status.get('bytesRead', 0)}"
        )
    lines += ["", "Detected FastFlags", "------------------"]
    if not report.get("detectedFastFlags"):
        lines.append("No FastFlags detected in captured Roblox logs.")
    for flag in report.get("detectedFastFlags", []):
        lines.append(f"{flag.get('timestamp')} {flag.get('name')}={flag.get('value')} Source={flag.get('sourceLog')} Place={flag.get('placeId')} Job={flag.get('jobId')}")
    lines += ["", "All Roblox Logs", "---------------"]
    if not report.get("robloxLogs"):
        lines.append("No raw Roblox logs captured.")
    for item in report.get("robloxLogs", []):
        lines += [
            f"Log: {item.get('logFile')}",
            f"Start: {item.get('startTime')} End: {item.get('endTime')} Duration: {item.get('duration')}",
            f"User: {item.get('username')} ({item.get('userId')}) Place: {item.get('placeId')} Job: {item.get('jobId')}",
            "Events:",
        ]
        for event in item.get("events", []):
            lines.append(f"  {event.get('timestamp')} [{event.get('type')}] {event.get('message')}")
        lines += ["Raw Roblox Log:", item.get("rawLog", ""), ""]
    lines += ["", "USN Journal Events", "------------------"]
    usn_status = report.get("usnJournalStatus", {}) if isinstance(report.get("usnJournalStatus"), dict) else {}
    if usn_status:
        lines.append(
            f"Status: available={usn_status.get('available')} readable={usn_status.get('readable')} "
            f"records={usn_status.get('recordsCollected', 0)} error={usn_status.get('error', '')}"
        )
    if not report.get("usnJournalEvents"):
        lines.append("No USN Change Journal events were available.")
    for item in report.get("usnJournalEvents", []):
        lines.append(
            f"{item.get('timestamp')} {item.get('eventType')} {item.get('fileName')} "
            f"Reason={item.get('reason')} USN={item.get('usn')} Parent={item.get('parentFileId')}"
        )
    lines += ["", "ShellBag Analyzer", "-----------------"]
    if not report.get("shellBagArtifacts"):
        lines.append("No SBECmd ShellBag artifacts were available.")
    for item in report.get("shellBagArtifacts", []):
        lines.append(
            f"{item.get('timestamp')} [{item.get('classification')}] {item.get('path')} "
            f"ShellType={item.get('shellType')} Hive={item.get('sourceHive')} "
            f"Slot={item.get('slot')} MRU={item.get('mruPosition')}"
        )
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
    lines += ["Defender Exclusions", "-------------------"]
    if not report.get("defenderExclusions"):
        lines.append("No Defender exclusions were found or accessible.")
    for item in report.get("defenderExclusions", []):
        reasons = "; ".join(item.get("reasons", [])) if isinstance(item.get("reasons"), list) else ""
        lines.append(f"{item.get('type')} {item.get('severity')} ManualReview={'yes' if item.get('manualReviewRequired') else 'no'}: {item.get('value')} {reasons}")
    lines.append("")
    lines += ["Engines", "-------"]
    if not report.get("engineResults"):
        lines.append("No engine heuristic results found.")
    for item in report.get("engineResults", [])[:40]:
        lines.append(f"{item.get('detectabilityRange')} score={item.get('localHeuristicScore')} VT={item.get('virusTotalStatus')} {item.get('path')}")
    lines.append("")
    lines += ["Key Artifacts", "-------------"]
    if not report.get("keyArtifacts"):
        lines.append("No Prefetch or deleted-file key artifacts found.")
    for item in report.get("keyArtifacts", []):
        lines.append(f"{item.get('timestamp')} [{item.get('type')}] {item.get('label')} Source={item.get('source')} Confidence={item.get('confidence')}")
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
    sessions = [{"Username": s.get("username", "Unknown"), "Display Name": s.get("displayName", ""), "User ID": s.get("userId", ""), "Place ID": s.get("placeId", ""), "Job ID": s.get("jobId", ""), "Duration": s.get("duration", ""), "Status": s.get("status", "Clean"), "Timestamp": s.get("launchTime", "")} for s in report["sessions"]]
    fastflag_rows = [{
        "FastFlag": f.get("name", ""),
        "Value": f.get("value", ""),
        "Source Log": f.get("sourceLog", ""),
        "Timestamp": f.get("timestamp", ""),
        "Place ID": f.get("placeId", ""),
        "Job ID": f.get("jobId", ""),
    } for f in report.get("detectedFastFlags", [])]
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
    defender_exclusion_rows = [{
        "Type": item.get("type", ""),
        "Value": item.get("value", ""),
        "Severity": item.get("severity", ""),
        "Manual Review": "yes" if item.get("manualReviewRequired") else "no",
        "Reasons": "; ".join(item.get("reasons", [])) if isinstance(item.get("reasons"), list) else "",
        "Source": item.get("source", ""),
    } for item in report.get("defenderExclusions", [])]
    engine_rows = [{
        "File": e.get("file", ""),
        "Score": e.get("localHeuristicScore", ""),
        "Local Hits": e.get("localEngineHits", ""),
        "Detectability": e.get("detectabilityRange", ""),
        "VirusTotal": e.get("virusTotalStatus", ""),
        "Manual Review": "yes" if e.get("manualReviewRequired") else "no",
    } for e in report.get("engineResults", [])[:60]]
    key_artifact_rows = [{
        "Type": item.get("type", ""),
        "Artifact": item.get("label", ""),
        "Path": item.get("path", ""),
        "Timestamp": item.get("timestamp", ""),
        "Source": item.get("source", ""),
        "Confidence": item.get("confidence", ""),
    } for item in report.get("keyArtifacts", [])]
    usn_rows = [{
        "Timestamp": item.get("timestamp", ""),
        "Event": item.get("eventType", ""),
        "File": item.get("fileName", ""),
        "Reason": item.get("reason", ""),
        "USN": item.get("usn", ""),
        "Parent ID": item.get("parentFileId", ""),
    } for item in report.get("usnJournalEvents", [])]
    usn_status = report.get("usnJournalStatus", {}) if isinstance(report.get("usnJournalStatus"), dict) else {}
    usn_status_rows = [{
        "Available": usn_status.get("available", ""),
        "Readable": usn_status.get("readable", ""),
        "Records": usn_status.get("recordsCollected", ""),
        "Volume": usn_status.get("volume", ""),
        "Read Command": usn_status.get("readCommand", ""),
        "Status/Error": usn_status.get("error", ""),
    }] if usn_status else []
    shellbag_rows = [{
        "Timestamp": item.get("timestamp", ""),
        "Classification": item.get("classification", ""),
        "Path": item.get("path", ""),
        "Shell Type": item.get("shellType", ""),
        "Source Hive": item.get("sourceHive", ""),
        "Slot": item.get("slot", ""),
        "MRU": item.get("mruPosition", ""),
    } for item in report.get("shellBagArtifacts", [])]
    account_context = report.get("accountIdentifiers", {}) if isinstance(report.get("accountIdentifiers"), dict) else {}
    discord_status = account_context.get("discordStatus", {}) if isinstance(account_context.get("discordStatus"), dict) else {}
    discord_status_rows = [{
        "Log Files Found": discord_status.get("logFilesFound", ""),
        "Log Files Scanned": discord_status.get("logFilesScanned", ""),
        "Candidate IDs": discord_status.get("candidateIdsFound", ""),
        "Bytes Read": discord_status.get("bytesRead", ""),
        "Note": discord_status.get("note", ""),
    }] if discord_status else []
    account_rows = []
    for row in account_context.get("roblox", []):
        sources = row.get("sources", []) if isinstance(row.get("sources"), list) else []
        account_rows.append({
            "Platform": row.get("platform", ""),
            "User ID": row.get("userId", ""),
            "Username": row.get("username", ""),
            "Display Name": row.get("displayName", ""),
            "First Seen": row.get("firstSeen", ""),
            "Last Seen": row.get("lastSeen", ""),
            "Places": ", ".join(row.get("places", [])[:12]) if isinstance(row.get("places"), list) else "",
            "Sources": "; ".join(sources[:8]),
            "Sources List": sources,
        })
    discord_account_rows = []
    for row in account_context.get("discord", []):
        sources = row.get("sources", []) if isinstance(row.get("sources"), list) else []
        discord_account_rows.append({
            "Platform": row.get("platform", "Discord"),
            "User ID": row.get("userId", ""),
            "Username": row.get("username", ""),
            "Display Name": row.get("displayName", ""),
            "First Seen": row.get("firstSeen", ""),
            "Last Seen": row.get("lastSeen", ""),
            "Sources": "; ".join(sources[:8]),
            "Sources List": sources,
            "Evidence Note": row.get("evidenceNote", ""),
        })

    played_account_ids = set()
    for session in report.get("sessions", []):
        user_id = re.sub(r"\D", "", str(session.get("userId") or ""))
        if user_id and (session.get("placeId") or session.get("gameId") or session.get("jobId") or session.get("launchTime") or session.get("exitTime")):
            played_account_ids.add(user_id)
    for log in report.get("robloxLogs", []):
        user_id = re.sub(r"\D", "", str(log.get("userId") or ""))
        events = log.get("events", []) if isinstance(log.get("events"), list) else []
        event_text = " ".join(str(e.get("type", "")) + " " + str(e.get("message", "")) for e in events if isinstance(e, dict)).lower()
        has_play_evidence = bool(log.get("placeId") or log.get("jobId") or any(token in event_text for token in ["join", "place", "teleport", "game_join"]))
        if user_id and has_play_evidence:
            played_account_ids.add(user_id)

    account_groups = {"played": [], "historical": [], "weak": []}
    for row in account_rows:
        user_id = re.sub(r"\D", "", str(row.get("User ID") or ""))
        sources = row.get("Sources List", []) if isinstance(row.get("Sources List"), list) else []
        has_crash_source = any(re.search(r"crashes?[\\/]+attachments?|crash", str(source), re.I) for source in sources)
        all_crash_sources = bool(sources) and all(re.search(r"crashes?[\\/]+attachments?|crash", str(source), re.I) for source in sources)
        same_single_timestamp = bool(has_crash_source and row.get("First Seen") and row.get("First Seen") == row.get("Last Seen"))
        if user_id and user_id in played_account_ids:
            account_groups["played"].append(row)
        elif all_crash_sources or same_single_timestamp:
            account_groups["weak"].append(row)
        else:
            account_groups["historical"].append(row)

    def account_card(row: dict, id_label: str = "Roblox User ID") -> str:
        places = f"<p>Place IDs: {html.escape(str(row.get('Places') or ''))}</p>" if row.get("Places") else ""
        evidence_note = f"<p>{html.escape(str(row.get('Evidence Note') or ''))}</p>" if row.get("Evidence Note") else ""
        return (
            f"<div class='account-card report-entry'{html_data_timestamp(row.get('Last Seen'))}>"
            f"<b>{html.escape(str(row.get('Platform') or 'Roblox'))}</b>"
            f"<small>{html.escape(id_label)}</small>"
            f"<div class='account-id'>{html.escape(str(row.get('User ID') or 'ID unavailable'))}</div>"
            f"<p><b>Username:</b> {html.escape(str(row.get('Username') or 'Unknown'))}</p>"
            f"<p><b>Display Name:</b> {html.escape(str(row.get('Display Name') or 'Unknown'))}</p>"
            f"<p>First evidence: {html.escape(str(row.get('First Seen') or 'Unavailable'))}</p>"
            f"<p>Last evidence: {html.escape(str(row.get('Last Seen') or 'Unavailable'))}</p>"
            f"{places}"
            f"{evidence_note}"
            f"<p>Sources: {html.escape(str(row.get('Sources') or 'Unavailable'))}</p>"
            f"</div>"
        )

    def account_group_html(title: str, description: str, rows: list[dict], id_label: str = "Roblox User ID") -> str:
        cards = "".join(account_card(row, id_label) for row in rows)
        body = cards or "<p class='muted'>None.</p>"
        return (
            f"<div class='account-group'>"
            f"<h3>{html.escape(title)}</h3>"
            f"<p class='muted'>{html.escape(description)}</p>"
            f"{body}"
            f"</div>"
        )

    account_cards_html = "".join([
        account_group_html("Played Accounts", "Accounts tied to Roblox session, join, place, or teleport evidence in the available logs.", account_groups["played"], "Roblox User ID"),
        account_group_html("Historical Account IDs Found", "IDs found in Roblox logs or metadata, but not enough evidence to say this scan proved active play.", account_groups["historical"], "Roblox User ID"),
        account_group_html("Weak/Old Account Artifacts", "Old crash or residue-only account artifacts. These are context only and should not be treated as proof of play.", account_groups["weak"], "Roblox User ID"),
        account_group_html("Discord Account Evidence", "Safe Discord log identifier evidence only. Tokens, cookies, Local Storage, IndexedDB, Session Storage, cache, DMs, private messages, friend lists, and server lists are excluded.", discord_account_rows, "Discord User ID"),
    ])
    reset_rows = [{
        "Type": item.get("type", ""),
        "Timestamp": item.get("timestamp", ""),
        "Source": item.get("source", ""),
        "Details": item.get("details", ""),
    } for item in report.get("systemResetEvidence", [])]
    install_rows = [{
        "Product": item.get("productName", ""),
        "Release": item.get("releaseId", ""),
        "Build": item.get("currentBuild", ""),
        "Install Date": item.get("installDate", ""),
    } for item in report.get("windowsInstallHistory", [])]
    sysmain = report.get("sysMainService", {}) if isinstance(report.get("sysMainService"), dict) else {}
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
    roblox_log_html = ""
    for item in report.get("robloxLogs", []):
        events = "".join(
            f"<li class='report-entry'{html_data_timestamp(event.get('timestamp'))}><time>{html.escape(str(event.get('timestamp', '')))}</time><span>{html.escape(str(event.get('message', '')))}</span><small>{html.escape(str(event.get('type', '')))}</small></li>"
            for event in item.get("events", [])
        )
        per_log_flags = html_table([{
            "FastFlag": flag.get("name", ""),
            "Value": flag.get("value", ""),
            "Timestamp": flag.get("timestamp", ""),
            "Source Log": flag.get("sourceLog", ""),
        } for flag in item.get("fastFlags", [])], ["FastFlag", "Value", "Timestamp", "Source Log"], "Timestamp")
        roblox_log_html += (
            f"<details class='report-entry' open{html_data_timestamp(item.get('startTime') or item.get('modifiedTime'))}>"
            f"<summary>{html.escape(Path(str(item.get('logFile', 'Roblox log'))).name)} - {html.escape(str(item.get('startTime') or item.get('modifiedTime') or 'unknown time'))}</summary>"
            f"<p><b>Place ID:</b> {html.escape(str(item.get('placeId', '')))} <b>Job ID:</b> {html.escape(str(item.get('jobId', '')))} <b>User ID:</b> {html.escape(str(item.get('userId', '')))}</p>"
            f"<h4>Detected FastFlags in this log</h4>{per_log_flags}"
            f"<h4>Captured Roblox Events</h4><ul class='timeline'>{events or '<li>No structured events extracted.</li>'}</ul>"
            f"<h4>Raw Roblox Log</h4><pre>{html.escape(str(item.get('rawLog', '')))}</pre>"
            f"</details>"
        )
    reset_list_html = "".join(
        f"<div class='reset-entry report-entry'{html_data_timestamp(item.get('Timestamp'))}>"
        f"<b>{html.escape(str(item.get('Type') or 'Reset/install evidence'))}</b>"
        f"<time>{html.escape(str(item.get('Timestamp') or 'Time unavailable'))}</time>"
        f"<small>{html.escape(str(item.get('Source') or 'Windows evidence'))}</small>"
        f"</div>"
        for item in reset_rows[:12]
    )
    install_list_html = "".join(
        f"<div class='reset-entry report-entry'{html_data_timestamp(item.get('Install Date'))}>"
        f"<b>{html.escape(str(item.get('Product') or 'Windows'))}</b>"
        f"<small>Release: {html.escape(str(item.get('Release') or 'Unknown'))} | Build: {html.escape(str(item.get('Build') or 'Unknown'))}</small>"
        f"<time>{html.escape(str(item.get('Install Date') or 'Install time unavailable'))}</time>"
        f"</div>"
        for item in install_rows[:8]
    )
    service_panel_html = (
        f"<div class='card'><b>{html.escape(str(sysmain.get('serviceName') or 'SysMain'))}</b>"
        f"<p>Current State: {html.escape(str(sysmain.get('currentState') or 'Unavailable'))}</p>"
        f"<p>Startup Type: {html.escape(str(sysmain.get('startupType') or 'Unavailable'))}</p>"
        f"<p>Last Changed: {html.escape(str(sysmain.get('lastChanged') or 'Could not determine'))}</p></div>"
    )
    defender_exclusion_panel_html = html_table(defender_exclusion_rows[:8], ["Type", "Value", "Severity", "Manual Review", "Reasons", "Source"])
    raw = html.escape(json.dumps(report, indent=2))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{APP_NAME} Report</title>
<style>
body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f5f7f9;color:#15191f}}header{{background:#111827;color:white;padding:24px 32px}}main{{max-width:1180px;margin:auto;padding:24px}}section{{background:white;border:1px solid #d8dee6;border-radius:8px;margin:16px 0;padding:18px}}.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card{{border:1px solid #d8dee6;border-radius:8px;padding:14px;background:#fbfcfd}}.value{{font-size:24px;font-weight:700}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{border-bottom:1px solid #e7ebf0;padding:8px;text-align:left;vertical-align:top}}th{{background:#f0f3f6}}.account-group{{margin:18px 0}}.account-card{{border:1px solid #d8dee6;border-radius:8px;padding:14px;margin:10px 0;background:#fbfcfd}}.account-card small{{display:block;color:#667085;margin-top:12px}}.account-id{{color:#16a34a;font-size:28px;font-weight:700;overflow-wrap:anywhere;margin:3px 0 12px}}.timeline-reset-grid{{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:16px;align-items:start}}.timeline-reset-grid section{{margin:0}}.timeline-reset-grid>aside{{display:grid;gap:12px}}.timeline li{{display:grid;grid-template-columns:170px minmax(0,1fr) 130px;gap:12px;padding:8px 10px;border-bottom:1px solid #edf0f3;overflow:hidden}}.timeline span{{min-width:0;overflow-wrap:anywhere;word-break:break-word}}.timeline small{{white-space:nowrap;color:#667085}}.reset-entry{{border-left:3px solid #16a34a;padding:4px 0 8px 10px;margin:10px 0}}.reset-entry time,.reset-entry small{{display:block;color:#667085;font-size:12px;margin-top:3px;overflow-wrap:anywhere}}.muted{{color:#667085}}.true{{color:#157347}}.false{{color:#b42318}}details{{border:1px solid #d8dee6;border-radius:8px;padding:10px;margin:10px 0}}summary{{font-weight:700;cursor:pointer}}pre{{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e5e7eb;padding:12px;border-radius:8px;max-height:520px;overflow:auto}}.warn{{border:1px solid #dc2626;background:#fee2e2;color:#7f1d1d;border-radius:8px;padding:12px;margin:10px 0}}.confidence-possible{{border-left:4px solid #9ca3af!important;background:#f9fafb}}.confidence-likely{{border-left:4px solid #f59e0b!important;background:#fffbeb}}.confidence-confirmed{{border-left:4px solid #dc2626!important;background:#fee2e2;color:#7f1d1d}}.filters{{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px}}.pill{{border:1px solid #d8dee6;border-radius:999px;padding:5px 10px;background:#fbfcfd;font-size:12px}}@media(max-width:800px){{.timeline-reset-grid{{grid-template-columns:1fr}}}}
</style></head><body><header><h1>{APP_NAME} Report</h1><p>No confirmed result means only that available logs did not prove it. Logging coverage may be incomplete.</p></header><main>
<section><h2>Summary</h2><div class="summary"><div class="card"><div>Scan Date</div><div class="value">{html.escape(report['scanTime'])}</div></div><div class="card"><div>Highest Result</div><div class="value">{report['highestResult']}</div></div><div class="card"><div>Top Score</div><div class="value">{report.get('topScore', 0)}</div></div><div class="card"><div>Roblox Sessions</div><div class="value">{len(report['sessions'])}</div></div></div></section>
<section><h2>Primary Roblox Account</h2><div class="summary"><div class="card"><div>User</div><div class="value">{html.escape(primary_session.get('username', 'Unknown'))}</div></div><div class="card"><div>User ID</div><div class="value">{html.escape(primary_session.get('userId', ''))}</div></div><div class="card"><div>Place ID</div><div class="value">{html.escape(primary_session.get('placeId', ''))}</div></div><div class="card"><div>Injection Evidence</div><div class="value">{html.escape(report['highestResult'] if report['highestResult'] in ['Confirmed Exploit','Suspicious'] else 'Not confirmed')}</div></div></div></section>
<section><h2>Top Suspicious Processes</h2>{html_table(top_rows, ['Process','Path','Score','Classification','Signer','First Seen','Reason'], 'First Seen')}</section>
<section><h2>Key Artifacts</h2><p class="muted">Prefetch and deleted-file artifacts are listed here as key scan evidence. These are review artifacts, not automatic proof by themselves.</p>{html_table(key_artifact_rows, ['Type','Artifact','Path','Timestamp','Source','Confidence'], 'Timestamp')}</section>
<section><h2>USN Journal Events</h2><p class="muted">Recent bounded NTFS create, delete, rename, and modify records. Normal file activity is not proof of cheating.</p>{html_table(usn_status_rows, ['Available','Readable','Records','Volume','Read Command','Status/Error'])}{html_table(usn_rows, ['Timestamp','Event','File','Reason','USN','Parent ID'], 'Timestamp')}</section>
<section><h2>ShellBag Analyzer</h2><p class="muted">Read-only folder history exported by SBECmd. ShellBag presence shows folder interaction context and is not proof that a program executed.</p>{html_table(shellbag_rows, ['Timestamp','Classification','Path','Shell Type','Source Hive','Slot','MRU'], 'Timestamp')}</section>
<section><h2>Forensic Correlation Findings</h2><p class="muted">These findings are built from multiple artifacts lining up in time, not from a single filename, hash, or keyword.</p>{correlation_html}</section>
<section><h2>Interaction / Detect Logs</h2><div class="filters">{''.join(f"<span class='pill'>{x}</span>" for x in DETECT_LOG_TYPES)}</div>{html_table(detect_rows, ['Type','Detection','Severity','Confidence','Manual Review','Evidence','Timestamp','Explanation'], 'Timestamp')}</section>
<section><h2>Warning Logs</h2><p class="muted">Warnings indicate modifications or behaviors that may reduce confidence or require review. They are not automatically cheating evidence.</p>{html_table(warning_rows, ['Detection','Severity','Confidence','Manual Review','Source','Timestamp','Explanation'], 'Timestamp')}</section>
<section><h2>Recovery</h2>{html_table(recovery_rows, ['Name','Path','Source','Timestamp','Manual Review'], 'Timestamp')}</section>
<section><h2>Antivirus Logs</h2>{html_table(antivirus_rows, ['Source','Detection','Severity','Timestamp','Path'], 'Timestamp')}</section>
<section><h2>Defender Exclusions</h2><p class="muted">Configured AV exclusions. Review entries can hide executor folders from Defender, but exclusions are not proof by themselves.</p>{html_table(defender_exclusion_rows, ['Type','Value','Severity','Manual Review','Reasons','Source'])}</section>
<section><h2>Engines</h2>{html_table(engine_rows, ['File','Score','Local Hits','Detectability','VirusTotal','Manual Review'])}</section>
<section><h2>Roblox Account History</h2><p class="muted">{html.escape(str(account_context.get('privacyNote', 'Only non-secret Roblox account identifiers are included.')))}</p>{html_table(discord_status_rows, ['Log Files Found','Log Files Scanned','Candidate IDs','Bytes Read','Note'])}{account_cards_html or "<p class='muted'>No Roblox account identifiers were available.</p>"}</section>
<section><h2>Detected FastFlags</h2><p class="muted">FastFlags are grouped with the Roblox log where they were found.</p>{html_table(fastflag_rows, ['FastFlag','Value','Source Log','Timestamp','Place ID','Job ID'], 'Timestamp')}</section>
<section><h2>Show All Roblox Logs</h2><p class="muted">Expand each log to inspect every captured Roblox event and the raw log text.</p>{roblox_log_html or "<p class='muted'>No raw Roblox logs were captured.</p>"}</section>
<div class="timeline-reset-grid"><section><h2>Timeline</h2><ul class="timeline">{timeline or "<p class='muted'>No timeline events found.</p>"}</ul></section><aside><section><h2>Factory Reset Information</h2><p class="muted">Install records may represent a reset, reinstall, or major Windows upgrade.</p>{install_list_html or reset_list_html or "<p class='muted'>No Windows installation records were available.</p>"}</section><section><h2>Services</h2>{service_panel_html}</section><section><h2>Defender Exclusions</h2><p class="muted">Configured AV exclusions. Review entries can hide executor folders from Defender.</p>{defender_exclusion_panel_html}</section></aside></div>
<section><h2>Findings</h2>{findings_html}</section>
<section><h2>Evidence Limitations</h2><ul>{quality}</ul></section>
<section><h2>Raw Artifacts</h2><pre>{raw}</pre></section>
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
    return True, {
        "sessionId": data["pinId"],
        "uploadToken": pin,
        "scanProfile": normalize_scan_profile(data.get("scanProfile") or data.get("scan_profile")),
    }


def upload_report(api_base_url: str, session_id: str, upload_token: str, report: dict) -> tuple[bool, str]:
    url = api_base_url.rstrip("/") + "/api/upload-report"
    report = json_safe(report)
    upload_report_data = compact_report_for_upload(report)
    payload = {
        "pin": upload_token,
        "hostname": upload_report_data.get("hostname", ""),
        "riskLevel": upload_report_data.get("highestResult", ""),
        "evidenceScore": int(upload_report_data.get("topScore", 0) or 0),
        "reportData": upload_report_data,
    }
    ok, data = post_json(url, payload, timeout=20, retries=2)
    if ok and isinstance(data, dict) and data.get("ok"):
        return True, "ok"
    error_text = json.dumps(data)[:500] if ok else str(data)
    if any(marker in error_text.lower() for marker in ["413", "payload", "too large", "statement timeout", "function_payload_too_large"]):
        minimal_report_data = compact_report_for_upload(report, max_bytes=250_000)
        minimal_report_data["uploadRetryCompacted"] = True
        retry_payload = {
            "pin": upload_token,
            "hostname": minimal_report_data.get("hostname", ""),
            "riskLevel": minimal_report_data.get("highestResult", ""),
            "evidenceScore": int(minimal_report_data.get("topScore", 0) or 0),
            "reportData": minimal_report_data,
        }
        retry_ok, retry_data = post_json(url, retry_payload, timeout=20, retries=1)
        if retry_ok and isinstance(retry_data, dict) and retry_data.get("ok"):
            return True, "ok_compacted_retry"
        if retry_ok:
            return False, json.dumps(retry_data)[:300]
        return False, str(retry_data)
    if ok:
        return False, json.dumps(data)[:300]
    return False, str(data)


def compact_roblox_logs_for_upload(logs: list, limit: int, include_raw: bool) -> list:
    compacted = []
    for item in logs[:limit]:
        if not isinstance(item, dict):
            continue
        row = {
            "logFile": item.get("logFile", ""),
            "modifiedTime": item.get("modifiedTime", ""),
            "startTime": item.get("startTime", ""),
            "endTime": item.get("endTime", ""),
            "duration": item.get("duration", ""),
            "placeId": item.get("placeId", ""),
            "jobId": item.get("jobId", ""),
            "userId": item.get("userId", ""),
            "username": item.get("username", ""),
            "displayName": item.get("displayName", ""),
            "version": item.get("version", ""),
            "events": list(item.get("events", []))[:80],
            "fastFlags": list(item.get("fastFlags", []))[:120],
            "loadClientSettings": list(item.get("loadClientSettings", []))[:40],
            "errors": list(item.get("errors", []))[:25],
            "crashes": list(item.get("crashes", []))[:25],
        }
        if include_raw:
            row["rawLog"] = item.get("rawLog", "")
        else:
            row["rawLog"] = ""
            row["rawLogOmittedForUpload"] = True
            row["rawLogApproxBytes"] = len(str(item.get("rawLog", "")).encode("utf-8", errors="replace"))
        compacted.append(row)
    return compacted


def compact_sessions_for_upload(sessions: list, limit: int) -> list:
    compacted = []
    for item in sessions[:limit]:
        if not isinstance(item, dict):
            continue
        compacted.append({
            "game": item.get("game", ""),
            "gameId": item.get("gameId", ""),
            "placeId": item.get("placeId", ""),
            "jobId": item.get("jobId", ""),
            "userId": item.get("userId", ""),
            "username": item.get("username", ""),
            "displayName": item.get("displayName", ""),
            "launchTime": item.get("launchTime", item.get("startTime", "")),
            "exitTime": item.get("exitTime", item.get("endTime", "")),
            "duration": item.get("duration", ""),
            "status": item.get("status", ""),
            "version": item.get("version", ""),
            "linkedDetections": list(item.get("linkedDetections", []))[:20],
            "fastFlags": list(item.get("fastFlags", []))[:40],
            "loadClientSettings": list(item.get("loadClientSettings", []))[:20],
            "events": list(item.get("events", []))[:30],
            "errors": list(item.get("errors", []))[:10],
            "crashes": list(item.get("crashes", []))[:10],
            "suspiciousLines": list(item.get("suspiciousLines", []))[:10],
            "robloxLogsOmittedForUpload": bool(item.get("robloxLogs")),
            "robloxLogsCount": len(item.get("robloxLogs", [])) if isinstance(item.get("robloxLogs"), list) else 0,
        })
    return compacted


def compact_report_for_upload(report: dict, max_bytes: int = 900_000) -> dict:
    try:
        encoded = json.dumps(report, separators=(",", ":"), default=str).encode("utf-8", errors="replace")
    except Exception:
        return report
    if len(encoded) <= max_bytes:
        return report

    compacted = dict(report)
    limitations = list(compacted.get("limitations", []))
    limitations.append("Large scan report was compacted for website upload. The full report remains saved locally on the scanned PC.")
    compacted["limitations"] = limitations
    compacted["uploadCompacted"] = True
    compacted["originalApproxBytes"] = len(encoded)

    # Vercel rejects large function payloads before the API route can store them.
    # Keep the website report useful, but reserve the complete report for local files.
    size_profiles = [
        {"timeline": 700, "keyArtifacts": 500, "sessions": 120, "findings": 350, "detectLogs": 350, "warningLogs": 120, "recoveryArtifacts": 120, "antivirusLogs": 160, "defenderExclusions": 80, "engineResults": 300, "rawArtifacts": 80, "robloxLogs": 80, "fastFlags": 800, "usnEvents": 1200, "shellbags": 800, "rawRoblox": False},
        {"timeline": 350, "keyArtifacts": 250, "sessions": 80, "findings": 180, "detectLogs": 180, "warningLogs": 80, "recoveryArtifacts": 80, "antivirusLogs": 100, "defenderExclusions": 60, "engineResults": 150, "rawArtifacts": 40, "robloxLogs": 40, "fastFlags": 500, "usnEvents": 600, "shellbags": 400, "rawRoblox": False},
        {"timeline": 150, "keyArtifacts": 120, "sessions": 40, "findings": 80, "detectLogs": 80, "warningLogs": 40, "recoveryArtifacts": 40, "antivirusLogs": 60, "defenderExclusions": 40, "engineResults": 80, "rawArtifacts": 20, "robloxLogs": 20, "fastFlags": 250, "usnEvents": 250, "shellbags": 180, "rawRoblox": False},
    ]
    for profile in size_profiles:
        compacted["timeline"] = list(report.get("timeline", []))[-profile["timeline"]:]
        compacted["keyArtifacts"] = list(report.get("keyArtifacts", []))[:profile["keyArtifacts"]]
        compacted["sessions"] = compact_sessions_for_upload(list(report.get("sessions", [])), profile["sessions"])
        compacted["findings"] = select_upload_findings(report.get("findings", []), limit=profile["findings"])
        compacted["detectLogs"] = list(report.get("detectLogs", []))[:profile["detectLogs"]]
        compacted["warningLogs"] = list(report.get("warningLogs", []))[:profile["warningLogs"]]
        compacted["recoveryArtifacts"] = list(report.get("recoveryArtifacts", []))[:profile["recoveryArtifacts"]]
        compacted["antivirusLogs"] = list(report.get("antivirusLogs", []))[:profile["antivirusLogs"]]
        compacted["defenderExclusions"] = list(report.get("defenderExclusions", []))[:profile["defenderExclusions"]]
        compacted["engineResults"] = list(report.get("engineResults", []))[:profile["engineResults"]]
        compacted["accountIdentifiers"] = compact_account_identifiers(report.get("accountIdentifiers", {}))
        compacted["systemResetEvidence"] = list(report.get("systemResetEvidence", []))[:80]
        compacted["robloxLogs"] = compact_roblox_logs_for_upload(list(report.get("robloxLogs", [])), profile["robloxLogs"], include_raw=profile["rawRoblox"])
        compacted["detectedFastFlags"] = list(report.get("detectedFastFlags", []))[:profile["fastFlags"]]
        compacted["usnJournalEvents"] = list(report.get("usnJournalEvents", []))[:profile["usnEvents"]]
        compacted["usnJournalStatus"] = report.get("usnJournalStatus", {})
        compacted["shellBagArtifacts"] = list(report.get("shellBagArtifacts", []))[:profile["shellbags"]]
        if isinstance(compacted.get("rawArtifacts"), list):
            compacted["rawArtifacts"] = list(report.get("rawArtifacts", []))[:profile["rawArtifacts"]]
        try:
            if len(json.dumps(compacted, separators=(",", ":"), default=str).encode("utf-8", errors="replace")) <= max_bytes:
                return compacted
        except Exception:
            return compacted

    compacted["timeline"] = list(report.get("timeline", []))[-80:]
    compacted["keyArtifacts"] = list(report.get("keyArtifacts", []))[:80]
    compacted["sessions"] = compact_sessions_for_upload(list(report.get("sessions", [])), 20)
    compacted["findings"] = select_upload_findings(report.get("findings", []), limit=40)
    compacted["detectLogs"] = list(report.get("detectLogs", []))[:40]
    compacted["warningLogs"] = list(report.get("warningLogs", []))[:20]
    compacted["recoveryArtifacts"] = list(report.get("recoveryArtifacts", []))[:20]
    compacted["antivirusLogs"] = list(report.get("antivirusLogs", []))[:30]
    compacted["defenderExclusions"] = list(report.get("defenderExclusions", []))[:20]
    compacted["engineResults"] = list(report.get("engineResults", []))[:40]
    compacted["accountIdentifiers"] = compact_account_identifiers(report.get("accountIdentifiers", {}))
    compacted["systemResetEvidence"] = list(report.get("systemResetEvidence", []))[:40]
    compacted["robloxLogs"] = compact_roblox_logs_for_upload(list(report.get("robloxLogs", [])), 10, include_raw=False)
    compacted["detectedFastFlags"] = list(report.get("detectedFastFlags", []))[:120]
    compacted["usnJournalEvents"] = list(report.get("usnJournalEvents", []))[:100]
    compacted["usnJournalStatus"] = report.get("usnJournalStatus", {})
    compacted["shellBagArtifacts"] = list(report.get("shellBagArtifacts", []))[:80]
    if isinstance(compacted.get("rawArtifacts"), list):
        compacted["rawArtifacts"] = []
    return compacted


def compact_account_identifiers(value) -> dict:
    if not isinstance(value, dict):
        return {"privacyNote": "Only non-secret Roblox and Discord account identifiers are included.", "roblox": [], "discord": []}
    return {
        "privacyNote": value.get("privacyNote", "Only non-secret Roblox and Discord account identifiers are included."),
        "roblox": list(value.get("roblox", []))[:80],
        "discord": list(value.get("discord", []))[:80],
        "discordStatus": value.get("discordStatus", {}),
    }


def select_upload_findings(findings: list, limit: int) -> list:
    def priority(finding: dict) -> tuple[int, int]:
        text = f"{finding.get('classification', '')} {finding.get('confidenceLevel', '')}".lower()
        if "confirmed" in text:
            rank = 0
        elif "suspicious" in text or "likely" in text:
            rank = 1
        else:
            rank = 2
        return rank, -int(finding.get("score", 0) or 0)

    normalized = [item for item in findings if isinstance(item, dict)]
    return sorted(normalized, key=priority)[:limit]


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
            icon_path = resource_path("assets/securo.ico")
            if icon_path.exists():
                root.iconbitmap(str(icon_path))
        except Exception:
            pass
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
    if not ensure_windows_admin():
        return 0
    return gui_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
