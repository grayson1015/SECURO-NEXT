import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
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
}
WARNING_DETECTION_CATEGORIES = {
    "Virtualization Check",
    "ActivitiesCache Disabled",
    "RUIN Mode Warning",
    "Manual Review Required",
}
EXPLOIT_FAMILY_TERMS = {
    "xeno",
    "xenoui",
    "synapse",
    "krnl",
    "fluxus",
    "solara",
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
}
VIRTUALIZATION_TERMS = ("qemu", "vmware", "sandboxie", "parallels", "virtualbox", "virtual pc", "vbox")
NETWORK_PATH_PREFIXES = ("\\\\", "file://")
EXTERNAL_DRIVE_LETTERS = set("DEFGHIJKLMNOPQRSTUVWXYZ")
TRUST_DAMPEN_SIGNERS = (
    "Roblox Corporation",
    "Microsoft Corporation",
    "Microsoft Windows",
    "Logitech",
    "Razer",
    "Corsair",
    "NVIDIA Corporation",
    "MeldaProduction",
    "Spotify",
    "Proton",
    "Python Software Foundation",
)
COMMON_DEPENDENCY_NAMES = (
    "sqlite3.dll",
    "libcrypto",
    "python312.dll",
    "python3.dll",
    "libffi",
    "vcruntime",
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
REAL_BEHAVIOR_EVIDENCE_TYPES = {
    "sysmon_remote_thread",
    "sysmon_process_access",
    "suspicious_module_load",
    "persistence",
    "powershell_history",
    "prefetch",
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
    return config


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
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace")
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
        "classification": "Weak",
    }
    if is_known_safe_signer(signer, config):
        add_score(finding, config["score_rules"]["known_safe_signer"], "Signed by known-safe signer")
    elif signer.get("status", "").lower() in ["notsigned", "unknown", "missing"]:
        add_score(finding, config["score_rules"]["unsigned_executable"], "Unsigned or unverifiable executable")
    if user_writable_path(norm):
        amount = config["score_rules"]["risky_source_path"]
        if low_signal_path(norm):
            amount = min(amount, 3)
        add_score(finding, amount, "Path is user-writable or commonly abused" if amount > 3 else "Path is in a known noisy/bundled location; path score dampened")
    if suspicious_name(norm or name, config):
        add_score(finding, config["score_rules"]["suspicious_name"], "Suspicious Roblox exploit/executor-related name")
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
        return "high"
    if score >= 50:
        return "medium-high"
    if score >= 25:
        return "medium"
    return "low"


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


def confirmed_exploit_artifact(finding: dict, config: dict) -> bool:
    categories = set(finding.get("detection_categories", []))
    if known_bad_hash(finding, config):
        return True
    if real_behavioral_evidence(finding) and exploit_specific_artifact(finding, config):
        return True
    if (categories & HIGH_CONFIDENCE_CHEAT_CATEGORIES or categories & CONFIRMED_EXPLOIT_CATEGORIES) and exploit_specific_artifact(finding, config):
        return True
    return False


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
    if trusted and not behavior and not known_bad_hash(finding, config):
        return "Trusted Safe" if not categories else "Likely False Positive"
    if (dependency or finding.get("low_signal_path")) and not behavior and not exploit_specific:
        return "Likely False Positive" if categories else "Trusted Safe"
    if "possible_context" in types:
        return "Indicator Found"
    if confirmed_exploit_artifact(finding, config):
        return "Confirmed Exploit"
    if types & {"sysmon_remote_thread", "sysmon_process_access", "suspicious_module_load"}:
        return "Confirmed Exploit" if score >= config["category_thresholds"]["confirmed"] and exploit_specific else "Suspicious"
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
    for f in findings:
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
    return sorted(findings, key=lambda x: x.get("score", 0), reverse=True)


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
                "artifact_source": "event_log",
                "attribution_explanation": "",
                "classification": "Weak",
            }
            if ident["known_safe_signer"]:
                add_score(findings[key], config["score_rules"]["known_safe_signer"], "Signed by known-safe signer")
            if ident["signer"].get("status", "").lower() in ["notsigned", "unknown", "missing"]:
                add_score(findings[key], config["score_rules"]["unsigned_executable"], "Unsigned or unverifiable executable")
            if risky_source_path(ident["path"]):
                add_score(findings[key], config["score_rules"]["risky_source_path"], "Executable path is in AppData, Temp, or Downloads")
            if suspicious_name(ident["path"] or fallback_name, config):
                add_score(findings[key], config["score_rules"]["suspicious_name"], "Suspicious executor-style name")
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


def collect_file_artifacts(days: int, config: dict, sessions: list[dict], verbose=False) -> tuple[list[dict], list[dict]]:
    # File-system artifacts are indirect: they show exploit-like files existed, especially near Roblox play sessions.
    findings = {}
    timeline = []
    cut = cutoff(days)
    max_files = 25000
    seen_files = 0
    for root in scan_roots():
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            dirnames[:] = [d for d in dirnames if d.lower() not in {"node_modules", ".git", "windowsapps", "packages"}]
            if seen_files > max_files:
                break
            for filename in filenames:
                seen_files += 1
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
                if not (suspicious_extension(path_text, config) and suspicious_text(path_text, config)):
                    continue
                finding = make_finding(path_text, filename, "file_system", config)
                inspect_file_indicators(path_text, finding)
                finding["first_seen"] = min(times).isoformat(sep=" ", timespec="seconds")
                add_score(finding, config["score_rules"]["file_artifact"], "Suspicious file artifact found in common user/system location")
                if any(near_any_session(t, sessions) for t in times):
                    add_score(finding, config["score_rules"]["near_roblox_session"], "File timestamp is within 30 minutes of Roblox activity")
                finding["supporting_evidence"].append(
                    f"created={times[0].isoformat(sep=' ', timespec='seconds')} modified={times[1].isoformat(sep=' ', timespec='seconds')} accessed={times[2].isoformat(sep=' ', timespec='seconds')}"
                )
                finding["evidence_types"].append("file_artifact")
                merge_findings(findings, finding)
                timeline.append({"time": finding["first_seen"], "source": "File system", "text": f"Suspicious file artifact: {path_text}"})
    return list(findings.values()), timeline


def make_possible_context_finding(path_text: str, name: str, source: str, reason: str, when: dt.datetime | None, config: dict) -> dict:
    finding = {
        "name": name or Path(path_text).name or source,
        "path": normalize_path(path_text) if path_text and "://" not in path_text else path_text,
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
            if not (download_terms.search(line) and suspicious_text(line, config)):
                continue
            name = f"PowerShell history line {i}"
            finding = make_finding(str(hist), name, "powershell_history", config)
            finding["first_seen"] = mtime.isoformat(sep=" ", timespec="seconds")
            add_score(finding, config["score_rules"]["powershell_download_execute"], "PowerShell history contains suspicious download/execute pattern")
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
    }


def build_scan_report(days: int, config: dict, verbose=False) -> dict:
    scan_time = iso_now()
    sessions_raw, roblox_timeline = parse_roblox_logs(days, config)
    process_findings, process_timeline = collect_process_evidence(days, config, sessions_raw)
    prefetch_findings, prefetch_timeline = collect_prefetch_evidence(days, config, sessions_raw)
    file_findings, file_timeline = collect_file_artifacts(days, config, sessions_raw, verbose=verbose)
    ps_findings, ps_timeline = collect_powershell_history(days, config, sessions_raw)
    defender_findings, defender_timeline = collect_defender_history(days, config, sessions_raw)
    persistence_findings, persistence_timeline = collect_persistence(days, config, sessions_raw)
    browser_findings, browser_timeline = collect_browser_downloads(days, config, sessions_raw)
    shellbag_findings, shellbag_timeline = collect_shellbag_context(days, config, sessions_raw)
    recycle_findings, recycle_timeline = collect_recycle_bin_context(days, config, sessions_raw)
    recovery_findings, recovery_timeline, recovery_artifacts = collect_recovery_artifacts(days, config, sessions_raw)
    warning_findings, warning_timeline, warning_logs = collect_warning_logs(days, config, sessions_raw)
    findings = combine_findings(
        [process_findings, prefetch_findings, file_findings, ps_findings, defender_findings, persistence_findings, browser_findings, shellbag_findings, recycle_findings, recovery_findings, warning_findings],
        config,
    )
    antivirus_logs = antivirus_logs_from_findings(findings)
    detect_logs = detect_logs_from_report_parts(findings, warning_logs, recovery_artifacts, antivirus_logs, config)
    engine_results = [engine_assessment(f, config) for f in findings if f.get("path") or f.get("sha256")]
    sessions_raw = attach_session_status(sessions_raw, findings)
    quality = evidence_quality(days)
    timeline = dedupe_timeline(
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
    partial = {"findings": findings, "evidence_quality": quality}
    highest_result = determine_overall_category(partial)
    top_score = max([f.get("score", 0) for f in findings], default=0)
    system = collect_system_info()
    system["scan_time"] = scan_time
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
        "warningLogs": warning_logs,
        "recoveryArtifacts": recovery_artifacts,
        "antivirusLogs": antivirus_logs,
        "engineResults": engine_results,
        "limitations": limitations_from_quality(quality),
        "scanDays": days,
        "topScore": top_score,
        "systemInfo": system,
        "finalStatement": "No confirmed Roblox injection evidence was found in available logs. Logging coverage may not be sufficient to rule it out."
        if highest_result not in ["Confirmed Exploit", "Suspicious"]
        else "Confirmed exploit or suspicious Roblox exploit/injection evidence was found in available artifacts.",
    }
    return report


def build_scan_report_with_progress(days: int, config: dict, progress) -> dict:
    scan_time = iso_now()
    progress("Collecting Roblox logs...")
    sessions_raw, roblox_timeline = parse_roblox_logs(days, config)
    progress("Checking event logs...")
    process_findings, process_timeline = collect_process_evidence(days, config, sessions_raw)
    progress("Checking Prefetch artifacts...")
    prefetch_findings, prefetch_timeline = collect_prefetch_evidence(days, config, sessions_raw)
    progress("Checking file artifacts...")
    file_findings, file_timeline = collect_file_artifacts(days, config, sessions_raw, verbose=False)
    progress("Checking PowerShell history...")
    ps_findings, ps_timeline = collect_powershell_history(days, config, sessions_raw)
    progress("Checking Defender artifacts...")
    defender_findings, defender_timeline = collect_defender_history(days, config, sessions_raw)
    progress("Checking persistence entries...")
    persistence_findings, persistence_timeline = collect_persistence(days, config, sessions_raw)
    progress("Checking browser artifacts...")
    browser_findings, browser_timeline = collect_browser_downloads(days, config, sessions_raw)
    progress("Checking ShellBag Analyzer context...")
    shellbag_findings, shellbag_timeline = collect_shellbag_context(days, config, sessions_raw)
    progress("Checking Recycle Bin context...")
    recycle_findings, recycle_timeline = collect_recycle_bin_context(days, config, sessions_raw)
    progress("Checking recovery metadata...")
    recovery_findings, recovery_timeline, recovery_artifacts = collect_recovery_artifacts(days, config, sessions_raw)
    progress("Checking warning indicators...")
    warning_findings, warning_timeline, warning_logs = collect_warning_logs(days, config, sessions_raw)
    progress("Building report...")
    findings = combine_findings(
        [process_findings, prefetch_findings, file_findings, ps_findings, defender_findings, persistence_findings, browser_findings, shellbag_findings, recycle_findings, recovery_findings, warning_findings],
        config,
    )
    antivirus_logs = antivirus_logs_from_findings(findings)
    detect_logs = detect_logs_from_report_parts(findings, warning_logs, recovery_artifacts, antivirus_logs, config)
    engine_results = [engine_assessment(f, config) for f in findings if f.get("path") or f.get("sha256")]
    sessions_raw = attach_session_status(sessions_raw, findings)
    quality = evidence_quality(days)
    timeline = dedupe_timeline(
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
    partial = {"findings": findings, "evidence_quality": quality}
    highest_result = determine_overall_category(partial)
    top_score = max([f.get("score", 0) for f in findings], default=0)
    system = collect_system_info()
    system["scan_time"] = scan_time
    return {
        "scanTime": scan_time,
        "hostname": system.get("hostname", ""),
        "highestResult": highest_result,
        "confidence": confidence_for(highest_result, quality),
        "evidenceSources": quality,
        "timeline": timeline,
        "sessions": [camel_session(s) for s in sessions_raw],
        "findings": [camel_finding(f) for f in findings],
        "detectLogs": detect_logs,
        "warningLogs": warning_logs,
        "recoveryArtifacts": recovery_artifacts,
        "antivirusLogs": antivirus_logs,
        "engineResults": engine_results,
        "limitations": limitations_from_quality(quality),
        "scanDays": days,
        "topScore": top_score,
        "systemInfo": system,
        "finalStatement": "No confirmed Roblox injection evidence was found in available logs. Logging coverage may not be sufficient to rule it out."
        if highest_result not in ["Confirmed Exploit", "Suspicious"]
        else "Confirmed exploit or suspicious Roblox exploit/injection evidence was found in available artifacts.",
    }


def save_local_reports(report: dict, out_dir: Path, html_only=False, json_only=False) -> list[Path]:
    base = out_dir / f"securo_check_{now_stamp()}"
    written = []
    if not json_only:
        html_path = base.with_suffix(".html")
        html_path.write_text(render_html(report), encoding="utf-8")
        written.append(html_path)
    if json_only:
        json_path = base.with_suffix(".json")
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        written.append(json_path)
    elif not html_only:
        json_path = base.with_suffix(".json")
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        txt_path = base.with_suffix(".txt")
        txt_path.write_text(render_txt(report), encoding="utf-8")
        save_sqlite(out_dir / "securo_check_history.sqlite", report)
        written += [json_path, txt_path, out_dir / "securo_check_history.sqlite"]
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


def html_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return "<p class='muted'>None found.</p>"
    head = "".join(f"<th>{html.escape(c)}</th>" for c in columns)
    body = ""
    for r in rows:
        body += "<tr>" + "".join(f"<td>{html.escape(str(r.get(c, '')))}</td>" for c in columns) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(report: dict) -> str:
    top_rows = [{
        "Process": f["name"], "Path": f["path"], "Score": f["score"], "Classification": f["classification"],
        "Signer": f["signer"].get("status", ""), "First Seen": f["firstSeen"], "Reason": "; ".join(b["reason"] for b in f["scoreBreakdown"][:3])
    } for f in sorted(report["findings"], key=lambda x: x["score"], reverse=True)[:10]]
    sessions = [{"Username": s["username"], "Display Name": s.get("displayName", ""), "User ID": s["userId"], "Place ID": s["placeId"], "Job ID": s["jobId"], "Duration": s["duration"], "Status": s.get("status", "Clean")} for s in report["sessions"]]
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
    primary_session = report["sessions"][0] if report["sessions"] else {}
    timeline = "".join(f"<li><time>{html.escape(e['time'])}</time><span>{html.escape(e['text'])}</span><small>{html.escape(e['source'])}</small></li>" for e in report["timeline"])
    quality = "".join(f"<li><span>{html.escape(k)}</span><b class='{str(v).lower()}'>{'yes' if v else 'no'}</b></li>" for k, v in report["evidenceSources"].items())
    grouped = defaultdict(list)
    for f in sorted(report["findings"], key=lambda x: x["score"], reverse=True):
        grouped[f["classification"]].append(f)
    findings_html = ""
    for group in ["Confirmed Exploit", "Suspicious", "Indicator Found", "Likely False Positive", "Trusted Safe"]:
        findings_html += f"<h3>{group}</h3>"
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
            findings_html += f"<details open><summary>{html.escape(f['name'])} - {f['score']} points</summary>{warnings}<p><b>Path:</b> {html.escape(f['path'])}</p><p><b>SHA256:</b> {html.escape(f['sha256'])}</p><p><b>Signer:</b> {html.escape(str(f['signer']))}</p><h4>Score</h4><ul>{breakdown}</ul><h4>Evidence</h4><ul>{evidence}</ul><p>{html.escape(f['attributionExplanation'])}</p></details>"
    session_cards = "".join(
        f"<div class='session {html.escape((s.get('status') or 'Clean').lower())}'><h3>{html.escape(s.get('username') or 'Unknown')}</h3><p><b>Display Name:</b> {html.escape(s.get('displayName', ''))}</p><p><b>User ID:</b> {html.escape(s.get('userId', ''))}</p><p><b>Place ID:</b> {html.escape(s.get('placeId', ''))}</p><p><b>Job ID:</b> {html.escape(s.get('jobId', ''))}</p><p><b>Duration:</b> {html.escape(s.get('duration', 'unknown'))}</p><p><b>Status:</b> {html.escape(s.get('status', 'Clean'))}</p>{''.join('<p><b>Detection:</b> ' + html.escape(d.get('name','')) + ' ' + html.escape(d.get('path','')) + '</p>' for d in s.get('linkedDetections', []))}</div>"
        for s in report["sessions"]
    )
    raw = html.escape(json.dumps(report, indent=2))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{APP_NAME} Report</title>
<style>
body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f5f7f9;color:#15191f}}header{{background:#111827;color:white;padding:24px 32px}}main{{max-width:1180px;margin:auto;padding:24px}}section{{background:white;border:1px solid #d8dee6;border-radius:8px;margin:16px 0;padding:18px}}.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.card{{border:1px solid #d8dee6;border-radius:8px;padding:14px;background:#fbfcfd}}.value{{font-size:24px;font-weight:700}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{border-bottom:1px solid #e7ebf0;padding:8px;text-align:left;vertical-align:top}}th{{background:#f0f3f6}}.timeline li{{display:grid;grid-template-columns:170px 1fr 130px;gap:12px;padding:8px 0;border-bottom:1px solid #edf0f3}}.muted{{color:#667085}}.true{{color:#157347}}.false{{color:#b42318}}details{{border:1px solid #d8dee6;border-radius:8px;padding:10px;margin:10px 0}}summary{{font-weight:700;cursor:pointer}}pre{{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e5e7eb;padding:12px;border-radius:8px;max-height:520px;overflow:auto}}.warn{{border:1px solid #dc2626;background:#fee2e2;color:#7f1d1d;border-radius:8px;padding:12px;margin:10px 0}}.sessions{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}}.session{{border:1px solid #d8dee6;border-radius:8px;padding:12px;background:#fbfcfd}}.session.suspicious,.session.confirmed{{border-color:#dc2626;background:#fee2e2;color:#7f1d1d}}.filters{{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px}}.pill{{border:1px solid #d8dee6;border-radius:999px;padding:5px 10px;background:#fbfcfd;font-size:12px}}
</style></head><body><header><h1>{APP_NAME} Report</h1><p>No confirmed result means only that available logs did not prove it. Logging coverage may be incomplete.</p></header><main>
<section><h2>Summary</h2><div class="summary"><div class="card"><div>Scan Date</div><div class="value">{html.escape(report['scanTime'])}</div></div><div class="card"><div>Highest Result</div><div class="value">{report['highestResult']}</div></div><div class="card"><div>Top Score</div><div class="value">{report.get('topScore', 0)}</div></div><div class="card"><div>Roblox Sessions</div><div class="value">{len(report['sessions'])}</div></div></div></section>
<section><h2>Primary Roblox Account</h2><div class="summary"><div class="card"><div>User</div><div class="value">{html.escape(primary_session.get('username', 'Unknown'))}</div></div><div class="card"><div>User ID</div><div class="value">{html.escape(primary_session.get('userId', ''))}</div></div><div class="card"><div>Place ID</div><div class="value">{html.escape(primary_session.get('placeId', ''))}</div></div><div class="card"><div>Injection Evidence</div><div class="value">{html.escape(report['highestResult'] if report['highestResult'] in ['Confirmed Exploit','Suspicious'] else 'Not confirmed')}</div></div></div></section>
<section><h2>Top Suspicious Processes</h2>{html_table(top_rows, ['Process','Path','Score','Classification','Signer','First Seen','Reason'])}</section>
<section><h2>Interaction / Detect Logs</h2><div class="filters">{''.join(f"<span class='pill'>{x}</span>" for x in DETECT_LOG_TYPES)}</div>{html_table(detect_rows, ['Type','Detection','Severity','Confidence','Manual Review','Evidence','Timestamp','Explanation'])}</section>
<section><h2>Warning Logs</h2><p class="muted">Warnings indicate modifications or behaviors that may reduce confidence or require review. They are not automatically cheating evidence.</p>{html_table(warning_rows, ['Detection','Severity','Confidence','Manual Review','Source','Timestamp','Explanation'])}</section>
<section><h2>Recovery</h2>{html_table(recovery_rows, ['Name','Path','Source','Timestamp','Manual Review'])}</section>
<section><h2>Antivirus Logs</h2>{html_table(antivirus_rows, ['Source','Detection','Severity','Timestamp','Path'])}</section>
<section><h2>Engines</h2>{html_table(engine_rows, ['File','Score','Local Hits','Detectability','VirusTotal','Manual Review'])}</section>
<section><h2>Session Information</h2><div class="sessions">{session_cards}</div>{html_table(sessions, ['Username','Display Name','User ID','Place ID','Job ID','Duration','Status'])}</section>
<section><h2>Timeline</h2><ul class="timeline">{timeline or "<p class='muted'>No timeline events found.</p>"}</ul></section>
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
    return True, {"sessionId": data["pinId"], "uploadToken": pin}


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


def parse_args():
    p = argparse.ArgumentParser(description="Read-only Roblox-focused PC evidence checker")
    p.add_argument("--cli", action="store_true", help="Run the old command-line flow")
    p.add_argument("--days", type=int, default=None, help="Number of recent days to scan")
    p.add_argument("--api-base-url", default=None, help="Securo website URL for PIN verification and upload")
    p.add_argument("--pin", default=None, help="PIN from the checker website")
    p.add_argument("--local-only", action="store_true", help="Do not verify PIN or upload; create local reports only")
    p.add_argument("--html-only", action="store_true", help="Only write HTML report")
    p.add_argument("--json-only", action="store_true", help="Only write JSON report")
    p.add_argument("--portable", action="store_true", help="Save reports next to executable")
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
        self.drag_x = 0
        self.drag_y = 0

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

        self.card = tk.Frame(self.window, bg="#111111", padx=30, pady=24)
        self.card.place(relx=0.5, rely=0.54, anchor="center", width=520, height=330)

        self.logo = tk.Canvas(self.card, width=64, height=64, bg="#111111", highlightthickness=0)
        self.logo.create_oval(6, 6, 58, 58, outline="#00D26A", width=3)
        self.logo.create_text(32, 32, text="S", fill="#00D26A", font=("Segoe UI", 28, "bold"))
        self.logo.pack(pady=(0, 8))

        tk.Label(self.card, text="Securo", bg="#111111", fg="#FFFFFF", font=("Segoe UI", 24, "bold")).pack()
        tk.Label(self.card, text="Enter your check PIN", bg="#111111", fg="#A1A1AA", font=("Segoe UI", 11)).pack(pady=(2, 18))

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

        self.status = tk.Text(
            self.card,
            height=5,
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
            text=f"API: {self.api_base_url or 'not configured'}",
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
        self.root.after(0, self._append_status, message)

    def _append_status(self, message: str):
        self.status.configure(state="normal")
        self.status.insert("end", message + "\n")
        self.status.see("end")
        self.status.configure(state="disabled")

    def set_busy(self, busy: bool):
        def apply():
            self.start_button.configure(state="disabled" if busy else "normal")
            self.pin_entry.configure(state="disabled" if busy else "normal")

        self.root.after(0, apply)

    def start_scan(self):
        pin = self.pin_var.get().strip()
        if not re.fullmatch(r"\d{6}", pin):
            messagebox.showerror("Securo", "Enter a valid 6-digit PIN.")
            return
        if not self.api_base_url:
            messagebox.showerror("Securo", "Missing api_base_url in config.json.")
            return
        self.set_busy(True)
        threading.Thread(target=self.worker, args=(pin,), daemon=True).start()

    def worker(self, pin: str):
        try:
            self.log("Calling POST /api/connect-pin...")
            verified, verify_result = verify_pin(self.api_base_url, pin)
            if not verified:
                self.log(f"Invalid or expired PIN: {verify_result}")
                self.set_busy(False)
                return

            self.log("PIN verified")
            self.session_id = verify_result["sessionId"]
            self.upload_token = verify_result["uploadToken"]

            report = build_scan_report_with_progress(self.days, self.config, self.log)
            out_dir = app_dir() if getattr(sys, "frozen", False) else Path.cwd()
            written = save_local_reports(report, out_dir)
            for path in written:
                self.log(f"Saved local report: {path.name}")

            self.log("Calling POST /api/upload-report...")
            uploaded, upload_message = upload_report(self.api_base_url, self.session_id, self.upload_token, report)
            if uploaded:
                self.log("Report uploaded successfully")
                self.root.after(0, self.show_close)
            else:
                self.log(f"Upload failed: {upload_message}")
                self.set_busy(False)
        except Exception as exc:
            self.log(f"Error: {exc}")
            self.set_busy(False)

    def show_close(self):
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
    elif not args.local_only:
        print("No API base URL configured. Running local-only scan.")
    if args.verbose:
        print("Collecting system info, Roblox logs, event logs, Prefetch, files, Defender, persistence, PowerShell, and browser artifacts...")
    print("scan started")
    report = build_scan_report(days, config, verbose=args.verbose)
    print("scan completed")
    out_dir = app_dir() if args.portable or getattr(sys, "frozen", False) else Path.cwd()
    written = save_local_reports(report, out_dir, html_only=args.html_only, json_only=args.json_only)
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
