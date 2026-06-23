import datetime as dt
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("roblox_pc_checker", ROOT / "roblox_pc_checker.py")
checker = importlib.util.module_from_spec(SPEC)
sys.modules["roblox_pc_checker"] = checker
SPEC.loader.exec_module(checker)


def test_config():
    return {
        "score_rules": {
            "known_safe_signer": -30,
            "unsigned_executable": 25,
            "risky_source_path": 20,
            "suspicious_name": 10,
            "file_artifact": 15,
            "near_roblox_session": 25,
            "browser_download": 25,
            "prefetch_execution": 25,
            "persistence": 35,
            "powershell_download_execute": 35,
            "defender_detection": 10,
            "sysmon_remote_thread": 50,
            "sysmon_process_access_dangerous": 40,
            "suspicious_dll_loaded": 35,
            "near_roblox_launch": 25,
        },
        "virustotal_api_key": "",
        "ruin_mode_enabled": False,
        "scan_days": 7,
        "scan_timeout_seconds": 900,
        "default_scan_profile": "standard",
        "scan_profiles": {},
        "storage_base_dir": "",
        "prefetch_dir": "C:/Windows/Prefetch",
        "recycle_bin_roots": [],
        "collect_safe_account_identifiers": False,
        "collect_system_reset_evidence": False,
        "ioc_file": "securo_iocs.json",
        "iocs": checker.normalize_iocs({}),
        "known_bad_hashes": [],
        "executor_confirmation_keywords": ["Volt", "Potassium", "Wave", "Synapse Z", "Seliware", "Madium", "Cosmic", "Velocity", "SirHurt", "Solara", "Xeno"],
        "category_thresholds": {"confirmed": 70, "suspicious": 35, "weak": 10},
        "known_safe_signers": ["Microsoft Corporation", "Roblox Corporation", "Python Software Foundation", "OpenAI", "Codex", "Medal"],
        "suspicious_name_terms": ["executor", "injector", "roblox", "solara", "arceus"],
        "suspicious_extensions": [".exe", ".dll", ".zip", ".ps1"],
        "dangerous_access_terms": ["PROCESS_VM_WRITE", "PROCESS_CREATE_THREAD"],
    }


class CoreTests(unittest.TestCase):
    def test_report_schema_uses_scan_time(self):
        original = {}
        for name in [
            "parse_roblox_logs",
            "collect_process_evidence",
            "collect_running_processes",
            "collect_network_ioc_evidence",
            "collect_prefetch_evidence",
            "collect_file_artifacts",
            "collect_powershell_history",
            "collect_defender_history",
            "collect_persistence",
            "collect_browser_downloads",
            "collect_shellbag_context",
            "collect_recycle_bin_context",
            "collect_recovery_artifacts",
            "collect_warning_logs",
            "evidence_quality",
            "collect_system_info",
        ]:
            original[name] = getattr(checker, name)
        try:
            checker.parse_roblox_logs = lambda days, config: ([], [])
            checker.collect_process_evidence = lambda days, config, sessions: ([], [])
            checker.collect_running_processes = lambda config, sessions: ([], [])
            checker.collect_network_ioc_evidence = lambda config: ([], [])
            checker.collect_prefetch_evidence = lambda days, config, sessions: ([], [])
            checker.collect_file_artifacts = lambda days, config, sessions, verbose=False: ([], [])
            checker.collect_powershell_history = lambda days, config, sessions: ([], [])
            checker.collect_defender_history = lambda days, config, sessions: ([], [])
            checker.collect_persistence = lambda days, config, sessions: ([], [])
            checker.collect_browser_downloads = lambda days, config, sessions: ([], [])
            checker.collect_shellbag_context = lambda days, config, sessions: ([], [])
            checker.collect_recycle_bin_context = lambda days, config, sessions: ([], [])
            checker.collect_recovery_artifacts = lambda days, config, sessions: ([], [], [])
            checker.collect_warning_logs = lambda days, config, sessions: ([], [], [])
            checker.evidence_quality = lambda days: {"Roblox logs available": False}
            checker.collect_system_info = lambda: {"hostname": "unit-host", "scan_time": "old"}
            report = checker.build_scan_report(7, test_config())
        finally:
            for name, value in original.items():
                setattr(checker, name, value)
        self.assertIn("scanTime", report)
        self.assertNotIn("scan_time", report)
        dt.datetime.fromisoformat(report["scanTime"])
        for key in ["hostname", "highestResult", "confidence", "evidenceSources", "timeline", "sessions", "findings", "limitations"]:
            self.assertIn(key, report)
        for key in ["detectLogs", "warningLogs", "recoveryArtifacts", "antivirusLogs", "engineResults"]:
            self.assertIn(key, report)
        self.assertTrue(report["scanTransparency"]["readOnly"])
        self.assertIn("Roblox logs including user ID", " ".join(report["scanTransparency"]["scannedScope"]))

    def test_upload_payload_shape(self):
        captured = {}
        original = checker.post_json
        try:
            def fake_post(url, payload, headers=None, timeout=15, retries=2):
                captured["payload"] = payload
                return True, {"ok": True}

            checker.post_json = fake_post
            report = {"scanTime": dt.datetime.now().astimezone().isoformat(), "hostname": "h", "highestResult": "Indicator Found", "confidence": "low", "evidenceSources": {}, "timeline": [], "sessions": [], "findings": [], "limitations": []}
            ok, _ = checker.upload_report("https://example.test", "sid", "tok", report)
        finally:
            checker.post_json = original
        self.assertTrue(ok)
        self.assertEqual(captured["payload"]["pin"], "tok")
        self.assertIn("scanTime", captured["payload"]["reportData"])

    def test_duplicate_sessions_removed_and_unknown_duration(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_local = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            log_dir = Path(tmp) / "Roblox" / "logs"
            log_dir.mkdir(parents=True)
            text = "userId: 123\nusername: Player\nplaceId: 999\njobId: abcdefgh-1234\n"
            (log_dir / "a.log").write_text(text, encoding="utf-8")
            (log_dir / "b.log").write_text(text, encoding="utf-8")
            fixed = dt.datetime.now().timestamp()
            os.utime(log_dir / "a.log", (fixed, fixed))
            os.utime(log_dir / "b.log", (fixed, fixed))
            try:
                sessions, _ = checker.parse_roblox_logs(7, test_config())
            finally:
                if old_local is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_local
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["duration"], "unknown")
        self.assertEqual(len(sessions[0]["all_logs"]), 2)

    def test_roblox_logs_preserve_raw_history_and_fastflags(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_local = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            log_dir = Path(tmp) / "Roblox" / "logs"
            log_dir.mkdir(parents=True)
            first = "2026-06-02 12:00:00 userId: 123 username: Player placeId: 999 jobId: abcdefgh-1234\n2026-06-02 12:01:00 LoadClientSettings FFlagDebugGraphicsPreferD3D11=true\n"
            second = "2026-06-03 12:00:00 userId: 123 username: Player placeId: 999 jobId: abcdefgh-1234\n2026-06-03 12:02:00 Teleport server reconnect DFIntTaskSchedulerTargetFps = 240\n"
            (log_dir / "first.log").write_text(first, encoding="utf-8")
            (log_dir / "second.log").write_text(second, encoding="utf-8")
            fixed = dt.datetime.now().timestamp()
            os.utime(log_dir / "first.log", (fixed, fixed))
            os.utime(log_dir / "second.log", (fixed, fixed))
            try:
                sessions, timeline = checker.parse_roblox_logs(30, test_config())
            finally:
                if old_local is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_local
        report_logs = checker.roblox_logs_for_report(sessions)
        flags = checker.fastflags_for_report(sessions)
        self.assertEqual(len(report_logs), 2)
        self.assertTrue(all(item.get("rawLog") for item in report_logs))
        self.assertIn("FFlagDebugGraphicsPreferD3D11", {flag["name"] for flag in flags})
        self.assertIn("DFIntTaskSchedulerTargetFps", {flag["name"] for flag in flags})
        self.assertFalse(any("FFlagDebugGraphicsPreferD3D11" in event.get("text", "") for event in timeline))
        self.assertFalse(any(event.get("source", "").startswith("Roblox FastFlag") for event in timeline))

    def test_missing_telemetry_lowers_confidence(self):
        quality = {"Roblox logs available": True, "Prefetch available": False, "Sysmon Event ID 8 available": False}
        self.assertEqual(checker.confidence_for("Clean-but-limited", quality), "limited")
        self.assertEqual(checker.determine_overall_category({"findings": [], "evidence_quality": quality}), "Insufficient data")

    def test_suspicious_artifact_near_session_scores_higher(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "solara_executor.zip"
            artifact.write_text("fixture", encoding="utf-8")
            event_time = dt.datetime.now()
            os.utime(artifact, (event_time.timestamp(), event_time.timestamp()))
            sessions = [{"start_time": event_time.isoformat(sep=" ", timespec="seconds"), "end_time": "", "duration": "unknown"}]
            original_roots = checker.scan_roots
            try:
                checker.scan_roots = lambda: [root]
                findings, _ = checker.collect_file_artifacts(7, test_config(), sessions)
            finally:
                checker.scan_roots = original_roots
        self.assertTrue(findings)
        self.assertGreaterEqual(findings[0]["score"], 40)

    def test_prefetch_scanner_extracts_embedded_suspicious_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pf = root / "POTASSIUM.EXE-1234ABCD.pf"
            embedded = "C:\\Users\\timmy\\Downloads\\Potassium.exe\x00C:\\Users\\timmy\\Downloads\\Potassium.dll"
            pf.write_bytes(b"SCCA" + embedded.encode("utf-16-le"))
            now = dt.datetime.now().timestamp()
            os.utime(pf, (now, now))
            config = test_config()
            config["prefetch_dir"] = tmp
            findings, timeline = checker.collect_prefetch_evidence(7, config, [])
        self.assertTrue(findings)
        self.assertEqual(findings[0]["name"], "Potassium.exe")
        self.assertIn("prefetch_execution", findings[0]["evidence_types"])
        self.assertIn("executed_deleted", findings[0]["evidence_types"])
        self.assertIn("Executed & Deleted", findings[0]["detection_categories"])
        self.assertTrue(any("Potassium.exe" in item for item in findings[0]["supporting_evidence"]))
        self.assertTrue(any("potassium.exe" in event["text"].lower() for event in timeline))

    def test_prefetch_name_parser_keeps_hyphenated_executor_names(self):
        self.assertEqual(checker.prefetch_executable_name("SYNAPSE-Z.EXE-ABCDEF12.pf"), "SYNAPSE-Z.EXE")
        self.assertEqual(checker.prefetch_executable_name("ROBLOXPLAYERBETA.EXE-12345678.pf"), "ROBLOXPLAYERBETA.EXE")

    def test_all_prefetch_entries_are_flagged_as_execution_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "NOTEPAD.EXE-1234ABCD.pf"
            pf.write_bytes(b"SCCA")
            now = dt.datetime.now().timestamp()
            os.utime(pf, (now, now))
            config = test_config()
            config["prefetch_dir"] = tmp
            findings, timeline = checker.collect_prefetch_evidence(7, config, [])
        self.assertTrue(findings)
        self.assertIn("Prefetch Execution", findings[0]["detection_categories"])
        self.assertIn("prefetch_execution", findings[0]["evidence_types"])
        self.assertTrue(any("notepad.exe" in event["text"].lower() for event in timeline))

    def test_xeno_detection_categories_are_confirmed(self):
        config = test_config()
        config["suspicious_name_terms"].append("xeno")
        cases = [
            ("C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30\\Xeno.exe", ["Tampered File"], "Confirmed Exploit"),
            ("C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30\\XenoUI.dll", ["DotNetDLL"], "Indicator Found"),
            ("C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30\\zlib1.dll", ["A3"], "Indicator Found"),
        ]
        for path, categories, expected in cases:
            finding = checker.make_finding(path, Path(path).name, "unit", config)
            finding["detection_categories"] = categories
            finding["detections"] = [{"category": categories[0], "reason": "fixture", "risk": "High"}]
            finding["supporting_evidence"] = ["fixture supporting evidence"]
            finding["first_seen"] = "2026-06-02 12:00:00"
            finding["score"] = config["category_thresholds"]["confirmed"] if expected == "Confirmed Exploit" else 20
            result = checker.finalize_findings([finding], config)[0]
            self.assertEqual(result["classification"], expected, path)
            if expected == "Confirmed Exploit":
                self.assertGreaterEqual(result["score"], config["category_thresholds"]["confirmed"])
                self.assertEqual(result["confidence_level"], "Confirmed")

    def test_flagged_executor_exe_or_dll_name_confirms(self):
        config = test_config()
        cases = [
            "C:\\Users\\timmy\\Downloads\\Synapse Z.exe",
            "C:\\Users\\timmy\\Downloads\\synapse_z.dll",
            "C:\\Users\\timmy\\Downloads\\synapse-z.exe",
            "C:\\Users\\timmy\\Downloads\\Potassium.dll",
        ]
        for path in cases:
            finding = checker.make_finding(path, Path(path).name, "unit", config)
            checker.add_detection(finding, "Executed Suspicious File", "Already flagged fixture", "High", 20)
            finding["first_seen"] = "2026-06-02 12:00:00"
            result = checker.finalize_findings([finding], config)[0]
            self.assertEqual(result["classification"], "Confirmed Exploit", path)
            self.assertEqual(result["confidence_level"], "Confirmed", path)

    def test_executor_filename_match_does_not_confirm_unflagged_file(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\Solara.exe", "Solara.exe", "unit", config)
        finding["first_seen"] = "2026-06-02 12:00:00"
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")

    def test_ioc_hash_match_confirms_flagged_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "neutral_tool.exe"
            path.write_bytes(b"MZ harmless fixture")
            digest = checker.sha256_file(str(path))
            config = test_config()
            config["iocs"] = checker.normalize_iocs({"hashes": [digest]})
            finding = checker.make_finding(str(path), path.name, "unit", config)
            finding["first_seen"] = "2026-06-02 12:00:00"
            result = checker.finalize_findings([finding], config)[0]
        self.assertIn("Confirmed IOC", result["detection_categories"])
        self.assertEqual(result["classification"], "Confirmed Exploit")
        self.assertEqual(result["confidence_level"], "Confirmed")

    def test_running_process_ioc_match_is_reported(self):
        config = test_config()
        config["iocs"] = checker.normalize_iocs({"filenames": ["BadLoader.exe"]})
        csv_text = (
            "Node,CommandLine,ExecutablePath,Name,ParentProcessId,ProcessId\r\n"
            "PC,\"C:\\Users\\timmy\\Downloads\\BadLoader.exe --run\",C:\\Users\\timmy\\Downloads\\BadLoader.exe,BadLoader.exe,100,200\r\n"
            "PC,C:\\Roblox\\RobloxPlayerBeta.exe,C:\\Roblox\\RobloxPlayerBeta.exe,RobloxPlayerBeta.exe,50,201\r\n"
        )
        original = checker.run_command
        try:
            checker.run_command = lambda *args, **kwargs: csv_text
            findings, timeline = checker.collect_running_processes(config, [])
        finally:
            checker.run_command = original
        self.assertTrue(findings)
        finalized = checker.finalize_findings(findings, config)
        self.assertIn("Confirmed IOC", finalized[0]["detection_categories"])
        self.assertTrue(any("BadLoader.exe" in event["text"] for event in timeline))

    def test_normal_roblox_install_path_is_not_confirmed(self):
        config = test_config()
        finding = checker.make_finding(
            "C:\\Program Files (x86)\\Roblox\\Versions\\version-123\\RobloxPlayerBeta.exe",
            "RobloxPlayerBeta.exe",
            "unit",
            config,
        )
        checker.add_detection(finding, "A3", "Generic indicator fixture", "Medium", 80)
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")

    def test_session_report_includes_roblox_identity_client_settings_and_times(self):
        session = {
            "place_id": "987654321",
            "job_id": "abc-def",
            "user_id": "123456789",
            "username": "ExampleUser",
            "display_name": "Example",
            "start_time": "2026-06-02 17:00:00",
            "end_time": "2026-06-02 18:24:00",
            "duration": "1h 24m",
            "load_client_settings": ["LoadClientSettingsFromLocal ClientAppSettings.json"],
        }
        row = checker.camel_session(session)
        self.assertEqual(row["userId"], "123456789")
        self.assertEqual(row["username"], "ExampleUser")
        self.assertEqual(row["displayName"], "Example")
        self.assertEqual(row["gameId"], "987654321")
        self.assertEqual(row["placeId"], "987654321")
        self.assertEqual(row["jobId"], "abc-def")
        self.assertEqual(row["launchTime"], "2026-06-02 17:00:00")
        self.assertEqual(row["exitTime"], "2026-06-02 18:24:00")
        self.assertEqual(row["duration"], "1h 24m")
        self.assertIn("LoadClientSettingsFromLocal", row["loadClientSettings"][0])

    def test_shellbag_and_recycle_bin_context_stay_possible(self):
        config = test_config()
        for source in ["ShellBag Analyzer", "Recycle Bin"]:
            finding = checker.make_possible_context_finding(
                "C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30",
                "Xeno-v1.3.30",
                source,
                "possible deleted/browsed exploit context",
                dt.datetime.now(),
                config,
            )
            finding["score"] = 100
            result = checker.finalize_findings([finding], config)[0]
            self.assertEqual(result["classification"], "Indicator Found", source)

    def test_recycle_bin_deleted_suspicious_file_is_key_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deleted = root / "Xeno.exe"
            deleted.write_text("deleted fixture", encoding="utf-8")
            config = test_config()
            config["recycle_bin_roots"] = [tmp]
            findings, timeline = checker.collect_recycle_bin_context(7, config, [])
        self.assertTrue(findings)
        self.assertIn("Suspicious File Deletion", findings[0]["detection_categories"])
        self.assertIn("recovery", findings[0]["evidence_types"])
        self.assertTrue(any("Recycle Bin" == event["source"] for event in timeline))

    def test_recycle_bin_deleted_prefetch_is_key_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = root / "$I123456"
            original = "C:\\Windows\\Prefetch\\POTASSIUM.EXE-1234ABCD.pf"
            # Minimal $I record: version, size, Windows FILETIME, then UTF-16 original path.
            deleted_time = dt.datetime(2026, 6, 2, 14, 27)
            filetime = int((deleted_time - dt.datetime(1601, 1, 1)).total_seconds() * 10_000_000)
            payload = (1).to_bytes(8, "little") + (123).to_bytes(8, "little") + filetime.to_bytes(8, "little") + original.encode("utf-16-le") + b"\x00\x00"
            record.write_bytes(payload)
            config = test_config()
            config["recycle_bin_roots"] = [tmp]
            findings, timeline = checker.collect_recycle_bin_context(30, config, [])
        self.assertTrue(findings)
        categories = set(findings[0]["detection_categories"])
        self.assertIn("Deleted Prefetch File", categories)
        self.assertIn("Prefetch Deleted", categories)
        self.assertIn("prefetch_deleted", findings[0]["evidence_types"])
        self.assertTrue(any("POTASSIUM.EXE" in event["text"] for event in timeline))

    def test_all_recycle_bin_deletions_are_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deleted = root / "boring_document.txt"
            deleted.write_text("deleted fixture", encoding="utf-8")
            config = test_config()
            config["recycle_bin_roots"] = [tmp]
            findings, timeline = checker.collect_recycle_bin_context(7, config, [])
        self.assertTrue(findings)
        self.assertIn("File Deletion", findings[0]["detection_categories"])
        self.assertNotIn("Suspicious File Deletion", findings[0]["detection_categories"])
        self.assertTrue(any("boring_document.txt" in event["text"] for event in timeline))

    def test_warning_logs_do_not_become_confirmed(self):
        config = test_config()
        finding = checker.make_possible_context_finding(
            "ConnectedDevicesPlatform ActivitiesCache",
            "ActivitiesCache",
            "ActivitiesCache Disabled",
            "coverage warning only",
            dt.datetime.now(),
            config,
        )
        finding["evidence_types"].append("warning")
        checker.add_detection(finding, "ActivitiesCache Disabled", "coverage warning only", "Low", 10)
        result = checker.finalize_findings([finding], config)[0]
        logs = checker.detect_logs_from_report_parts([result], [{
            "detectionName": "ActivitiesCache Disabled",
            "severity": "Low",
            "explanation": "coverage warning only",
            "evidencePath": "ActivitiesCache",
            "timestamp": result["first_seen"],
            "manualReviewRequired": True,
            "confidenceLevel": "low",
            "type": "Warning",
        }], [], [], config)
        self.assertEqual(result["classification"], "Indicator Found")
        self.assertTrue(any(log["type"] == "Warning" and log["manualReviewRequired"] for log in logs))

    def test_skript_loader_trace_is_direct_detection(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\SkriptLoader.exe", "SkriptLoader.exe", "unit", config)
        checker.add_detection(finding, "Skript Loader Trace", "Known Skript Loader-style trace found", "High", 55)
        result = checker.finalize_findings([finding], config)[0]
        logs = checker.detect_logs_from_report_parts([result], [], [], [], config)
        self.assertNotEqual(result["classification"], "Confirmed Exploit")
        self.assertTrue(any(log["type"] == "Direct" for log in logs))

    def test_a3_alone_is_indicator_found(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\Public\\zlib1.dll", "zlib1.dll", "unit", config)
        finding["detection_categories"] = ["A3"]
        finding["detections"] = [{"category": "A3", "type": "Direct", "reason": "generic string fixture", "risk": "High"}]
        finding["score"] = 100
        result = checker.finalize_findings([finding], config)[0]
        self.assertEqual(result["classification"], "Indicator Found")

    def test_securo_internal_components_are_suppressed(self):
        config = test_config()
        config["storage_base_dir"] = "C:\\Users\\timmy\\Documents\\Securo"
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\SECURO\\_internal\\python312.dll", "python312.dll", "unit", config)
        checker.add_detection(finding, "A3", "generic string fixture", "High", 100)
        self.assertTrue(finding["suppressed"])
        self.assertEqual(finding["suppression_reason"], "Internal Securo Component")
        self.assertEqual(checker.finalize_findings([finding], config), [])

    def test_codex_workspace_files_are_suppressed(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\Grayson Gollotte\\Documents\\Codex\\2026-06-01\\work\\Velocity.exe", "Velocity.exe", "unit", config)
        checker.add_detection(finding, "Executed Suspicious File", "fixture", "High", 80)
        self.assertTrue(finding["suppressed"])
        self.assertEqual(checker.finalize_findings([finding], config), [])

    def test_medal_is_not_confirmed_from_generic_flags(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\AppData\\Local\\Medal\\Medal.exe", "Medal.exe", "unit", config)
        finding["signer"] = {"status": "Valid", "subject": "CN=Medal", "issuer": "CN=Trusted CA"}
        checker.add_detection(finding, "Generic Packed File", "Generic fixture", "High", 100)
        finding["first_seen"] = "2026-06-02 12:00:00"
        finding["score"] = 500
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")
        self.assertNotEqual(result["confidence_level"], "Confirmed")

    def test_trusted_signed_dependency_downgrades_outside_securo(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\OtherApp\\python312.dll", "python312.dll", "unit", config)
        finding["signer"] = {"status": "Valid", "subject": "CN=Python Software Foundation", "issuer": "CN=Trusted CA"}
        finding["detection_categories"] = ["A3", "RAM Suspicious Indicator"]
        finding["detections"] = [
            {"category": "A3", "type": "Direct", "reason": "generic string fixture", "risk": "High"},
            {"category": "RAM Suspicious Indicator", "type": "Specific", "reason": "API strings", "risk": "High"},
        ]
        finding["score"] = 100
        result = checker.finalize_findings([finding], config)[0]
        self.assertIn(result["classification"], {"Likely False Positive", "Trusted Safe"})

    def test_suspicious_dll_name_without_load_evidence_is_indicator(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\xeno_hook.dll", "xeno_hook.dll", "unit", config)
        finding["signer"] = {"status": "Valid", "subject": "CN=Microsoft Corporation", "issuer": "CN=Trusted CA"}
        checker.add_detection(finding, "Suspicious DLL Loading", "Suspicious DLL name in user-writable path", "High", 35)
        result = checker.finalize_findings([finding], config)[0]
        self.assertIn(result["classification"], {"Indicator Found", "Likely False Positive"})

    def test_keyword_only_item_does_not_confirm(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\xeno_executor.exe", "xeno_executor.exe", "unit", config)
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")
        self.assertNotIn("Executor Keyword Match", result.get("detection_categories", []))

    def test_flagged_item_with_executor_keyword_can_confirm(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\Xeno.exe", "Xeno.exe", "unit", config)
        checker.add_detection(finding, "A3", "A3 indicator found in flagged artifact", "High", 20)
        finding["first_seen"] = "2026-06-02 12:00:00"
        finding["score"] = config["category_thresholds"]["confirmed"]
        result = checker.finalize_findings([finding], config)[0]
        self.assertEqual(result["classification"], "Confirmed Exploit")
        self.assertIn("Executor Keyword Match", result.get("detection_categories", []))

    def test_flagged_item_with_keyword_in_non_exact_exe_name_does_not_confirm(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\xeno_executor.exe", "xeno_executor.exe", "unit", config)
        checker.add_detection(finding, "A3", "A3 indicator found in flagged artifact", "High", 20)
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")
        self.assertNotIn("Executor Keyword Match", result.get("detection_categories", []))

    def test_config_executor_keyword_is_second_stage_only(self):
        config = test_config()
        keyword_only = checker.make_finding("C:\\Users\\timmy\\Downloads\\Potassium.exe", "Potassium.exe", "unit", config)
        keyword_only_result = checker.finalize_findings([keyword_only], config)[0]
        self.assertNotEqual(keyword_only_result["classification"], "Confirmed Exploit")
        self.assertNotIn("Executor Keyword Match", keyword_only_result.get("detection_categories", []))

        flagged = checker.make_finding("C:\\Users\\timmy\\Downloads\\Potassium.exe", "Potassium.exe", "unit", config)
        checker.add_detection(flagged, "A3", "A3 indicator found in flagged artifact", "High", 20)
        flagged["first_seen"] = "2026-06-02 12:00:00"
        flagged["score"] = config["category_thresholds"]["confirmed"]
        flagged_result = checker.finalize_findings([flagged], config)[0]
        self.assertEqual(flagged_result["classification"], "Confirmed Exploit")
        self.assertIn("Executor Keyword Match", flagged_result.get("detection_categories", []))

    def test_engine_detected_executor_filename_confirms(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Desktop\\OpXOyuApWKTlFzrV (2)\\Potassium.exe", "Potassium.exe", "file_system", config)
        checker.add_detection(finding, "DotNetExecutable", "C#/.NET assembly metadata found", "Medium", 25)
        checker.add_detection(finding, "Generic Packed File", "High entropy unsigned executable content", "High", 35)
        checker.add_detection(finding, "A1", "A1 indicator found in file metadata/content", "Medium", 20)
        finding["first_seen"] = "2026-06-04 12:00:00"
        finding["score"] = 455
        result = checker.finalize_findings([finding], config)[0]
        self.assertEqual(result["classification"], "Confirmed Exploit")
        self.assertEqual(result["confidence_level"], "Confirmed")
        self.assertIn("Executor Keyword Match", result.get("detection_categories", []))

    def test_common_runtime_dependencies_never_confirm_from_score(self):
        config = test_config()
        for name in ["sqlite3.dll", "libcrypto-3-x64.dll", "python312.dll", "python3.dll", "libffi-8.dll", "vcruntime140.dll", "msvcp140.dll"]:
            path = f"C:\\Users\\timmy\\Downloads\\OtherApp\\{name}"
            finding = checker.make_finding(path, name, "unit", config)
            checker.add_detection(finding, "A3", "generic dependency string fixture", "High", 100)
            finding["first_seen"] = "2026-06-02 12:00:00"
            finding["supporting_evidence"].append("fixture supporting evidence")
            finding["score"] = 500
            result = checker.finalize_findings([finding], config)[0]
            self.assertNotEqual(result["classification"], "Confirmed Exploit", name)
            self.assertNotEqual(result["confidence_level"], "Confirmed", name)

    def test_os_allowlisted_runtime_never_confirms(self):
        config = test_config()
        finding = checker.make_finding("C:\\Windows\\System32\\python3.dll", "python3.dll", "unit", config)
        checker.add_detection(finding, "A3", "generic system dependency string fixture", "High", 100)
        finding["first_seen"] = "2026-06-02 12:00:00"
        finding["score"] = 500
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")

    def test_allowlisted_runtime_with_strong_behavior_stays_visible_not_confirmed(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\OtherApp\\sqlite3.dll", "sqlite3.dll", "unit", config)
        checker.add_detection(finding, "Suspicious DLL Loading", "DLL loaded into Roblox from suspicious context", "High", 35)
        finding["evidence_types"].append("suspicious_module_load")
        finding["first_seen"] = "2026-06-02 12:00:00"
        finding["score"] = 500
        result = checker.finalize_findings([finding], config)[0]
        self.assertEqual(result["classification"], "Suspicious")
        self.assertEqual(result["confidence_level"], "Likely")

    def test_trusted_razer_app_does_not_confirm_from_score_or_heuristic(self):
        config = test_config()
        finding = checker.make_finding("C:\\Program Files\\Razer\\RazerAppEngine\\RazerAppEngine.exe", "RazerAppEngine.exe", "unit", config)
        finding["signer"] = {"status": "Valid", "subject": "CN=Razer", "issuer": "CN=Trusted CA"}
        checker.add_detection(finding, "Generic Packed File", "High entropy executable content", "High", 100)
        finding["first_seen"] = "2026-06-02 12:00:00"
        finding["score"] = 500
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")
        self.assertNotEqual(result["confidence_level"], "Confirmed")

    def test_svchost_does_not_confirm_without_tamper_evidence(self):
        config = test_config()
        finding = checker.make_finding("C:\\Windows\\System32\\svchost.exe", "svchost.exe", "unit", config)
        finding["signer"] = {"status": "Valid", "subject": "CN=Microsoft Windows", "issuer": "CN=Microsoft Corporation"}
        checker.add_detection(finding, "RAM Suspicious Indicator", "Generic API string fixture", "High", 100)
        finding["evidence_types"].append("sysmon_process_access")
        finding["first_seen"] = "2026-06-02 12:00:00"
        finding["score"] = 500
        result = checker.finalize_findings([finding], config)[0]
        self.assertNotEqual(result["classification"], "Confirmed Exploit")
        self.assertNotEqual(result["confidence_level"], "Confirmed")

    def test_forensic_correlation_requires_artifact_overlap_not_name_only(self):
        config = test_config()
        session = {"start_time": "2026-06-02 14:21:00", "end_time": "2026-06-02 14:40:00"}
        name_only = checker.make_finding("C:\\Users\\timmy\\Downloads\\Xeno.exe", "Xeno.exe", "file_system", config)
        name_only["first_seen"] = "2026-06-02 14:22:00"
        name_only["supporting_evidence"].append("Name-only fixture")
        finalized = checker.finalize_findings([name_only], config)
        correlations = checker.build_forensic_correlation_findings(finalized, [], [session], config)
        self.assertFalse(correlations)

    def test_forensic_correlation_builds_executed_then_deleted_story(self):
        config = test_config()
        session = {"start_time": "2026-06-02 14:21:00", "end_time": "2026-06-02 14:40:00"}
        executed = checker.make_finding("C:\\Users\\timmy\\Downloads\\tool.exe", "tool.exe", "prefetch", config)
        executed["first_seen"] = "2026-06-02 14:22:00"
        executed["evidence_types"].append("prefetch_execution")
        checker.add_detection(executed, "Executed Suspicious File", "Prefetch execution fixture", "High", 25)
        deleted = checker.make_possible_context_finding("C:\\Users\\timmy\\Downloads\\tool.exe", "tool.exe", "Recycle Bin", "Recycle Bin deletion fixture", dt.datetime(2026, 6, 2, 14, 27), config)
        deleted["evidence_types"].append("recovery")
        checker.add_detection(deleted, "Suspicious File Deletion", "Deleted suspicious file metadata fixture", "Medium", 20)
        finalized = checker.finalize_findings([executed, deleted], config)
        timeline = [
            {"time": "2026-06-02 14:21:00", "source": "Roblox log", "text": "Roblox launched"},
            {"time": "2026-06-02 14:22:00", "source": "Prefetch", "text": "tool.exe executed"},
            {"time": "2026-06-02 14:27:00", "source": "Recycle Bin", "text": "tool.exe deleted"},
        ]
        correlations = checker.build_forensic_correlation_findings(finalized, timeline, [session], config)
        names = {item["name"] for item in correlations}
        self.assertIn("Executed-Then-Deleted Application", names)
        story = next(item for item in correlations if item["name"] == "Executed-Then-Deleted Application")
        self.assertGreaterEqual(story["evidence_score_contribution"], 32)
        self.assertTrue(story["event_timeline"])

    def test_relationship_enrichment_marks_executed_deleted(self):
        config = test_config()
        executed = checker.make_finding("C:\\Users\\timmy\\Downloads\\Potassium.exe", "Potassium.exe", "prefetch", config)
        executed["first_seen"] = "2026-06-02 14:22:00"
        executed["evidence_types"].append("prefetch_execution")
        checker.add_detection(executed, "Executed Suspicious File", "Prefetch execution fixture", "High", 25)
        deleted = checker.make_possible_context_finding("C:\\Users\\timmy\\Downloads\\Potassium.exe", "Potassium.exe", "Recycle Bin", "Recycle Bin deletion fixture", dt.datetime(2026, 6, 2, 14, 27), config)
        deleted["evidence_types"].append("recovery")
        checker.add_detection(deleted, "Suspicious File Deletion", "Deleted suspicious file metadata fixture", "Medium", 20)
        finalized = checker.finalize_findings([executed, deleted], config)
        categories = set().union(*(set(f["detection_categories"]) for f in finalized))
        self.assertIn("Executed & Deleted", categories)
        self.assertIn("Suspicious File Deletion/Execution/Modification", categories)

    def test_relationship_enrichment_marks_executed_modified(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\Xeno.exe", "Xeno.exe", "file_system", config)
        finding["first_seen"] = "2026-06-02 14:22:00"
        finding["evidence_types"].append("prefetch_execution")
        finding["supporting_evidence"].append("created=2026-06-02 14:20:00 modified=2026-06-02 14:29:00 accessed=2026-06-02 14:30:00")
        checker.add_detection(finding, "Executed Suspicious File", "Execution fixture", "High", 25)
        finalized = checker.finalize_findings([finding], config)
        self.assertIn("Executed & Modified", finalized[0]["detection_categories"])

    def test_network_and_external_bypass_labels_are_added(self):
        config = test_config()
        network = checker.make_finding("\\\\share\\tools\\Velocity.exe", "Velocity.exe", "file_system", config)
        network["first_seen"] = "2026-06-02 14:22:00"
        network["evidence_types"].append("process_execution")
        checker.add_detection(network, "Executed Suspicious File", "Network execution fixture", "High", 25)
        external = checker.make_finding("E:\\Wave.exe", "Wave.exe", "file_system", config)
        external["first_seen"] = "2026-06-02 14:22:00"
        external["evidence_types"].extend(["process_execution", "external_device"])
        checker.add_detection(external, "External Device Execution", "External execution fixture", "Medium", 20)
        finalized = checker.finalize_findings([network, external], config)
        categories = set().union(*(set(f["detection_categories"]) for f in finalized))
        self.assertIn("Generic Bypass Method (Network File)", categories)
        self.assertIn("Generic Bypass Method (External Device Execution)", categories)

    def test_forensic_correlation_marks_dll_injection_critical_from_sysmon(self):
        config = test_config()
        session = {"start_time": "2026-06-02 14:21:00", "end_time": "2026-06-02 14:40:00"}
        dll = checker.make_finding("C:\\Users\\timmy\\AppData\\Local\\Temp\\module.dll", "module.dll", "event_log", config)
        dll["first_seen"] = "2026-06-02 14:22:00"
        dll["evidence_types"].extend(["sysmon_remote_thread", "suspicious_module_load"])
        checker.add_detection(dll, "Suspicious DLL Loading", "Sysmon DLL/injection fixture", "High", 50)
        finalized = checker.finalize_findings([dll], config)
        correlations = checker.build_forensic_correlation_findings(finalized, [], [session], config)
        story = next(item for item in correlations if item["name"] == "Possible DLL Injection Activity")
        self.assertEqual(story["forensic_confidence"], "Critical")
        self.assertTrue(any("remote-thread" in text.lower() for text in story["supporting_evidence"]))

    def test_reports_save_to_securo_storage_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config()
            config["storage_base_dir"] = tmp
            report = {
                "scanTime": dt.datetime.now().astimezone().isoformat(),
                "hostname": "h",
                "highestResult": "Indicator Found",
                "confidence": "low",
                "evidenceSources": {},
                "timeline": [],
                "sessions": [],
                "findings": [],
                "detectLogs": [],
                "warningLogs": [],
                "recoveryArtifacts": [],
                "antivirusLogs": [],
                "engineResults": [],
                "limitations": [],
                "finalStatement": "test",
            }
            written = checker.save_local_reports(report, config)
            paths = [Path(p) for p in written]
            self.assertTrue((Path(tmp) / "Reports").exists())
            self.assertTrue((Path(tmp) / "History" / "securo_check_history.sqlite").exists())
            self.assertTrue((Path(tmp) / "Logs" / "application_logs.log").exists())
            self.assertTrue(any(p.parent.name == "Reports" and p.suffix == ".html" for p in paths))

    def test_html_report_includes_offline_time_filter(self):
        report = {
            "scanTime": "2026-06-02T17:55:00",
            "hostname": "h",
            "highestResult": "Indicator Found",
            "confidence": "low",
            "evidenceSources": {},
            "timeline": [{"time": "2026-06-02 17:55:00", "source": "unit", "text": "event"}],
            "sessions": [{
                "username": "ExampleUser",
                "userId": "123",
                "placeId": "456",
                "duration": "10m",
                "robloxLogs": [{"rawLog": "x" * 1_000_000}],
                "events": [{"text": "event"} for _ in range(100)],
            }],
            "robloxLogs": [{
                "logFile": "Client.log",
                "startTime": "2026-06-02 17:55:00",
                "events": [{"timestamp": "2026-06-02 17:55:00", "type": "FastFlag", "message": "FFlagUnit=true"}],
                "fastFlags": [{"name": "FFlagUnit", "value": "true", "timestamp": "2026-06-02 17:55:00", "sourceLog": "Client.log"}],
                "rawLog": "FFlagUnit=true",
            }],
            "detectedFastFlags": [{"name": "FFlagUnit", "value": "true", "timestamp": "2026-06-02 17:55:00", "sourceLog": "Client.log"}],
            "findings": [],
            "detectLogs": [{
                "type": "Generic",
                "detectionName": "Unit",
                "severity": "Low",
                "confidenceLevel": "low",
                "manualReviewRequired": True,
                "evidencePath": "unit",
                "timestamp": "2026-06-02 17:55:00",
                "explanation": "unit",
            }],
            "warningLogs": [],
            "recoveryArtifacts": [],
            "antivirusLogs": [],
            "engineResults": [],
            "limitations": [],
            "finalStatement": "test",
        }
        rendered = checker.render_html(report)
        self.assertIn('id="report-time-filter"', rendered)
        self.assertIn('<option value="7" selected>1 week</option>', rendered)
        self.assertIn('<option value="all">All logs</option>', rendered)
        self.assertIn("report-entry", rendered)
        self.assertIn('data-timestamp=', rendered)
        self.assertIn('applyReportTimeFilter', rendered)
        self.assertIn("Detected FastFlags", rendered)
        self.assertIn("Show All Roblox Logs", rendered)
        self.assertIn("FFlagUnit", rendered)

    def test_invalid_pin_stops_before_scan(self):
        original = checker.post_json
        try:
            checker.post_json = lambda *args, **kwargs: (True, {"ok": False, "error": "invalid_or_expired_pin"})
            ok, result = checker.verify_pin("https://example.test", "123456")
        finally:
            checker.post_json = original
        self.assertFalse(ok)
        self.assertEqual(result, "invalid_or_expired_pin")

    def test_upload_failure_is_reported(self):
        original = checker.post_json
        try:
            checker.post_json = lambda *args, **kwargs: (False, "network down")
            ok, result = checker.upload_report("https://example.test", "sid", "tok", {"scanTime": "2026-06-01T00:00:00-05:00"})
        finally:
            checker.post_json = original
        self.assertFalse(ok)
        self.assertIn("network down", result)

    def test_diagnostic_report_schema_for_failed_scan(self):
        config = test_config()
        diag = checker.ScanDiagnostics(config)
        diag.progress("Checking file artifacts", stage="Checking file artifacts", percent=34, files_scanned=1500)
        report = checker.diagnostic_report("timeout", "unit timeout", diag, config)
        self.assertEqual(report["scanStatus"], "timeout")
        self.assertIn("scanTime", report)
        self.assertIn("findings", report)
        self.assertIn("limitations", report)
        self.assertTrue(report["warningLogs"])
        self.assertEqual(report["diagnostics"]["filesScanned"], 1500)

    def test_dedupe_timeline_normalizes_datetime_objects(self):
        events = [
            {"time": "2026-06-23T00:45:50", "source": "String", "text": "later"},
            {"time": dt.datetime(2026, 6, 23, 0, 45, 49), "source": "Datetime", "text": "earlier"},
            {"time": dt.datetime(2026, 6, 23, 0, 45, 49), "source": "Datetime", "text": "earlier"},
        ]
        result = checker.dedupe_timeline(events)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["source"], "Datetime")
        self.assertIsInstance(result[0]["time"], str)
        self.assertEqual(result[1]["source"], "String")

    def test_json_safe_serializes_nested_datetimes(self):
        report = {
            "scanTime": dt.datetime(2026, 6, 23, 1, 2, 3),
            "timeline": [{"time": dt.datetime(2026, 6, 23, 1, 2, 4), "source": "Unit", "text": "ok"}],
            "nested": {"values": {dt.datetime(2026, 6, 23, 1, 2, 5)}},
            "path": Path("C:/Securo/example.exe"),
        }
        safe = checker.json_safe(report)
        json.dumps(safe)
        self.assertEqual(safe["scanTime"], "2026-06-23 01:02:03")
        self.assertIsInstance(safe["timeline"][0]["time"], str)
        self.assertIsInstance(safe["nested"]["values"][0], str)
        self.assertIn("Securo", safe["path"])
        self.assertTrue(safe["path"].endswith("example.exe"))

    def test_run_scan_with_timeout_returns_terminal_report(self):
        config = test_config()
        original = checker.build_scan_report_with_progress
        try:
            def slow_scan(days, cfg, progress):
                time.sleep(2)
                return {}

            checker.build_scan_report_with_progress = slow_scan
            status, report = checker.run_scan_with_timeout(7, config, lambda message: None, timeout_seconds=1)
        finally:
            checker.build_scan_report_with_progress = original
        self.assertEqual(status, "timeout")
        self.assertEqual(report["scanStatus"], "timeout")
        self.assertIn("Last successful operation", " ".join(report["limitations"]))

    def test_run_scan_with_timeout_passes_internal_deadline(self):
        config = test_config()
        config["scan_finish_buffer_seconds"] = 10
        captured = {}
        original = checker.build_scan_report_with_progress
        try:
            def fast_scan(days, cfg, progress):
                captured["deadline"] = cfg.get("_scan_deadline_monotonic")
                captured["remaining"] = checker.scan_time_remaining(cfg)
                return {}

            checker.build_scan_report_with_progress = fast_scan
            status, report = checker.run_scan_with_timeout(7, config, lambda message: None, timeout_seconds=60)
        finally:
            checker.build_scan_report_with_progress = original
        self.assertEqual(status, "completed")
        self.assertEqual(report["scanStatus"], "completed")
        self.assertIsNotNone(captured.get("deadline"))
        self.assertGreater(captured.get("remaining", 0), 40)
        self.assertLess(captured.get("remaining", 999), 60)

    def test_scan_profiles_apply_expected_coverage(self):
        quick = checker.apply_scan_profile(test_config(), "quick")
        standard = checker.apply_scan_profile(test_config(), "standard")
        deep = checker.apply_scan_profile(test_config(), "deep")
        self.assertEqual(quick["scan_profile"], "quick")
        self.assertTrue(quick["skip_browser_artifacts"])
        self.assertEqual(quick["scan_timeout_seconds"], 120)
        self.assertEqual(standard["scan_timeout_seconds"], 360)
        self.assertEqual(deep["scan_timeout_seconds"], 480)
        self.assertEqual(quick["scan_finish_buffer_seconds"], 20)
        self.assertEqual(standard["scan_finish_buffer_seconds"], 35)
        self.assertEqual(deep["scan_finish_buffer_seconds"], 55)
        self.assertLess(quick["scan_timeout_seconds"], standard["scan_timeout_seconds"])
        self.assertGreater(deep["scan_days"], standard["scan_days"])
        self.assertGreater(deep["max_files_scanned"], standard["max_files_scanned"])
        self.assertLessEqual(quick["file_artifact_time_budget_seconds"], 35)
        self.assertLessEqual(standard["file_artifact_time_budget_seconds"], 90)
        self.assertLessEqual(deep["file_artifact_time_budget_seconds"], 210)
        self.assertFalse(standard["skip_browser_artifacts"])
        self.assertFalse(deep["skip_browser_artifacts"])
        self.assertTrue(deep["collect_safe_account_identifiers"])
        self.assertTrue(deep["collect_system_reset_evidence"])
        self.assertEqual(deep["scan_timeout_seconds"], 480)
        self.assertGreaterEqual(deep["scan_days"], 90)
        self.assertGreaterEqual(deep["max_files_scanned"], 60000)

    def test_switching_from_quick_to_deep_clears_quick_skips(self):
        quick = checker.apply_scan_profile(test_config(), "quick")
        deep = checker.apply_scan_profile(quick, "deep")
        self.assertEqual(deep["scan_profile"], "deep")
        self.assertFalse(deep["skip_browser_artifacts"])
        self.assertFalse(deep["skip_recovery_metadata"])

    def test_safe_account_identifiers_include_roblox_and_skip_discord_sensitive_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("APPDATA")
            os.environ["APPDATA"] = tmp
            discord = Path(tmp) / "Discord"
            safe_logs = discord / "logs"
            sensitive = discord / "Local Storage" / "leveldb"
            safe_logs.mkdir(parents=True)
            sensitive.mkdir(parents=True)
            (safe_logs / "main.log").write_text('user_id: "123456789012345678" username: ExampleDiscord', encoding="utf-8")
            (sensitive / "000001.ldb").write_text('user_id: "999999999999999999"', encoding="utf-8")
            config = test_config()
            config["collect_safe_account_identifiers"] = True
            sessions = [{
                "user_id": "123456789",
                "username": "ExampleRoblox",
                "display_name": "Example",
                "place_id": "987",
                "job_id": "abc",
                "start_time": "2026-06-02 12:00:00",
                "end_time": "2026-06-02 12:30:00",
                "log_file": "Client.log",
            }]
            try:
                result = checker.collect_safe_account_identifiers(sessions, config)
            finally:
                if old_appdata is None:
                    os.environ.pop("APPDATA", None)
                else:
                    os.environ["APPDATA"] = old_appdata
        self.assertEqual(result["roblox"][0]["userId"], "123456789")
        discord_ids = {item["userId"] for item in result["discord"]}
        self.assertIn("123456789012345678", discord_ids)
        self.assertNotIn("999999999999999999", discord_ids)
        self.assertIn("excludes tokens", result["privacyNote"].lower())

    def test_verify_pin_returns_scan_profile(self):
        original = checker.post_json
        try:
            checker.post_json = lambda *args, **kwargs: (True, {"ok": True, "pinId": "abc", "scanProfile": "deep"})
            ok, result = checker.verify_pin("https://example.test", "123456")
        finally:
            checker.post_json = original
        self.assertTrue(ok)
        self.assertEqual(result["scanProfile"], "deep")

    def test_large_report_compacts_for_upload(self):
        report = {
            "scanTime": "2026-06-09T00:00:00",
            "hostname": "unit",
            "highestResult": "Suspicious",
            "confidence": "medium",
            "evidenceSources": {},
            "timeline": [{"time": "2026-06-09T00:00:00", "source": "unit", "text": "x" * 2000} for _ in range(3000)],
            "sessions": [{
                "username": "ExampleUser",
                "userId": "123",
                "placeId": "456",
                "duration": "10m",
                "robloxLogs": [{"rawLog": "x" * 1_000_000}],
                "events": [{"text": "event"} for _ in range(100)],
            }],
            "findings": [
                {"name": "possible", "classification": "Indicator Found", "confidenceLevel": "Possible", "score": 5},
                {"name": "confirmed", "classification": "Confirmed Exploit", "confidenceLevel": "Confirmed", "score": 90},
            ],
            "detectLogs": [{"text": "x" * 2000} for _ in range(1000)],
            "warningLogs": [],
            "recoveryArtifacts": [],
            "antivirusLogs": [],
            "engineResults": [],
            "robloxLogs": [{
                "logFile": "Client.log",
                "startTime": "2026-06-09T00:00:00",
                "events": [{"timestamp": "2026-06-09T00:00:00", "type": "FastFlag", "message": "FFlagUnit=true"}],
                "fastFlags": [{"name": "FFlagUnit", "value": "true", "timestamp": "2026-06-09T00:00:00", "sourceLog": "Client.log"}],
                "rawLog": "FFlagUnit=true\n" + ("x" * 2_000_000),
            }],
            "detectedFastFlags": [{"name": "FFlagUnit", "value": "true", "timestamp": "2026-06-09T00:00:00", "sourceLog": "Client.log"}],
            "limitations": [],
            "topScore": 90,
        }
        compacted = checker.compact_report_for_upload(report, max_bytes=1000)
        self.assertTrue(compacted["uploadCompacted"])
        self.assertLessEqual(len(compacted["timeline"]), 80)
        self.assertEqual(compacted["findings"][0]["name"], "confirmed")
        self.assertTrue(compacted["sessions"][0]["robloxLogsOmittedForUpload"])
        self.assertNotIn("robloxLogs", compacted["sessions"][0])
        self.assertEqual(compacted["detectedFastFlags"][0]["name"], "FFlagUnit")
        self.assertTrue(compacted["robloxLogs"][0]["rawLogOmittedForUpload"])
        self.assertEqual(compacted["robloxLogs"][0]["rawLog"], "")
        self.assertIn("full report remains saved locally", " ".join(compacted["limitations"]))
        encoded = json.dumps(compacted, separators=(",", ":"), default=str).encode("utf-8", errors="replace")
        self.assertLess(len(encoded), 900_000)


if __name__ == "__main__":
    unittest.main()
