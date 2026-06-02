import datetime as dt
import importlib.util
import json
import os
import sys
import tempfile
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
        "known_bad_hashes": [],
        "category_thresholds": {"confirmed": 70, "suspicious": 35, "weak": 10},
        "known_safe_signers": ["Microsoft Corporation", "Roblox Corporation", "Python Software Foundation"],
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

    def test_xeno_detection_categories_are_confirmed(self):
        config = test_config()
        config["suspicious_name_terms"].append("xeno")
        cases = [
            ("C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30\\XenoUI.dll", ["DotNetDLL"]),
            ("C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30\\Xeno.exe", ["Tampered File"]),
            ("C:\\Users\\timmy\\Downloads\\Xeno-v1.3.30\\zlib1.dll", ["A3"]),
        ]
        for path, categories in cases:
            finding = checker.make_finding(path, Path(path).name, "unit", config)
            finding["detection_categories"] = categories
            finding["detections"] = [{"category": categories[0], "reason": "fixture", "risk": "High"}]
            finding["score"] = 20
            result = checker.finalize_findings([finding], config)[0]
            self.assertEqual(result["classification"], "Confirmed Exploit", path)
            self.assertGreaterEqual(result["score"], config["category_thresholds"]["confirmed"])

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
        self.assertEqual(result["classification"], "Confirmed Exploit")
        self.assertTrue(any(log["type"] == "Direct" for log in logs))

    def test_a3_alone_is_indicator_found(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\Public\\zlib1.dll", "zlib1.dll", "unit", config)
        finding["detection_categories"] = ["A3"]
        finding["detections"] = [{"category": "A3", "type": "Direct", "reason": "generic string fixture", "risk": "High"}]
        finding["score"] = 100
        result = checker.finalize_findings([finding], config)[0]
        self.assertEqual(result["classification"], "Indicator Found")

    def test_trusted_signed_dependency_downgrades(self):
        config = test_config()
        finding = checker.make_finding("C:\\Users\\timmy\\Downloads\\SECURO\\_internal\\python312.dll", "python312.dll", "unit", config)
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


if __name__ == "__main__":
    unittest.main()
