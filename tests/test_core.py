import datetime as dt
import importlib.util
import inspect
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
        "forensic_export_dirs": [],
        "forensic_export_max_files": 80,
        "forensic_export_max_rows": 5000,
        "external_forensic_tools_enabled": False,
        "external_forensic_tools_dir": "",
        "prefetch_parser_enabled": False,
        "prefetch_parser_timeout_seconds": 25,
        "shellbag_parser_enabled": False,
        "shellbag_parser_timeout_seconds": 30,
        "shellbag_max_records": 5000,
        "usn_journal_enabled": False,
        "usn_journal_max_records": 5000,
        "usn_journal_window_bytes": 4000000,
        "usn_journal_timeout_seconds": 12,
        "external_forensic_tool_timeout_seconds": 55,
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
            "collect_usn_journal_events",
            "collect_jump_list_context",
            "collect_amcache_context",
            "collect_file_artifacts",
            "collect_powershell_history",
            "collect_defender_history",
            "collect_defender_exclusions",
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
            checker.collect_usn_journal_events = lambda days, config, sessions: ([], [], [])
            checker.collect_jump_list_context = lambda days, config, sessions: ([], [])
            checker.collect_amcache_context = lambda days, config, sessions: ([], [])
            checker.collect_file_artifacts = lambda days, config, sessions, verbose=False: ([], [])
            checker.collect_powershell_history = lambda days, config, sessions: ([], [])
            checker.collect_defender_history = lambda days, config, sessions: ([], [])
            checker.collect_defender_exclusions = lambda config: ([], [])
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
        for key in ["detectLogs", "warningLogs", "recoveryArtifacts", "antivirusLogs", "defenderExclusions", "engineResults"]:
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

    def test_roblox_studio_logs_are_not_used_as_player_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_local = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = tmp
            log_dir = Path(tmp) / "Roblox" / "logs"
            log_dir.mkdir(parents=True)
            (log_dir / "Player.log").write_text(
                "2026-06-03 12:00:00 userId: 123 username: Player placeId: 999 jobId: abcdefgh-1234\n",
                encoding="utf-8",
            )
            (log_dir / "Studio.log").write_text(
                "2026-06-03 12:01:00 Roblox Studio RobloxStudioBeta.exe userId: 999 username: StudioUser placeId: 111\n",
                encoding="utf-8",
            )
            fixed = dt.datetime.now().timestamp()
            os.utime(log_dir / "Player.log", (fixed, fixed))
            os.utime(log_dir / "Studio.log", (fixed, fixed))
            try:
                sessions, _ = checker.parse_roblox_logs(30, test_config())
            finally:
                if old_local is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_local
        ids = {session.get("user_id") for session in sessions}
        self.assertIn("123", ids)
        self.assertNotIn("999", ids)

    def test_discord_identifier_collection_skips_token_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("APPDATA")
            old_local = os.environ.get("LOCALAPPDATA")
            os.environ["APPDATA"] = tmp
            os.environ["LOCALAPPDATA"] = tmp
            log_dir = Path(tmp) / "discord" / "logs"
            log_dir.mkdir(parents=True)
            safe_id = "123456789012345678"
            token_adjacent_id = "987654321098765432"
            (log_dir / "discord.log").write_text(
                f"current_user_id: {safe_id} username: SafeUser\n"
                f"token refresh for user_id {token_adjacent_id} authorization header omitted\n",
                encoding="utf-8",
            )
            try:
                accounts = checker.collect_safe_discord_identifiers(test_config())
            finally:
                if old_appdata is None:
                    os.environ.pop("APPDATA", None)
                else:
                    os.environ["APPDATA"] = old_appdata
                if old_local is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_local
        ids = {account["userId"] for account in accounts}
        self.assertIn(safe_id, ids)
        self.assertNotIn(token_adjacent_id, ids)
        self.assertEqual(accounts[0]["platform"], "Discord")

    def test_discord_identifier_collection_handles_current_user_json_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("APPDATA")
            old_local = os.environ.get("LOCALAPPDATA")
            os.environ["APPDATA"] = tmp
            os.environ["LOCALAPPDATA"] = tmp
            log_dir = Path(tmp) / "discordcanary" / "logs"
            log_dir.mkdir(parents=True)
            user_id = "222222222222222222"
            (log_dir / "discord.log").write_text(
                f'info currentUser={{"id":"{user_id}","username":"CurrentUser"}} ready\n',
                encoding="utf-8",
            )
            config = test_config()
            try:
                accounts = checker.collect_safe_discord_identifiers(config)
            finally:
                if old_appdata is None:
                    os.environ.pop("APPDATA", None)
                else:
                    os.environ["APPDATA"] = old_appdata
                if old_local is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_local
        self.assertEqual(accounts[0]["userId"], user_id)
        self.assertEqual(config["_discord_account_status"]["logFilesScanned"], 1)
        self.assertEqual(config["_discord_account_status"]["candidateIdsFound"], 1)

    def test_discord_identifier_allows_current_user_lines_with_message_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_appdata = os.environ.get("APPDATA")
            old_local = os.environ.get("LOCALAPPDATA")
            os.environ["APPDATA"] = tmp
            os.environ["LOCALAPPDATA"] = tmp
            log_dir = Path(tmp) / "discord" / "logs"
            log_dir.mkdir(parents=True)
            user_id = "333333333333333333"
            other_id = "444444444444444444"
            (log_dir / "discord.log").write_text(
                f'info message router currentUser={{"id":"{user_id}","username":"SafeUser"}} channel ready\n'
                f"message author id {other_id} channel dispatch only\n",
                encoding="utf-8",
            )
            config = test_config()
            try:
                accounts = checker.collect_safe_discord_identifiers(config)
            finally:
                if old_appdata is None:
                    os.environ.pop("APPDATA", None)
                else:
                    os.environ["APPDATA"] = old_appdata
                if old_local is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old_local
        ids = {account["userId"] for account in accounts}
        self.assertIn(user_id, ids)
        self.assertNotIn(other_id, ids)

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
        finalized = checker.finalize_findings(findings, config)
        self.assertIn("PREFETCH", findings[0]["detection_categories"])
        self.assertIn("prefetch_execution", findings[0]["evidence_types"])
        self.assertEqual(finalized[0]["classification"], "Indicator Found")
        self.assertEqual(finalized[0]["confidence_level"], "Possible")
        self.assertTrue(any("notepad.exe" in event["text"].lower() for event in timeline))
        self.assertTrue(any(item.startswith("PREFETCH FILE:") for item in findings[0]["supporting_evidence"]))

    def test_known_executor_prefetch_is_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "XENO.EXE-1234ABCD.pf"
            pf.write_bytes(b"SCCA")
            now = dt.datetime.now().timestamp()
            os.utime(pf, (now, now))
            config = test_config()
            config["prefetch_dir"] = tmp
            findings, _ = checker.collect_prefetch_evidence(7, config, [])
            finalized = checker.finalize_findings(findings, config)
        self.assertIn("Confirmed Prefetch Exploit", finalized[0]["detection_categories"])
        self.assertIn("prefetch_confirmed_indicator", finalized[0]["evidence_types"])
        self.assertEqual(finalized[0]["classification"], "Confirmed Exploit")

    def test_clumsy_prefetch_is_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "CLUMSY.EXE-1234ABCD.pf"
            pf.write_bytes(b"SCCA")
            now = dt.datetime.now().timestamp()
            os.utime(pf, (now, now))
            config = test_config()
            config["prefetch_dir"] = tmp
            findings, _ = checker.collect_prefetch_evidence(7, config, [])
            finalized = checker.finalize_findings(findings, config)
        self.assertEqual(finalized[0]["classification"], "Confirmed Exploit")

    def test_fastflag_prefetch_is_confirmed_for_non_roblox_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "TOOL.EXE-1234ABCD.pf"
            pf.write_bytes(b"SCCA" + "C:\\Users\\Test\\Downloads\\ClientAppSettings.json".encode("utf-16-le"))
            now = dt.datetime.now().timestamp()
            os.utime(pf, (now, now))
            config = test_config()
            config["prefetch_dir"] = tmp
            findings, _ = checker.collect_prefetch_evidence(7, config, [])
            finalized = checker.finalize_findings(findings, config)
        self.assertEqual(finalized[0]["classification"], "Confirmed Exploit")

    def test_roblox_prefetch_with_client_settings_is_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "ROBLOXPLAYERBETA.EXE-1234ABCD.pf"
            pf.write_bytes(b"SCCA" + "C:\\Users\\Test\\AppData\\Local\\Roblox\\ClientSettings.json".encode("utf-16-le"))
            now = dt.datetime.now().timestamp()
            os.utime(pf, (now, now))
            config = test_config()
            config["prefetch_dir"] = tmp
            findings, _ = checker.collect_prefetch_evidence(7, config, [])
            finalized = checker.finalize_findings(findings, config)
        self.assertNotEqual(finalized[0]["classification"], "Confirmed Exploit")

    def test_usn_csv_parser_extracts_delete_and_modify_events(self):
        sample = (
            '"File name","Time stamp","Reason","USN","File ID","Parent file ID"\n'
            '"Solara.exe","06/27/2026 14:22:00","FILE_DELETE | CLOSE","0x100","0x10","0x01"\n'
            '"notes.txt","06/27/2026 14:23:00","DATA_OVERWRITE | CLOSE","0x101","0x11","0x01"\n'
        )
        events = checker.parse_usn_journal_csv(sample, "C:", 100, 3650)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["eventType"], "Deleted")
        self.assertEqual(events[0]["fileName"], "Solara.exe")
        self.assertEqual(events[1]["eventType"], "Modified")

    def test_usn_text_parser_extracts_windows_key_value_records(self):
        sample = """
USN                 : 0x0000000000000100
File Ref#           : 0x0000000000000010
Parent File Ref#    : 0x0000000000000001
Time Stamp          : 06/27/2026 14:22:00
Reason              : FILE_DELETE | CLOSE
File Name           : Solara.exe

USN                 : 0x0000000000000101
File Ref#           : 0x0000000000000011
Parent File Ref#    : 0x0000000000000001
Time Stamp          : 06/27/2026 14:23:00
Reason              : DATA_OVERWRITE | CLOSE
File Name           : notes.txt
"""
        events = checker.parse_usn_journal_text(sample, "C:", 100, 3650)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["eventType"], "Deleted")
        self.assertEqual(events[0]["fileName"], "Solara.exe")
        self.assertEqual(events[1]["eventType"], "Modified")

    def test_usn_collector_promotes_only_suspicious_events_to_findings(self):
        sample = (
            '"File name","Time stamp","Reason","USN","File ID","Parent file ID"\n'
            f'"Solara.exe","{dt.datetime.now().strftime("%m/%d/%Y %H:%M:%S")}","FILE_DELETE | CLOSE","0x100","0x10","0x01"\n'
            f'"notes.txt","{dt.datetime.now().strftime("%m/%d/%Y %H:%M:%S")}","DATA_OVERWRITE | CLOSE","0x101","0x11","0x01"\n'
        )
        config = test_config()
        config["usn_journal_enabled"] = True
        original_query = checker.query_usn_journal_state
        original_run = checker.run_command
        try:
            checker.query_usn_journal_state = lambda volume="C:": {
                "available": True,
                "volume": volume,
                "firstUsn": 0x10,
                "nextUsn": 0x1000,
                "error": "",
            }
            checker.run_command = lambda args, timeout=20: sample
            findings, timeline, events = checker.collect_usn_journal_events(7, config, [])
        finally:
            checker.query_usn_journal_state = original_query
            checker.run_command = original_run
        self.assertEqual(len(events), 2)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Solara.exe")
        self.assertIn("Suspicious File Deletion", findings[0]["detection_categories"])
        self.assertTrue(any("Solara.exe" in event["text"] for event in timeline))

    def test_usn_collector_tries_alternate_csv_argument_order(self):
        sample = (
            '"File name","Time stamp","Reason","USN","File ID","Parent file ID"\n'
            f'"Solara.exe","{dt.datetime.now().strftime("%m/%d/%Y %H:%M:%S")}","FILE_DELETE | CLOSE","0x100","0x10","0x01"\n'
        )
        config = test_config()
        config["usn_journal_enabled"] = True
        original_query = checker.query_usn_journal_state
        original_run = checker.run_command
        calls = []
        try:
            checker.query_usn_journal_state = lambda volume="C:": {
                "available": True,
                "volume": volume,
                "firstUsn": 0x10,
                "nextUsn": 0x1000,
                "error": "",
            }
            def fake_run(args, timeout=20):
                calls.append(args)
                if args[-1] == "csv":
                    return "COMMAND_ERROR: invalid parameter"
                return sample
            checker.run_command = fake_run
            findings, timeline, events = checker.collect_usn_journal_events(7, config, [])
        finally:
            checker.query_usn_journal_state = original_query
            checker.run_command = original_run
        self.assertEqual(len(events), 1)
        self.assertEqual(len(findings), 1)
        self.assertIn("csv", calls[1])
        self.assertEqual(config["_usn_journal_status"]["recordsCollected"], 1)

    def test_usn_collector_tries_read_data_csv_variant(self):
        sample = (
            '"File Name","Time Stamp","Reason(s)","USN","File Ref#","Parent File Ref#"\n'
            f'"Xeno.dll","{dt.datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")}","FILE_DELETE | CLOSE","0x100","0x10","0x01"\n'
        )
        config = test_config()
        config["usn_journal_enabled"] = True
        original_query = checker.query_usn_journal_state
        original_run = checker.run_command
        calls = []
        try:
            checker.query_usn_journal_state = lambda volume="C:": {
                "available": True,
                "volume": volume,
                "firstUsn": 0x10,
                "nextUsn": 0x1000,
                "error": "",
            }
            def fake_run(args, timeout=20):
                calls.append(args)
                if "readData" in args:
                    return sample
                return "COMMAND_ERROR: invalid parameter"
            checker.run_command = fake_run
            findings, timeline, events = checker.collect_usn_journal_events(7, config, [])
        finally:
            checker.query_usn_journal_state = original_query
            checker.run_command = original_run
        self.assertEqual(len(events), 1)
        self.assertEqual(findings[0]["name"], "Xeno.dll")
        self.assertTrue(any("readData" in call for call in calls))

    def test_prefetch_inventory_reports_readable_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            pf = Path(tmp) / "EXAMPLE.EXE-1234ABCD.pf"
            pf.write_bytes(b"SCCA")
            config = test_config()
            config["prefetch_dir"] = tmp
            original_enabled = checker.prefetch_registry_enabled
            original_admin = checker.is_windows_admin
            original_install = checker.windows_install_time
            try:
                checker.prefetch_registry_enabled = lambda: True
                checker.is_windows_admin = lambda: True
                checker.windows_install_time = lambda: dt.datetime.now() - dt.timedelta(days=2)
                inventory = checker.prefetch_inventory(config)
            finally:
                checker.prefetch_registry_enabled = original_enabled
                checker.is_windows_admin = original_admin
                checker.windows_install_time = original_install
        self.assertTrue(inventory["readable"])
        self.assertEqual(inventory["count"], 1)
        self.assertTrue(inventory["oldest"])
        self.assertTrue(inventory["newest"])

    def test_prefetch_inventory_explains_non_admin_empty_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = test_config()
            config["prefetch_dir"] = tmp
            original_enabled = checker.prefetch_registry_enabled
            original_admin = checker.is_windows_admin
            try:
                checker.prefetch_registry_enabled = lambda: True
                checker.is_windows_admin = lambda: False
                inventory = checker.prefetch_inventory(config)
            finally:
                checker.prefetch_registry_enabled = original_enabled
                checker.is_windows_admin = original_admin
        self.assertFalse(inventory["readable"])
        self.assertIn("administrator", inventory["error"].lower())

    def test_admin_guard_allows_already_elevated_process(self):
        original_admin = checker.is_windows_admin
        try:
            checker.is_windows_admin = lambda: True
            self.assertTrue(checker.ensure_windows_admin())
        finally:
            checker.is_windows_admin = original_admin

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
        self.assertTrue(any(item.startswith("DELETED FILE:") for item in findings[0]["supporting_evidence"]))

    def test_recycle_bin_skips_sid_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "S-1-5-21-123-456-789-1001").mkdir()
            config = test_config()
            config["recycle_bin_roots"] = [tmp]
            findings, timeline = checker.collect_recycle_bin_context(7, config, [])
        self.assertFalse(findings)
        self.assertFalse(timeline)

    def test_recycle_bin_r_file_uses_i_metadata_original_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deleted_time = dt.datetime(2026, 6, 2, 14, 27)
            filetime = int((deleted_time - dt.datetime(1601, 1, 1)).total_seconds() * 10_000_000)
            original = "C:\\Users\\Test\\Downloads\\Potassium.exe"
            i_file = root / "$IABC123.exe"
            r_file = root / "$RABC123.exe"
            i_file.write_bytes((1).to_bytes(8, "little") + (123).to_bytes(8, "little") + filetime.to_bytes(8, "little") + original.encode("utf-16-le") + b"\x00\x00")
            r_file.write_text("deleted content fixture", encoding="utf-8")
            config = test_config()
            config["recycle_bin_roots"] = [tmp]
            findings, timeline = checker.collect_recycle_bin_context(30, config, [])
        self.assertTrue(findings)
        self.assertTrue(any(f.get("path") == original for f in findings))
        self.assertTrue(any("DELETED FILE: C:\\Users\\Test\\Downloads\\Potassium.exe" in event["text"] for event in timeline))
        self.assertTrue(any("Recoverable Recycle Bin content file" in item for f in findings for item in f["supporting_evidence"]))

    def test_jump_list_context_extracts_suspicious_recent_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "unit.automaticDestinations-ms"
            artifact.write_bytes("C:\\Users\\Test\\Downloads\\Solara.exe\x00".encode("utf-16-le"))
            config = test_config()
            config["jump_list_roots"] = [tmp]
            findings, timeline = checker.collect_jump_list_context(7, config, [])
        self.assertTrue(findings)
        self.assertIn("Jump List Recent Item Context", findings[0]["detection_categories"])
        self.assertIn("jump_list_context", findings[0]["evidence_types"])
        self.assertTrue(any("Solara.exe" in event["text"] for event in timeline))

    def test_amcache_context_extracts_suspicious_program_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            hive = Path(tmp) / "Amcache.hve"
            hive.write_bytes("C:\\Users\\Test\\Downloads\\Xeno.exe\x00".encode("utf-16-le"))
            config = test_config()
            config["amcache_path"] = str(hive)
            findings, timeline = checker.collect_amcache_context(7, config, [])
        self.assertTrue(findings)
        self.assertIn("Amcache Execution/Install Context", findings[0]["detection_categories"])
        self.assertIn("amcache_context", findings[0]["evidence_types"])
        self.assertTrue(any("Xeno.exe" in event["text"] for event in timeline))

    def test_external_pecmd_export_adds_prefetch_key_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp) / "PECmd_Output.csv"
            export.write_text(
                "ExecutableName,LastRun,SourceFile\n"
                "Potassium.exe,2026-06-02 17:55:00,C:\\Windows\\Prefetch\\POTASSIUM.EXE-12345678.pf\n",
                encoding="utf-8",
            )
            config = test_config()
            config["forensic_export_dirs"] = [tmp]
            findings, timeline = checker.collect_external_forensic_exports(3650, config, [])
        finding = next(item for item in findings if "Potassium.exe" in item.get("path", ""))
        self.assertIn("prefetch_execution", finding["evidence_types"])
        self.assertTrue(any(item.startswith("PREFETCH FILE:") for item in finding["supporting_evidence"]))
        self.assertTrue(any("PREFETCH FILE: Potassium.exe" in event["text"] for event in timeline))

    def test_external_mftecmd_export_adds_deleted_file_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp) / "MFTECmd_Output.csv"
            export.write_text(
                "FullPath,IsDeleted,DeletedTime\n"
                "C:\\Users\\Test\\Downloads\\Wave.exe,true,2026-06-02 18:05:00\n",
                encoding="utf-8",
            )
            config = test_config()
            config["forensic_export_dirs"] = [tmp]
            findings, timeline = checker.collect_external_forensic_exports(3650, config, [])
        finding = next(item for item in findings if "Wave.exe" in item.get("path", ""))
        self.assertIn("File Deletion", finding["detection_categories"])
        self.assertIn("recovery", finding["evidence_types"])
        self.assertTrue(any(item.startswith("DELETED FILE:") for item in finding["supporting_evidence"]))
        self.assertTrue(any("DELETED FILE: C:\\Users\\Test\\Downloads\\Wave.exe" in event["text"] for event in timeline))

    def test_external_forensic_tool_runner_is_opt_in_and_whitelisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / "Tools"
            prefetch = root / "Prefetch"
            tools.mkdir()
            prefetch.mkdir()
            (tools / "PECmd.exe").write_text("fixture", encoding="utf-8")
            config = test_config()
            config["storage_base_dir"] = str(root / "Securo")
            config["external_forensic_tools_enabled"] = True
            config["external_forensic_tools_dir"] = str(tools)
            config["prefetch_dir"] = str(prefetch)
            calls = []
            original = checker.run_command
            try:
                checker.run_command = lambda args, timeout=20: calls.append(args) or ""
                notes = checker.execute_external_forensic_tools(7, config)
            finally:
                checker.run_command = original
        self.assertTrue(calls)
        self.assertEqual(Path(calls[0][0]).name, "PECmd.exe")
        self.assertIn("--csv", calls[0])
        self.assertTrue(config.get("_external_forensic_output_dir"))
        self.assertTrue(any("PECmd" in note for note in notes))

    def test_forensic_tool_discovery_finds_nested_zimmerman_net9_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            tools = Path(tmp) / "Tools"
            recmd = tools / "net9" / "RECmd"
            evtx = tools / "net9" / "EvtxECmd"
            recmd.mkdir(parents=True)
            evtx.mkdir(parents=True)
            (recmd / "RECmd.exe").write_text("fixture", encoding="utf-8")
            (evtx / "EvtxECmd.exe").write_text("fixture", encoding="utf-8")
            config = test_config()
            config["external_forensic_tools_dir"] = str(tools)
            found = checker.available_forensic_tools(config)
        self.assertEqual(found["RECmd.exe"].name, "RECmd.exe")
        self.assertEqual(found["EvtxECmd.exe"].name, "EvtxECmd.exe")

    def test_new_zimmerman_exports_are_classified(self):
        self.assertEqual(checker.forensic_export_family(Path("RECmd_UserActivity.csv"), ["UserAssist", "Path"]), "RECmd")
        self.assertEqual(checker.forensic_export_family(Path("RBCmd_Output.csv"), ["DeletedTime", "FileName"]), "RBCmd")
        self.assertEqual(checker.forensic_export_family(Path("LECmd_Output.csv"), ["TargetPath", "SourceFile"]), "LECmd")
        self.assertEqual(checker.forensic_export_family(Path("WxTCmd_Output.csv"), ["ActivityTime", "AppId"]), "WxTCmd")

    def test_prefetch_parser_runs_without_enabling_every_forensic_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / "Tools"
            prefetch = root / "Prefetch"
            tools.mkdir()
            prefetch.mkdir()
            (tools / "PECmd.exe").write_text("fixture", encoding="utf-8")
            config = test_config()
            config["storage_base_dir"] = str(root / "Securo")
            config["external_forensic_tools_enabled"] = False
            config["prefetch_parser_enabled"] = True
            config["external_forensic_tools_dir"] = str(tools)
            config["prefetch_dir"] = str(prefetch)
            calls = []
            original = checker.run_command
            try:
                checker.run_command = lambda args, timeout=20: calls.append((args, timeout)) or ""
                notes = checker.execute_external_forensic_tools(7, config)
            finally:
                checker.run_command = original
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0][0][0]).name, "PECmd.exe")
        self.assertIn("--csv", calls[0][0])
        self.assertTrue(any("PECmd" in note for note in notes))

    def test_sbecmd_runs_live_read_only_without_enabling_every_forensic_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / "Tools"
            tools.mkdir()
            (tools / "SBECmd.exe").write_text("fixture", encoding="utf-8")
            config = test_config()
            config["storage_base_dir"] = str(root / "Securo")
            config["external_forensic_tools_enabled"] = False
            config["shellbag_parser_enabled"] = True
            config["external_forensic_tools_dir"] = str(tools)
            calls = []
            original = checker.run_command
            try:
                checker.run_command = lambda args, timeout=20: calls.append((args, timeout)) or ""
                notes = checker.execute_external_forensic_tools(7, config)
            finally:
                checker.run_command = original
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0][0][0]).name, "SBECmd.exe")
        self.assertIn("-l", calls[0][0])
        self.assertIn("--csv", calls[0][0])
        self.assertIn("--csvf", calls[0][0])
        self.assertTrue(any("SBECmd live ShellBag parser completed" in note for note in notes))

    def test_sbecmd_csv_is_preserved_and_suspicious_paths_become_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp) / "SBECmd_ShellBags.csv"
            export.write_text(
                "AbsolutePath,ShellType,LastInteracted,FirstInteracted,SourceFile,Slot,MruPosition\n"
                "C:\\Users\\Test\\Downloads\\Solara,Directory,2026-06-02 17:55:00,2026-06-02 17:50:00,UsrClass.dat,4,1\n"
                "\\\\server\\share\\NormalFolder,Network,2026-06-02 18:00:00,2026-06-02 17:58:00,UsrClass.dat,5,2\n",
                encoding="utf-8",
            )
            config = test_config()
            config["forensic_export_dirs"] = [tmp]
            config["shellbag_max_records"] = 100
            findings, timeline, artifacts = checker.collect_sbecmd_shellbags(3650, config, [])
        artifact_by_path = {item["path"]: item for item in artifacts}
        self.assertEqual(artifact_by_path["C:\\Users\\Test\\Downloads\\Solara"]["classification"], "Old / Deleted Folder")
        self.assertEqual(artifact_by_path["\\\\server\\share\\NormalFolder"]["classification"], "Network / External Folder")
        self.assertTrue(any("Solara" in finding["path"] for finding in findings))
        self.assertTrue(any("ShellBag Old / Deleted Folder" in event["text"] for event in timeline))

    def test_fastflag_injector_pattern_becomes_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fastflag_injector_gui_enhanced.exe"
            path.write_bytes(
                b"MZ RobloxPlayerBeta.exe Enhanced FastFlag Injector FFlag DFFlag DFInt FLog "
                b"Inject Once OpenProcess WriteProcessMemory Failed to find FVar container in Roblox memory"
            )
            config = test_config()
            finding = checker.make_finding(str(path), path.name, "unit", config)
            checker.inspect_file_indicators(str(path), finding)
            finding["first_seen"] = "2026-06-02 12:00:00"
            result = checker.finalize_findings([finding], config)[0]
        self.assertIn("Confirmed FastFlag Injector", result["detection_categories"])
        self.assertEqual(result["classification"], "Confirmed Exploit")

    def test_potassium_executor_bundle_pattern_becomes_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "OpXOyuApWKTlFzrV (3)" / "bin"
            root.mkdir(parents=True)
            path = root / "Potassium.exe"
            path.write_bytes(b"MZ Potassium Potassium.dll monaco basic-languages lua RBXScriptSignal.js Drawing.js crypt.js raknet.js loader.js")
            config = test_config()
            finding = checker.make_finding(str(path), path.name, "unit", config)
            checker.inspect_file_indicators(str(path), finding)
            finding["first_seen"] = "2026-06-02 12:00:00"
            result = checker.finalize_findings([finding], config)[0]
        self.assertIn("Confirmed Executor Artifact", result["detection_categories"])
        self.assertEqual(result["classification"], "Confirmed Exploit")

    def test_clumsy_windivert_pattern_is_high_risk_but_not_executor(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clumsy.exe"
            path.write_bytes(b"MZ clumsy WinDivert WinDivert64.sys lag drop throttle duplicate tamper")
            config = test_config()
            finding = checker.make_finding(str(path), path.name, "unit", config)
            checker.inspect_file_indicators(str(path), finding)
            finding["first_seen"] = "2026-06-02 12:00:00"
            result = checker.finalize_findings([finding], config)[0]
        self.assertIn("Network Lag Tool / WinDivert Manipulation", result["detection_categories"])
        self.assertEqual(result["classification"], "Suspicious")
        self.assertEqual(result["confidence_level"], "Likely")
        self.assertNotEqual(result["classification"], "Confirmed Exploit")

    def test_key_artifacts_collect_prefetch_and_deleted_files_for_report(self):
        finding = checker.make_finding("C:/Users/Test/Downloads/Example.exe", "Example.exe", "unit", test_config())
        finding["first_seen"] = "2026-06-02 17:55:00"
        finding["supporting_evidence"] = [
            "PREFETCH FILE: Example.exe",
            "DELETED FILE: C:/Users/Test/Downloads/Example.exe",
        ]
        timeline = [
            {"time": "2026-06-02 17:55:01", "source": "Prefetch", "text": "PREFETCH FILE: Example.exe from EXAMPLE.EXE-1234.pf"},
            {"time": "2026-06-02 17:55:02", "source": "Recycle Bin", "text": "DELETED FILE: C:/Users/Test/Downloads/Example.exe"},
        ]
        artifacts = checker.key_artifacts_from_report_parts([finding], timeline, [])
        labels = [item["label"] for item in artifacts]
        self.assertTrue(any(label.startswith("PREFETCH FILE:") for label in labels))
        self.assertTrue(any(label.startswith("DELETED FILE:") for label in labels))

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
            "keyArtifacts": [{
                "type": "Prefetch",
                "label": "PREFETCH FILE: Example.exe",
                "path": "C:/Windows/Prefetch/EXAMPLE.EXE-1234.pf",
                "timestamp": "2026-06-02 17:55:00",
                "source": "Prefetch",
                "confidence": "Possible",
            }],
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
            "accountIdentifiers": {
                "privacyNote": "Only non-secret identifiers.",
                "roblox": [{"platform": "Roblox", "userId": "123", "username": "ExampleUser", "displayName": "Example", "firstSeen": "2026-06-02 17:55:00", "lastSeen": "2026-06-02 17:55:00", "sources": ["Client.log"]}],
                "discord": [{"platform": "Discord", "userId": "123456789012345678", "username": "DiscordUser", "displayName": "", "firstSeen": "2026-06-02 17:55:00", "lastSeen": "2026-06-02 17:55:00", "sources": ["discord.log"], "evidenceNote": "Safe Discord log identifier evidence only."}],
            },
            "systemResetEvidence": [{
                "type": "Possible Windows Reset/Reinstall",
                "timestamp": "2026-05-01 10:30:00",
                "source": "Windows CurrentVersion InstallDate",
                "details": "Windows installation timestamp.",
            }],
            "windowsInstallHistory": [{
                "productName": "Windows 10 Home",
                "releaseId": "2009",
                "currentBuild": "19045",
                "installDate": "2021-04-14 13:28:43",
                "source": "HKLM/SYSTEM/Setup/Source OS",
            }],
            "sysMainService": {
                "serviceName": "SysMain",
                "currentState": "Stopped",
                "startupType": "Disabled",
                "lastChanged": "",
                "manualReviewRequired": True,
            },
            "usnJournalEvents": [{
                "timestamp": "2026-06-02 17:56:00",
                "eventType": "Deleted",
                "fileName": "Example.exe",
                "reason": "FILE_DELETE | CLOSE",
                "usn": "0x100",
                "parentFileId": "0x01",
            }],
            "shellBagArtifacts": [{
                "timestamp": "2026-06-02 17:54:00",
                "classification": "Old / Deleted Folder",
                "path": "C:\\Users\\Test\\Downloads\\Solara",
                "shellType": "Directory",
                "sourceHive": "UsrClass.dat",
                "slot": "4",
                "mruPosition": "1",
            }],
            "limitations": [],
            "finalStatement": "test",
        }
        rendered = checker.render_html(report)
        self.assertNotIn('id="report-time-filter"', rendered)
        self.assertIn("report-entry", rendered)
        self.assertIn('data-timestamp=', rendered)
        self.assertNotIn('applyReportTimeFilter', rendered)
        self.assertNotIn('id="report-filter-count"', rendered)
        self.assertIn("Detected FastFlags", rendered)
        self.assertIn("Show All Roblox Logs", rendered)
        self.assertIn("FFlagUnit", rendered)
        self.assertIn("Key Artifacts", rendered)
        self.assertIn("PREFETCH FILE: Example.exe", rendered)
        self.assertIn("Roblox Account History", rendered)
        self.assertIn("Discord Account Evidence", rendered)
        self.assertIn("123456789012345678", rendered)
        self.assertIn("Factory Reset Information", rendered)
        self.assertIn("Windows 10 Home", rendered)
        self.assertIn("Startup Type: Disabled", rendered)
        self.assertIn("Possible Windows Reset/Reinstall", rendered)
        self.assertIn("USN Journal Events", rendered)
        self.assertIn("FILE_DELETE", rendered)
        self.assertIn("ShellBag Analyzer", rendered)
        self.assertIn("Old / Deleted Folder", rendered)

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

    def test_deleted_file_artifacts_survive_when_file_scan_is_skipped(self):
        config = test_config()
        config["_scan_deadline_monotonic"] = time.monotonic() - 1
        calls = []
        originals = {}
        for name in [
            "parse_roblox_logs",
            "collect_process_evidence",
            "collect_running_processes",
            "collect_network_ioc_evidence",
            "collect_prefetch_evidence",
            "collect_usn_journal_events",
            "collect_recycle_bin_context",
            "collect_jump_list_context",
            "collect_amcache_context",
            "collect_file_artifacts",
            "collect_safe_account_identifiers",
            "evidence_quality",
            "collect_system_info",
        ]:
            originals[name] = getattr(checker, name)
        try:
            checker.parse_roblox_logs = lambda days, cfg: ([], [])
            checker.collect_process_evidence = lambda days, cfg, sessions: ([], [])
            checker.collect_running_processes = lambda cfg, sessions: ([], [])
            checker.collect_network_ioc_evidence = lambda cfg: ([], [])
            checker.collect_prefetch_evidence = lambda days, cfg, sessions: (calls.append("prefetch") or ([], []))
            checker.collect_usn_journal_events = lambda days, cfg, sessions: (calls.append("usn") or ([], [], []))
            checker.collect_recycle_bin_context = lambda days, cfg, sessions: (calls.append("deleted") or ([], [{"time": "2026-06-02 17:55:00", "source": "Recycle Bin", "text": "DELETED FILE: C:/Temp/a.exe"}]))
            checker.collect_jump_list_context = lambda days, cfg, sessions: (calls.append("jump") or ([], []))
            checker.collect_amcache_context = lambda days, cfg, sessions: (calls.append("amcache") or ([], []))
            checker.collect_file_artifacts = lambda days, cfg, sessions, verbose=False, progress=None: (calls.append("files") or ([], []))
            checker.collect_safe_account_identifiers = lambda sessions, cfg: {}
            checker.evidence_quality = lambda days: {"Prefetch available": True}
            checker.collect_system_info = lambda: {"hostname": "unit-host", "scan_time": "old"}
            report = checker.build_scan_report_with_progress(7, config, lambda message: None)
        finally:
            for name, value in originals.items():
                setattr(checker, name, value)
        self.assertNotIn("files", calls)
        self.assertIn("deleted", calls)
        self.assertIn("DELETED FILE:", json.dumps(report))

    def test_priority_forensic_stages_run_before_file_artifacts(self):
        config = test_config()
        config["_scan_deadline_monotonic"] = time.monotonic() + 600
        calls = []
        originals = {}
        for name in [
            "parse_roblox_logs",
            "collect_process_evidence",
            "collect_running_processes",
            "collect_network_ioc_evidence",
            "collect_prefetch_evidence",
            "collect_usn_journal_events",
            "collect_recycle_bin_context",
            "collect_jump_list_context",
            "collect_amcache_context",
            "execute_external_forensic_tools",
            "collect_sbecmd_shellbags",
            "collect_external_forensic_exports",
            "collect_powershell_history",
            "collect_defender_history",
            "collect_defender_exclusions",
            "collect_persistence",
            "collect_browser_downloads",
            "collect_shellbag_context",
            "collect_recovery_artifacts",
            "collect_warning_logs",
            "collect_file_artifacts",
            "collect_safe_account_identifiers",
            "evidence_quality",
            "collect_system_info",
        ]:
            originals[name] = getattr(checker, name)
        try:
            checker.parse_roblox_logs = lambda days, cfg: ([], [])
            checker.collect_process_evidence = lambda days, cfg, sessions: ([], [])
            checker.collect_running_processes = lambda cfg, sessions: ([], [])
            checker.collect_network_ioc_evidence = lambda cfg: ([], [])
            checker.collect_prefetch_evidence = lambda days, cfg, sessions: (calls.append("prefetch") or ([], []))
            checker.collect_usn_journal_events = lambda days, cfg, sessions: (calls.append("usn") or ([], [], []))
            checker.collect_recycle_bin_context = lambda days, cfg, sessions: (calls.append("deleted") or ([], []))
            checker.collect_jump_list_context = lambda days, cfg, sessions: (calls.append("jump") or ([], []))
            checker.collect_amcache_context = lambda days, cfg, sessions: (calls.append("amcache") or ([], []))
            checker.execute_external_forensic_tools = lambda days, cfg: (calls.append("external-tools") or [])
            checker.collect_sbecmd_shellbags = lambda days, cfg, sessions: (calls.append("sbecmd") or ([], [], []))
            checker.collect_external_forensic_exports = lambda days, cfg, sessions: (calls.append("external-exports") or ([], []))
            checker.collect_powershell_history = lambda days, cfg, sessions: (calls.append("powershell") or ([], []))
            checker.collect_defender_history = lambda days, cfg, sessions: (calls.append("defender") or ([], []))
            checker.collect_defender_exclusions = lambda cfg: (calls.append("exclusions") or ([], []))
            checker.collect_persistence = lambda days, cfg, sessions: (calls.append("persistence") or ([], []))
            checker.collect_browser_downloads = lambda days, cfg, sessions: (calls.append("browser") or ([], []))
            checker.collect_shellbag_context = lambda days, cfg, sessions: (calls.append("shellbag") or ([], []))
            checker.collect_recovery_artifacts = lambda days, cfg, sessions: (calls.append("recovery") or ([], [], []))
            checker.collect_warning_logs = lambda days, cfg, sessions: (calls.append("warnings") or ([], [], []))
            checker.collect_file_artifacts = lambda days, cfg, sessions, verbose=False, progress=None: (calls.append("files") or ([], []))
            checker.collect_safe_account_identifiers = lambda sessions, cfg: {}
            checker.evidence_quality = lambda days: {"Prefetch available": True}
            checker.collect_system_info = lambda: {"hostname": "unit-host", "scan_time": "old"}
            checker.build_scan_report_with_progress(7, config, lambda message: None)
        finally:
            for name, value in originals.items():
                setattr(checker, name, value)
        self.assertIn("files", calls)
        for stage in ["prefetch", "usn", "deleted", "jump", "amcache", "defender", "persistence", "browser", "shellbag", "recovery", "warnings"]:
            self.assertLess(calls.index(stage), calls.index("files"))

    def test_scan_profiles_apply_expected_coverage(self):
        quick = checker.apply_scan_profile(test_config(), "quick")
        standard = checker.apply_scan_profile(test_config(), "standard")
        deep = checker.apply_scan_profile(test_config(), "deep")
        self.assertEqual(quick["scan_profile"], "quick")
        self.assertTrue(quick["skip_browser_artifacts"])
        self.assertEqual(quick["scan_timeout_seconds"], 120)
        self.assertEqual(standard["scan_timeout_seconds"], 360)
        self.assertEqual(deep["scan_timeout_seconds"], 600)
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
        self.assertFalse(quick["external_forensic_tools_enabled"])
        self.assertFalse(standard["external_forensic_tools_enabled"])
        self.assertTrue(deep["external_forensic_tools_enabled"])
        self.assertTrue(deep["collect_safe_account_identifiers"])
        self.assertTrue(quick["collect_system_reset_evidence"])
        self.assertTrue(standard["collect_system_reset_evidence"])
        self.assertTrue(deep["collect_system_reset_evidence"])
        self.assertEqual(deep["scan_timeout_seconds"], 600)
        self.assertGreaterEqual(deep["scan_days"], 90)
        self.assertGreaterEqual(deep["max_files_scanned"], 60000)

    def test_file_artifact_budget_is_enforced_inside_large_directory(self):
        config = test_config()
        config["file_artifact_time_budget_seconds"] = 1
        config["max_files_scanned"] = 100
        progress_messages = []
        ticks = iter([0.0, 0.0, 0.0, 2.0])
        original_roots = checker.scan_roots
        original_walk = checker.os.walk
        original_monotonic = checker.time.monotonic
        try:
            checker.scan_roots = lambda: [Path("C:/large")]
            checker.os.walk = lambda root, topdown=True: iter([
                ("C:/large", [], ["first.exe", "second.exe", "third.exe"])
            ])
            checker.time.monotonic = lambda: next(ticks, 2.0)
            findings, timeline = checker.collect_file_artifacts(
                7,
                config,
                [],
                progress=lambda message, files_scanned=0: progress_messages.append((message, files_scanned)),
            )
        finally:
            checker.scan_roots = original_roots
            checker.os.walk = original_walk
            checker.time.monotonic = original_monotonic
        self.assertEqual(findings, [])
        self.assertEqual(timeline, [])
        self.assertTrue(any("hit time cap after 1 files" in message for message, _ in progress_messages))
        self.assertTrue(config["_file_artifact_status"]["truncated"])
        self.assertEqual(config["_file_artifact_status"]["filesScanned"], 1)

    def test_switching_from_quick_to_deep_clears_quick_skips(self):
        quick = checker.apply_scan_profile(test_config(), "quick")
        deep = checker.apply_scan_profile(quick, "deep")
        self.assertEqual(deep["scan_profile"], "deep")
        self.assertFalse(deep["skip_browser_artifacts"])
        self.assertFalse(deep["skip_recovery_metadata"])

    def test_safe_account_identifiers_include_roblox(self):
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
        original_roblox = checker.collect_historical_roblox_identifiers
        original_discord = checker.collect_safe_discord_identifiers
        try:
            checker.collect_historical_roblox_identifiers = lambda config: []
            checker.collect_safe_discord_identifiers = lambda config: []
            result = checker.collect_safe_account_identifiers(sessions, {"collect_safe_account_identifiers": True})
        finally:
            checker.collect_historical_roblox_identifiers = original_roblox
            checker.collect_safe_discord_identifiers = original_discord
        self.assertEqual(result["roblox"][0]["userId"], "123456789")
        self.assertIn("discord", result)
        self.assertEqual(result["discord"], [])
        self.assertIn("roblox", result["privacyNote"].lower())
        self.assertIn("discord", result["privacyNote"].lower())

    def test_historical_roblox_accounts_are_collected_outside_session_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "Roblox" / "logs"
            log_dir.mkdir(parents=True)
            old_log = log_dir / "old-session.log"
            old_log.write_text(
                "2025-01-01 12:00:00 userId: 24681012 username: OlderPlayer displayName: Older Display",
                encoding="utf-8",
            )
            original_dirs = checker.get_common_roblox_log_dirs
            original_command = checker.run_command
            try:
                checker.get_common_roblox_log_dirs = lambda: [log_dir]
                checker.run_command = lambda *args, **kwargs: ""
                result = checker.collect_safe_account_identifiers([], {
                    "collect_safe_account_identifiers": True,
                    "account_log_max_files": 20,
                    "account_log_max_bytes": 100000,
                })
            finally:
                checker.get_common_roblox_log_dirs = original_dirs
                checker.run_command = original_command
        self.assertEqual(result["roblox"][0]["userId"], "24681012")
        self.assertEqual(result["roblox"][0]["username"], "OlderPlayer")
        self.assertIn("old-session.log", result["roblox"][0]["sources"][0])

    def test_historical_roblox_accounts_ignore_studio_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "Roblox" / "logs"
            log_dir.mkdir(parents=True)
            (log_dir / "studio-history.log").write_text(
                "2025-01-01 12:00:00 Roblox Studio RobloxStudioBeta.exe userId: 1357911 username: StudioOnly",
                encoding="utf-8",
            )
            original_dirs = checker.get_common_roblox_log_dirs
            original_command = checker.run_command
            try:
                checker.get_common_roblox_log_dirs = lambda: [log_dir]
                checker.run_command = lambda *args, **kwargs: ""
                result = checker.collect_safe_account_identifiers([], {
                    "collect_safe_account_identifiers": True,
                    "account_log_max_files": 20,
                    "account_log_max_bytes": 100000,
                })
            finally:
                checker.get_common_roblox_log_dirs = original_dirs
                checker.run_command = original_command
        self.assertEqual(result["roblox"], [])

    def test_reset_history_uses_windows_install_timestamp(self):
        original_command = checker.run_command
        original_exists = checker.safe_exists
        original_events = checker.query_events
        try:
            checker.run_command = lambda command, **kwargs: (
                "InstallDate    REG_DWORD    0x65ec8780"
                if command[:2] == ["reg", "query"]
                else ""
            )
            checker.safe_exists = lambda path: False
            checker.query_events = lambda *args, **kwargs: []
            evidence, timeline = checker.collect_system_reset_evidence(7, {})
        finally:
            checker.run_command = original_command
            checker.safe_exists = original_exists
            checker.query_events = original_events
        self.assertEqual(evidence[0]["type"], "Possible Windows Reset/Reinstall")
        self.assertTrue(evidence[0]["timestamp"])
        self.assertIn("may represent", evidence[0]["details"].lower())
        self.assertTrue(timeline)

    def test_windows_install_record_parser(self):
        record = checker.parse_windows_install_record(
            r"HKLM\SYSTEM\Setup\Source OS (Updated on 4/14/2021)",
            """
ProductName    REG_SZ    Windows 10 Home
ReleaseId      REG_SZ    2009
CurrentBuild   REG_SZ    19045
InstallDate    REG_DWORD    0x60764fa0
""",
        )
        self.assertEqual(record["productName"], "Windows 10 Home")
        self.assertEqual(record["releaseId"], "2009")
        self.assertEqual(record["currentBuild"], "19045")
        self.assertTrue(record["installDate"])

    def test_sysmain_service_info_reports_disabled_state(self):
        original_run = checker.run_command
        original_events = checker.query_events
        try:
            checker.run_command = lambda args, timeout=20: (
                "STATE              : 1  STOPPED"
                if "query" in args
                else "START_TYPE         : 4   DISABLED"
            )
            checker.query_events = lambda *args, **kwargs: [{
                "time": "2026-06-01 12:00:00",
                "data": {"param1": "SysMain", "param2": "disabled"},
                "raw": "SysMain disabled",
            }]
            info = checker.collect_sysmain_service_info(7)
        finally:
            checker.run_command = original_run
            checker.query_events = original_events
        self.assertEqual(info["currentState"], "Stopped")
        self.assertEqual(info["startupType"], "Disabled")
        self.assertEqual(info["lastChanged"], "2026-06-01 12:00:00")
        self.assertTrue(info["manualReviewRequired"])

    def test_progress_scan_collects_account_history_before_slow_artifacts(self):
        source = inspect.getsource(checker.build_scan_report_with_progress)
        self.assertLess(
            source.index('emit_progress(progress, "Checking account history", 8)'),
            source.index('emit_progress(progress, "Checking event logs", 12)'),
        )
        self.assertNotIn('note_stage_skipped(config, progress, "Safe account identifier context"', source)

    def test_verify_pin_returns_scan_profile(self):
        original = checker.post_json
        try:
            checker.post_json = lambda *args, **kwargs: (True, {
                "ok": True,
                "pinId": "abc",
                "scanProfile": "deep",
            })
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
            "usnJournalEvents": [
                {"timestamp": "2026-06-09T00:00:00", "eventType": "Modified", "fileName": f"file-{index}.tmp", "reason": "DATA_OVERWRITE", "usn": str(index)}
                for index in range(5000)
            ],
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
        self.assertLessEqual(len(compacted["usnJournalEvents"]), 100)
        self.assertTrue(compacted["robloxLogs"][0]["rawLogOmittedForUpload"])
        self.assertEqual(compacted["robloxLogs"][0]["rawLog"], "")
        self.assertIn("full report remains saved locally", " ".join(compacted["limitations"]))
        encoded = json.dumps(compacted, separators=(",", ":"), default=str).encode("utf-8", errors="replace")
        self.assertLess(len(encoded), 900_000)


if __name__ == "__main__":
    unittest.main()
