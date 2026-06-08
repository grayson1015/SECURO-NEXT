import type { ReportRow, ReportSummaryRow, SecuroReportJson } from "@/lib/types";

export function validateReportJson(report: unknown): report is SecuroReportJson {
  if (!report || typeof report !== "object") return false;
  const value = report as Record<string, unknown>;
  return [
    "scanTime",
    "hostname",
    "highestResult",
    "confidence",
    "evidenceSources",
    "timeline",
    "sessions",
    "findings",
    "limitations"
  ].every((key) => key in value);
}

export function evidenceScore(report: SecuroReportJson, fallback = 0) {
  const scores = report.findings.map((finding) => Number(finding.score || 0));
  return Math.max(fallback, ...scores, Number((report as { topScore?: number }).topScore || 0));
}

export function riskFromScore(score: number, reported: string) {
  if (reported === "Confirmed" || score >= 70) return "High";
  if (reported === "Suspicious" || score >= 35) return "Medium";
  return "Low";
}

export function countFindings(report: SecuroReportJson, label: string) {
  return report.findings.filter((finding) => {
    if (isSecuroSuppressedFinding(finding)) return false;
    const className = finding.classification || finding.category || "";
    const requested = label.toLowerCase();
    const confidence = findingConfidence(finding).toLowerCase();
    if (requested === "confirmed" || requested === "likely" || requested === "possible") {
      return confidence === requested;
    }
    if ((requested === "confirmed exploit" || requested === "confirmed") && isMainstreamOrRuntimeFinding(finding)) {
      return false;
    }
    if (requested === "suspicious" && isMainstreamOrRuntimeFinding(finding) && className.toLowerCase() === "confirmed exploit") {
      return true;
    }
    return className.toLowerCase() === label.toLowerCase();
  }).length;
}

function findingConfidence(finding: { name?: string; path?: string; confidenceLevel?: string; classification?: string; score?: number }) {
  if (isMainstreamOrRuntimeFinding(finding) && (finding.confidenceLevel === "Confirmed" || finding.classification === "Confirmed Exploit")) {
    return Number(finding.score || 0) >= 50 ? "Likely" : "Possible";
  }
  if (finding.confidenceLevel === "Confirmed" || finding.classification === "Confirmed Exploit") return "Confirmed";
  if (finding.confidenceLevel === "Likely" || finding.classification === "Suspicious" || Number(finding.score || 0) >= 50) return "Likely";
  return "Possible";
}

function isSecuroSuppressedFinding(finding: { name?: string; path?: string }) {
  const text = `${finding.name || ""} ${finding.path || ""}`.toLowerCase();
  return text.includes("\\securo") || text.includes("/securo") || text.includes("_internal");
}

function isMainstreamOrRuntimeFinding(finding: { name?: string; path?: string }) {
  const text = `${finding.name || ""} ${finding.path || ""}`.toLowerCase();
  const runtime = ["sqlite3.dll", "libcrypto", "libssl", "python312.dll", "python3.dll", "libffi", "vcruntime", "msvcp140.dll", "api-ms-win", "webview2loader.dll", "base_library.zip"];
  const mainstream = ["spotify", "chrome", "discord", "steam", "roblox", "microsoft", "nvidia", "amd", "edge", "razer", "logitech", "corsair", "steelseries", "mozilla", "firefox", "intel"];
  const protectedSystem = ["svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe", "dwm.exe", "taskhostw.exe", "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe"];
  const trustedLocation = text.includes("c:\\windows\\") || text.includes("c:\\program files\\") || text.includes("c:\\program files (x86)\\");
  return trustedLocation || runtime.some((name) => text.includes(name)) || mainstream.some((name) => text.includes(name)) || protectedSystem.some((name) => text.includes(name));
}

export function filterReports(reports: ReportRow[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return reports;
  return reports.filter((report) => {
    const text = [
      report.hostname,
      report.risk_level,
      report.evidence_score,
      report.report_json.highestResult,
      report.report_json.confidence,
      ...report.report_json.sessions.flatMap((session) => [
        session.username,
        session.displayName,
        session.userId,
        session.placeId,
        session.gameId,
        session.jobId
      ])
    ].join(" ").toLowerCase();
    return text.includes(needle);
  });
}

export function filterReportSummaries(reports: ReportSummaryRow[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return reports;
  return reports.filter((report) => {
    const text = [
      report.hostname,
      report.risk_level,
      report.evidence_score,
      report.username,
      report.display_name,
      report.user_id,
      report.place_id,
      report.game_id,
      report.job_id,
      report.duration,
      report.session_status
    ].join(" ").toLowerCase();
    return text.includes(needle);
  });
}

export function countDetectionCategory(report: SecuroReportJson, terms: string[]) {
  const needles = terms.map((term) => term.toLowerCase());
  return report.findings.filter((finding) => {
    const haystack = [
      ...(finding.detectionCategories || []),
      ...(finding.detections || []).map((d) => d.category || ""),
      ...(finding.evidenceTypes || [])
    ].join(" ").toLowerCase();
    return needles.some((needle) => haystack.includes(needle));
  }).length;
}

export function primarySession(report: SecuroReportJson) {
  return report.sessions[0] || {};
}
