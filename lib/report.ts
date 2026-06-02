import type { ReportRow, SecuroReportJson } from "@/lib/types";

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
    const className = finding.classification || finding.category || "";
    return className.toLowerCase() === label.toLowerCase();
  }).length;
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
