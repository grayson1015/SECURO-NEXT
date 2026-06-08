import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { createRouteSupabase } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const supabase = createRouteSupabase();
  const summaryOnly = req.nextUrl.searchParams.get("summary") === "1";
  const limit = Math.min(Math.max(Number(req.nextUrl.searchParams.get("limit") || 500), 1), 1000);
  if (summaryOnly) {
    const summaryResult = await supabase.rpc("list_report_summaries_by_key", {
      input_email: session.email,
      input_key: session.key,
      input_limit: limit
    });

    if (!summaryResult.error) {
      return NextResponse.json({ ok: true, reports: summaryResult.data });
    }
  }

  const { data, error } = await supabase.rpc("list_reports_by_key", {
    input_email: session.email,
    input_key: session.key
  });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const reports = summaryOnly ? (data || []).slice(0, limit).map(toReportSummary) : data;
  return NextResponse.json({ ok: true, reports });
}

function toReportSummary(report: Record<string, any>) {
  const json = report.report_json || {};
  const sessions = Array.isArray(json.sessions) ? json.sessions : [];
  const findings = Array.isArray(json.findings) ? json.findings : [];
  const session = sessions[0] || {};
  return {
    id: report.id,
    pin_id: report.pin_id,
    owner_user_id: report.owner_user_id,
    owner_email: report.owner_email,
    uploaded_at: report.uploaded_at,
    hostname: report.hostname,
    scan_time: report.scan_time,
    risk_level: report.risk_level,
    evidence_score: report.evidence_score,
    username: session.username || null,
    display_name: session.displayName || null,
    user_id: session.userId || null,
    place_id: session.placeId || null,
    game_id: session.gameId || null,
    job_id: session.jobId || null,
    duration: session.duration || null,
    session_status: session.status || null,
    sessions_count: sessions.length,
    findings_count: findings.length,
    confirmed_count: findings.filter((finding: Record<string, unknown>) => finding.confidenceLevel === "Confirmed" || finding.classification === "Confirmed Exploit").length,
    likely_count: findings.filter((finding: Record<string, unknown>) => finding.confidenceLevel === "Likely" || finding.classification === "Suspicious").length,
    possible_count: findings.filter((finding: Record<string, unknown>) => !["Confirmed", "Likely"].includes(String(finding.confidenceLevel || "")) && finding.classification !== "Confirmed Exploit").length,
    packed_count: countFindingText(findings, ["packed", "upx", "vmprotect", "themida"]),
    dotnet_count: countFindingText(findings, ["dotnet", "suspicious net file"]),
    autoit_count: countFindingText(findings, ["autoit", "autohotkey"]),
    tampered_count: countFindingText(findings, ["tampered file"]),
    evidence_coverage: evidenceCoverage(json.evidenceSources || {})
  };
}

function countFindingText(findings: Record<string, unknown>[], terms: string[]) {
  return findings.filter((finding) => {
    const text = JSON.stringify(finding).toLowerCase();
    return terms.some((term) => text.includes(term));
  }).length;
}

function evidenceCoverage(sources: Record<string, unknown>) {
  const values = Object.values(sources);
  if (!values.length) return 0;
  return Math.round((values.filter(Boolean).length / values.length) * 100);
}
