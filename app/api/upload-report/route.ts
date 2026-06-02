import { NextRequest, NextResponse } from "next/server";
import { createRouteSupabase } from "@/lib/supabase";
import { evidenceScore, riskFromScore, validateReportJson } from "@/lib/report";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const pin = String(body?.pin || "");
  const reportData = body?.reportData;

  if (!/^\d{6}$/.test(pin)) {
    return NextResponse.json({ ok: false, error: "invalid_or_expired_pin" }, { status: 400 });
  }

  if (!validateReportJson(reportData)) {
    return NextResponse.json({ ok: false, error: "invalid_report_schema" }, { status: 400 });
  }

  const score = Number(body?.evidenceScore ?? evidenceScore(reportData));
  const incomingRisk = String(body?.riskLevel || "");
  const riskLevel = ["High", "Medium", "Low"].includes(incomingRisk)
    ? incomingRisk
    : riskFromScore(score, reportData.highestResult);
  const hostname = String(body?.hostname || reportData.hostname || "Unknown");

  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("upload_report_by_pin", {
    input_pin: pin,
    input_hostname: hostname,
    input_risk_level: riskLevel,
    input_evidence_score: score,
    input_report_json: reportData
  });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const result = Array.isArray(data) ? data[0] : data;
  if (!result?.ok) return NextResponse.json({ ok: false, error: result?.error || "upload_failed" }, { status: 400 });

  return NextResponse.json({ ok: true });
}
