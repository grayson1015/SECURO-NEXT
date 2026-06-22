import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { compactReportRow } from "@/lib/report-compact";
import { createRouteSupabase } from "@/lib/supabase";
import type { ReportRow } from "@/lib/types";

export async function GET(req: NextRequest) {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const days = clampDays(Number(req.nextUrl.searchParams.get("days") || 7));
  const supabase = createRouteSupabase();
  const summary = await supabase.rpc("list_report_summaries_by_key", {
    input_email: session.email,
    input_key: session.key,
    input_days: days
  });

  if (!summary.error) return NextResponse.json({ ok: true, reports: summary.data || [] });

  const fallback = await supabase.rpc("list_reports_by_key", {
    input_email: session.email,
    input_key: session.key
  });

  if (fallback.error) return NextResponse.json({ ok: false, error: fallback.error.message }, { status: 500 });
  const reports = ((fallback.data || []) as ReportRow[])
    .map((report) => compactReportRow(report, days, false))
    .filter((report) => withinDays(report.scan_time || report.uploaded_at, days));
  return NextResponse.json({ ok: true, reports });
}

function clampDays(value: number) {
  if (!Number.isFinite(value)) return 7;
  return Math.max(3, Math.min(30, Math.round(value)));
}

function withinDays(value: string, days: number) {
  const time = new Date(value || "").getTime();
  if (!Number.isFinite(time)) return true;
  return time >= Date.now() - days * 24 * 60 * 60 * 1000;
}
