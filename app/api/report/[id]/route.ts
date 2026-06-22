import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { compactReportRow } from "@/lib/report-compact";
import { createRouteSupabase } from "@/lib/supabase";
import type { ReportRow } from "@/lib/types";

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("get_report_by_key", {
    input_email: session.email,
    input_key: session.key,
    input_report_id: params.id
  });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 404 });
  const report = Array.isArray(data) ? data[0] : data;
  if (!report) return NextResponse.json({ ok: false, error: "not_found" }, { status: 404 });

  const days = Number(req.nextUrl.searchParams.get("days") || 7);
  const compacted = compactReportRow(report as ReportRow, Number.isFinite(days) ? days : 7, false);
  return NextResponse.json({ ok: true, report: compacted });
}
