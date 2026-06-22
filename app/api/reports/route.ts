import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { createRouteSupabase } from "@/lib/supabase";

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
  return NextResponse.json({
    ok: false,
    error: "Report summaries are not installed in Supabase yet. Run the latest supabase/schema.sql function list_report_summaries_by_key."
  }, { status: 500 });
}

function clampDays(value: number) {
  if (!Number.isFinite(value)) return 7;
  return Math.max(3, Math.min(30, Math.round(value)));
}
