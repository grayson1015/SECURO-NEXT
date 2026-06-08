import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { createRouteSupabase } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const supabase = createRouteSupabase();
  const summaryOnly = req.nextUrl.searchParams.get("summary") === "1";
  const limit = Math.min(Math.max(Number(req.nextUrl.searchParams.get("limit") || 100), 1), 250);
  const { data, error } = summaryOnly
    ? await supabase.rpc("list_report_summaries_by_key", {
        input_email: session.email,
        input_key: session.key,
        input_limit: limit
      })
    : await supabase.rpc("list_reports_by_key", {
        input_email: session.email,
        input_key: session.key
      });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true, reports: data });
}
