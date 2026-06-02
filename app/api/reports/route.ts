import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { createRouteSupabase } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("list_reports_by_key", {
    input_email: session.email,
    input_key: session.key
  });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true, reports: data });
}
