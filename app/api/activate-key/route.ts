import { NextRequest, NextResponse } from "next/server";
import { bearer } from "@/lib/authz";
import { createRouteSupabase } from "@/lib/supabase";

export async function POST(req: NextRequest) {
  const token = bearer(req.headers.get("authorization"));
  if (!token) return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => null);
  const key = String(body?.key || "").trim().toUpperCase();
  if (!/^SECURO-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    return NextResponse.json({ ok: false, error: "invalid_or_used_key" }, { status: 400 });
  }

  const supabase = createRouteSupabase(token);
  const { data, error } = await supabase.rpc("activate_access_key", { input_key: key });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });

  const result = Array.isArray(data) ? data[0] : data;
  if (!result?.ok) {
    return NextResponse.json({ ok: false, error: result?.error || "invalid_or_used_key" }, { status: 400 });
  }

  return NextResponse.json({ ok: true });
}
