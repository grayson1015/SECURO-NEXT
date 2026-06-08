import { NextRequest, NextResponse } from "next/server";
import { createRouteSupabase } from "@/lib/supabase";

export async function POST(req: NextRequest) {
  const { pin } = await req.json().catch(() => ({ pin: "" }));
  if (!/^\d{6}$/.test(String(pin || ""))) {
    return NextResponse.json({ ok: false, error: "invalid_or_expired_pin" }, { status: 400 });
  }

  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("connect_pin", { input_pin: String(pin) });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const result = Array.isArray(data) ? data[0] : data;
  if (!result?.ok) return NextResponse.json({ ok: false, error: result?.error || "invalid_or_expired_pin" }, { status: 404 });

  return NextResponse.json({ ok: true, pinId: result.pin_id, scanProfile: result.scan_profile || "standard" });
}
