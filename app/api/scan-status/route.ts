import { NextRequest, NextResponse } from "next/server";
import { createRouteSupabase } from "@/lib/supabase";

const allowedStatuses = new Set(["queued", "scanning", "completed", "failed", "timeout"]);

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const pin = String(body?.pin || "");
  const status = String(body?.status || "");
  const diagnostics = body?.diagnostics && typeof body.diagnostics === "object" ? body.diagnostics : {};

  if (!/^\d{6}$/.test(pin)) {
    return NextResponse.json({ ok: false, error: "invalid_or_expired_pin" }, { status: 400 });
  }

  if (!allowedStatuses.has(status)) {
    return NextResponse.json({ ok: false, error: "invalid_status" }, { status: 400 });
  }

  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("update_pin_scan_status", {
    input_pin: pin,
    input_status: status,
    input_diagnostics: diagnostics
  });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const result = Array.isArray(data) ? data[0] : data;
  if (!result?.ok) return NextResponse.json({ ok: false, error: result?.error || "status_update_failed" }, { status: 400 });

  return NextResponse.json({ ok: true });
}
