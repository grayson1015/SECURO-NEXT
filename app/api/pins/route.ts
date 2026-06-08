import { NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { createRouteSupabase } from "@/lib/supabase";

export async function GET() {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("list_pins_by_key", {
    input_email: session.email,
    input_key: session.key
  });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const pins = (data || []).map((pin: Record<string, unknown>) => ({
    ...pin,
    pin_code: pin.pin_code || pin.pin || pin.pinCode || "",
    status: pin.status || "queued",
    scan_profile: pin.scan_profile || "standard"
  }));
  return NextResponse.json({ ok: true, pins });
}
