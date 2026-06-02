import { NextRequest, NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";
import { createRouteSupabase } from "@/lib/supabase";
import { randomPin } from "@/lib/utils";

export async function POST(req: NextRequest) {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });

  const supabase = createRouteSupabase();
  const pin = randomPin();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  const { data, error } = await supabase.rpc("create_pin_by_key", {
    input_email: session.email,
    input_key: session.key,
    input_pin: pin,
    input_expires_at: expiresAt
  });

  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const result = Array.isArray(data) ? data[0] : data;
  if (!result) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });
  return NextResponse.json({
    ok: true,
    pin: {
      ...result,
      pin_code: result.pin_code || pin,
      status: result.status || "pending",
      expires_at: result.expires_at || expiresAt
    }
  });
}
