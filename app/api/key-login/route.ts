import { NextRequest, NextResponse } from "next/server";
import { createRouteSupabase } from "@/lib/supabase";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);

  const email = String(body?.email || "").trim().toLowerCase();
  const key = String(body?.key || "").trim().toUpperCase();

  if (
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
    !/^SECURO-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)
  ) {
    return NextResponse.json(
      { ok: false, error: "invalid_email_or_key" },
      { status: 400 }
    );
  }

  const supabase = createRouteSupabase();

  const { data, error } = await supabase.rpc("key_login", {
    input_email: email,
    input_key: key,
  });

  if (error) {
    console.error("key_login error:", error);
    return NextResponse.json(
      { ok: false, error: "invalid_email_or_key" },
      { status: 400 }
    );
  }

  const result = Array.isArray(data) ? data[0] : data;

  if (!result?.ok) {
    return NextResponse.json(
      { ok: false, error: result?.error || "invalid_email_or_key" },
      { status: 400 }
    );
  }

  const response = NextResponse.json({ ok: true });

  response.cookies.set("securo_email", email, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  });

  response.cookies.set("securo_key", key, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  });

  return response;
}