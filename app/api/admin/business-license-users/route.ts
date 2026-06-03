import { NextRequest, NextResponse } from "next/server";
import { bearer, getAllowedUser } from "@/lib/authz";
import { createRouteSupabase } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  const token = bearer(req.headers.get("authorization"));
  if (!token) return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });

  const allowed = await getAllowedUser(token);
  if (!allowed.ok || allowed.allowed?.role !== "owner") {
    return NextResponse.json({ ok: false, error: "owner_required" }, { status: 403 });
  }

  const key = String(req.nextUrl.searchParams.get("key") || "").trim().toUpperCase();
  if (!/^SEC-MVP-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    return NextResponse.json({ ok: false, error: "invalid_license_key" }, { status: 400 });
  }

  const supabase = createRouteSupabase(token);
  const { data, error } = await supabase.rpc("list_business_license_users", {
    input_license_key: key
  });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true, users: data || [] });
}

export async function DELETE(req: NextRequest) {
  const token = bearer(req.headers.get("authorization"));
  if (!token) return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });

  const allowed = await getAllowedUser(token);
  if (!allowed.ok || allowed.allowed?.role !== "owner") {
    return NextResponse.json({ ok: false, error: "owner_required" }, { status: 403 });
  }

  const body = await req.json().catch(() => null);
  const key = String(body?.key || "").trim().toUpperCase();
  const email = String(body?.email || "").trim().toLowerCase();

  if (!/^SEC-MVP-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key) || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return NextResponse.json({ ok: false, error: "invalid_request" }, { status: 400 });
  }

  const supabase = createRouteSupabase(token);
  const { data, error } = await supabase.rpc("revoke_business_license_user", {
    input_license_key: key,
    input_email: email
  });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });

  const result = Array.isArray(data) ? data[0] : data;
  if (!result?.ok) return NextResponse.json({ ok: false, error: result?.error || "revoke_failed" }, { status: 400 });

  return NextResponse.json({ ok: true });
}
