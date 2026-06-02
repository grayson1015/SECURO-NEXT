import { NextRequest, NextResponse } from "next/server";
import { bearer, getAllowedUser } from "@/lib/authz";
import { createRouteSupabase } from "@/lib/supabase";

const roles = new Set(["owner", "admin", "moderator"]);

export async function GET(req: NextRequest) {
  const token = bearer(req.headers.get("authorization"));
  if (!token) return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });

  const allowed = await getAllowedUser(token);
  if (!allowed.ok || allowed.allowed?.role !== "owner") {
    return NextResponse.json({ ok: false, error: "owner_required" }, { status: 403 });
  }

  const supabase = createRouteSupabase(token);
  const { data, error } = await supabase.rpc("list_allowed_users");
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true, users: data || [] });
}

export async function POST(req: NextRequest) {
  const token = bearer(req.headers.get("authorization"));
  if (!token) return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });

  const allowed = await getAllowedUser(token);
  if (!allowed.ok || allowed.allowed?.role !== "owner") {
    return NextResponse.json({ ok: false, error: "owner_required" }, { status: 403 });
  }

  const body = await req.json().catch(() => null);
  const email = String(body?.email || "").trim().toLowerCase();
  const role = String(body?.role || "moderator");
  if (!email || !roles.has(role)) {
    return NextResponse.json({ ok: false, error: "invalid_request" }, { status: 400 });
  }

  const supabase = createRouteSupabase(token);
  const { data, error } = await supabase.rpc("upsert_allowed_user", {
    input_email: email,
    input_role: role
  });
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });
  const result = Array.isArray(data) ? data[0] : data;
  if (!result?.ok) return NextResponse.json({ ok: false, error: result?.error || "update_failed" }, { status: 400 });
  return NextResponse.json({ ok: true });
}
