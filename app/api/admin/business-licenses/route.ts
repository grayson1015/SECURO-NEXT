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

  const supabase = createRouteSupabase(token);
  const { data, error } = await supabase.rpc("list_business_licenses");
  if (error) return NextResponse.json({ ok: false, error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true, licenses: data || [] });
}
