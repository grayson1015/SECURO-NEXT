import { NextResponse } from "next/server";
import { verifyKeySession } from "@/lib/key-session";

export async function GET() {
  const session = await verifyKeySession();
  if (!session.ok) return NextResponse.json({ ok: false, error: "invalid_email_or_key" }, { status: 401 });
  return NextResponse.json({ ok: true, email: session.email });
}
