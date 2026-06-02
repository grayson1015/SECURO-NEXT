import { NextResponse } from "next/server";
import { clearKeySession } from "@/lib/key-session";

export async function POST() {
  clearKeySession();
  return NextResponse.json({ ok: true });
}
