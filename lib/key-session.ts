import { cookies } from "next/headers";
import { createRouteSupabase } from "@/lib/supabase";

const emailCookie = "securo_email";
const keyCookie = "securo_key";

export function getKeySession() {
  const store = cookies();
  const email = store.get(emailCookie)?.value || "";
  const key = store.get(keyCookie)?.value || "";
  return { email, key };
}

export function setKeySession(email: string, key: string) {
  const secure = process.env.NODE_ENV === "production";
  cookies().set(emailCookie, email.toLowerCase(), {
    httpOnly: true,
    sameSite: "lax",
    secure,
    path: "/",
    maxAge: 60 * 60 * 24 * 30
  });
  cookies().set(keyCookie, key.toUpperCase(), {
    httpOnly: true,
    sameSite: "lax",
    secure,
    path: "/",
    maxAge: 60 * 60 * 24 * 30
  });
}

export function clearKeySession() {
  cookies().delete(emailCookie);
  cookies().delete(keyCookie);
}

export async function verifyKeySession() {
  const session = getKeySession();
  if (!session.email || !session.key) {
    return { ok: false as const, email: "", key: "", error: "invalid_email_or_key" };
  }
  const supabase = createRouteSupabase();
  const { data, error } = await supabase.rpc("validate_key_session", {
    input_email: session.email,
    input_key: session.key
  });
  if (error || !data) {
    return { ok: false as const, email: session.email, key: session.key, error: "invalid_email_or_key" };
  }
  return { ok: true as const, email: session.email, key: session.key, error: null };
}
