import { createRouteSupabase } from "@/lib/supabase";

export async function getAllowedUser(accessToken: string) {
  const supabase = createRouteSupabase(accessToken);
  const { data: userData, error: userError } = await supabase.auth.getUser(accessToken);
  if (userError || !userData.user?.email) {
    return { ok: false as const, user: null, allowed: null, error: "unauthorized" };
  }

  const { data: allowed, error: allowedError } = await supabase
    .from("allowed_users")
    .select("email,role")
    .ilike("email", userData.user.email)
    .maybeSingle();

  if (allowedError) {
    return { ok: false as const, user: userData.user, allowed: null, error: allowedError.message };
  }
  if (!allowed) {
    return { ok: false as const, user: userData.user, allowed: null, error: "not_approved" };
  }
  return { ok: true as const, user: userData.user, allowed, error: null };
}

export async function getActivatedUser(accessToken: string) {
  const supabase = createRouteSupabase(accessToken);
  const { data: userData, error: userError } = await supabase.auth.getUser(accessToken);
  if (userError || !userData.user?.email) {
    return { ok: false as const, user: null, access: null, error: "unauthorized" };
  }

  const { data: access, error: accessError } = await supabase
    .from("access_keys")
    .select("id,key_code,assigned_email,assigned_user_id,used_at,created_at")
    .or(`assigned_user_id.eq.${userData.user.id},assigned_email.ilike.${userData.user.email}`)
    .not("used_at", "is", null)
    .maybeSingle();

  if (accessError) {
    return { ok: false as const, user: userData.user, access: null, error: accessError.message };
  }
  if (!access) {
    return { ok: false as const, user: userData.user, access: null, error: "activation_required" };
  }
  return { ok: true as const, user: userData.user, access, error: null };
}

export function bearer(authHeader: string | null) {
  const auth = authHeader || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : "";
}
