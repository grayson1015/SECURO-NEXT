"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { BriefcaseBusiness, Eye, Trash2, UserPlus } from "lucide-react";
import { LoginPanel } from "@/components/login-panel";
import { SecuroLogo } from "@/components/securo-logo";
import { SiteNav } from "@/components/site-nav";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { createBrowserSupabase } from "@/lib/supabase";
import type { AllowedUserRow, BusinessLicenseRow, BusinessLicenseUserRow } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export default function AdminPage() {
  const supabase = createBrowserSupabase();
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [owner, setOwner] = useState(false);
  const [users, setUsers] = useState<AllowedUserRow[]>([]);
  const [businessLicenses, setBusinessLicenses] = useState<BusinessLicenseRow[]>([]);
  const [businessUsers, setBusinessUsers] = useState<BusinessLicenseUserRow[]>([]);
  const [selectedBusinessKey, setSelectedBusinessKey] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<AllowedUserRow["role"]>("moderator");
  const [message, setMessage] = useState("");

  useEffect(() => {
    load();
  }, []);

  async function token() {
    const { data } = await supabase.auth.getSession();
    return data.session?.access_token || "";
  }

  async function load() {
    const { data } = await supabase.auth.getSession();
    if (!data.session) {
      setAuthenticated(false);
      setLoading(false);
      return;
    }
    setAuthenticated(true);
    const accessToken = data.session.access_token;
    const res = await fetch("/api/admin/allowed-users", { headers: { Authorization: `Bearer ${accessToken}` } });
    const body = await res.json();
    if (body.ok) {
      setOwner(true);
      setUsers(body.users || []);
      await loadBusinessLicenses(accessToken);
    } else {
      setOwner(false);
      setMessage(body.error === "owner_required" ? "Only Securo owners can access this page." : body.error || "Access denied.");
    }
    setLoading(false);
  }

  async function loadBusinessLicenses(accessToken?: string) {
    const activeToken = accessToken || (await token());
    const res = await fetch("/api/admin/business-licenses", { headers: { Authorization: `Bearer ${activeToken}` } });
    const body = await res.json();
    if (body.ok) {
      setBusinessLicenses(body.licenses || []);
    }
  }

  async function loadBusinessUsers(key: string) {
    setSelectedBusinessKey(key);
    setMessage("Loading business license users...");
    const accessToken = await token();
    const res = await fetch(`/api/admin/business-license-users?key=${encodeURIComponent(key)}`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const body = await res.json();
    if (!body.ok) {
      setMessage(body.error || "Could not load business users.");
      return;
    }
    setBusinessUsers(body.users || []);
    setMessage("");
  }

  async function revokeBusinessUser(key: string, targetEmail: string) {
    setMessage(`Removing ${targetEmail} from business license...`);
    const accessToken = await token();
    const res = await fetch("/api/admin/business-license-users", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ key, email: targetEmail })
    });
    const body = await res.json();
    if (!body.ok) {
      setMessage(body.error || "Could not remove email slot.");
      return;
    }
    setMessage("Email slot removed.");
    await loadBusinessLicenses(accessToken);
    await loadBusinessUsers(key);
  }

  async function saveUser() {
    setMessage("Saving role user...");
    const accessToken = await token();
    const res = await fetch("/api/admin/allowed-users", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email, role })
    });
    const body = await res.json();
    if (!body.ok) {
      setMessage(body.error || "Could not save role user.");
      return;
    }
    setEmail("");
    setRole("moderator");
    setMessage("Role user saved.");
    await load();
  }

  if (loading) return <main className="flex min-h-screen items-center justify-center text-zinc-400">Loading admin...</main>;
  if (!authenticated) return <LoginPanel />;
  if (!owner) {
    return (
      <main className="min-h-screen">
        <SiteNav />
        <section className="mx-auto flex max-w-3xl flex-col items-center px-6 py-20 text-center">
          <Card>
            <SecuroLogo size={52} className="mx-auto" />
            <h1 className="mt-4 text-2xl font-bold">Only Securo owners can access this page.</h1>
            <p className="mt-3 text-sm text-zinc-400">{message || "Ask the first owner to approve your account."}</p>
            <Link className="mt-6 inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-sm font-semibold text-black" href="/dashboard">
              Back to dashboard
            </Link>
          </Card>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen">
      <SiteNav />
      <section className="mx-auto max-w-6xl px-6 py-10">
        <p className="text-sm font-semibold text-primary">Owner</p>
        <h1 className="mt-2 text-4xl font-bold">Securo owner roles</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-zinc-400">
          Manage owner/admin role records and business license seats here. Dashboard access is activated with standard one-email keys or business keys with up to 20 emails.
        </p>

        <Card className="mt-8">
          <CardTitle>Add or update role user</CardTitle>
          <div className="mt-4 grid gap-3 md:grid-cols-[1fr_180px_auto]">
            <Input placeholder="owner@example.com" value={email} onChange={(event) => setEmail(event.target.value)} />
            <select className="h-10 rounded-md border border-border bg-black/20 px-3 text-sm text-white outline-none" value={role} onChange={(event) => setRole(event.target.value as AllowedUserRow["role"])}>
              <option value="moderator">moderator</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
            </select>
            <Button onClick={saveUser}><UserPlus size={16} />Save</Button>
          </div>
          {message ? <p className="mt-3 text-sm text-zinc-400">{message}</p> : null}
        </Card>

        <Card className="mt-5">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <CardTitle>Business licenses</CardTitle>
              <p className="mt-2 text-sm text-zinc-400">Business keys can be shared by a team, but each unique email uses one slot.</p>
            </div>
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
              <BriefcaseBusiness size={14} />
              Business License
            </div>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr className="border-b border-border">
                  <th className="py-3">License key</th>
                  <th>Emails Used</th>
                  <th>Remaining</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {businessLicenses.map((license) => (
                  <tr key={license.key_code} className="border-b border-border/70">
                    <td className="py-3 font-mono text-xs text-primary">{license.key_code}</td>
                    <td className="font-semibold">{license.emails_used} / {license.max_emails}</td>
                    <td>{Math.max(license.max_emails - license.emails_used, 0)}</td>
                    <td>{formatDate(license.created_at)}</td>
                    <td>{license.expires_at ? formatDate(license.expires_at) : "Never"}</td>
                    <td className="text-right">
                      <Button onClick={() => loadBusinessUsers(license.key_code)} className="border border-border bg-zinc-900 text-white">
                        <Eye size={16} />View users
                      </Button>
                    </td>
                  </tr>
                ))}
                {!businessLicenses.length ? (
                  <tr>
                    <td className="py-4 text-zinc-500" colSpan={6}>No business licenses found.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>

        {selectedBusinessKey ? (
          <Card className="mt-5">
            <CardTitle>Active users for {selectedBusinessKey}</CardTitle>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-zinc-500">
                  <tr className="border-b border-border"><th className="py-3">Email</th><th>Activated</th><th>Last seen</th><th></th></tr>
                </thead>
                <tbody>
                  {businessUsers.map((user) => (
                    <tr key={`${user.license_key}-${user.email}`} className="border-b border-border/70">
                      <td className="py-3 font-medium">{user.email}</td>
                      <td>{formatDate(user.activated_at)}</td>
                      <td>{formatDate(user.last_seen_at)}</td>
                      <td className="text-right">
                        <Button onClick={() => revokeBusinessUser(user.license_key, user.email)} className="border border-border bg-zinc-900 text-white">
                          <Trash2 size={16} />Revoke slot
                        </Button>
                      </td>
                    </tr>
                  ))}
                  {!businessUsers.length ? (
                    <tr>
                      <td className="py-4 text-zinc-500" colSpan={4}>No emails have used this business license yet.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </Card>
        ) : null}

        <Card className="mt-5">
          <CardTitle>Role users</CardTitle>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr className="border-b border-border"><th className="py-3">Email</th><th>Role</th><th>Created</th></tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id} className="border-b border-border/70">
                    <td className="py-3 font-medium">{user.email}</td>
                    <td>{user.role}</td>
                    <td>{formatDate(user.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </section>
    </main>
  );
}
