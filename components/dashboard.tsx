"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Activity, Download, LogOut, Monitor, Plus, Search, ShieldAlert, ShieldCheck, Timer } from "lucide-react";
import type { PinRow, ReportRow } from "@/lib/types";
import { countDetectionCategory, countFindings, filterReports, primarySession } from "@/lib/report";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, CardValue } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

type TimeRange = "30d" | "14d" | "7d" | "3d";
const timeRanges: { label: string; value: TimeRange; days: number }[] = [
  { label: "1 month", value: "30d", days: 30 },
  { label: "2 weeks", value: "14d", days: 14 },
  { label: "1 week", value: "7d", days: 7 },
  { label: "3 days", value: "3d", days: 3 }
];

export function Dashboard({ initialReports, initialPins }: { initialReports: ReportRow[]; initialPins: PinRow[] }) {
  const [reports, setReports] = useState(initialReports);
  const [pins, setPins] = useState(initialPins);
  const [query, setQuery] = useState("");
  const [timeRange, setTimeRange] = useState<TimeRange>("7d");
  const [sortKey, setSortKey] = useState<"username" | "userId" | "placeId" | "risk" | "scanTime">("scanTime");
  const [createdPin, setCreatedPin] = useState<PinRow | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const timer = window.setInterval(async () => {
      const res = await fetch("/api/reports");
      const body = await res.json().catch(() => null);
      if (body?.ok) setReports(body.reports || []);
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const rangedReports = useMemo(() => filterReportsByTimeRange(reports, timeRange), [reports, timeRange]);
  const filtered = useMemo(() => sortReports(filterReports(rangedReports, query), sortKey), [rangedReports, query, sortKey]);
  const latest = rangedReports[0];
  const confirmed = latest ? countFindings(latest.report_json, "Confirmed") : 0;
  const likely = latest ? countFindings(latest.report_json, "Likely") : 0;
  const possible = latest ? countFindings(latest.report_json, "Possible") : 0;
  const sessions = latest?.report_json.sessions.length || 0;
  const coverage = latest ? coveragePercent(latest.report_json.evidenceSources) : 0;
  const packed = latest ? countDetectionCategory(latest.report_json, ["packed", "UPX", "VMProtect", "Themida"]) : 0;
  const dotnet = latest ? countDetectionCategory(latest.report_json, ["dotnet", "DotNet", "Suspicious Net File"]) : 0;
  const autoit = latest ? countDetectionCategory(latest.report_json, ["AutoIT", "AutoHotkey", "autohotkey"]) : 0;
  const tampered = latest ? countDetectionCategory(latest.report_json, ["Tampered File"]) : 0;

  async function createPin() {
    setBusy(true);
    const res = await fetch("/api/create-pin", { method: "POST" });
    const body = await res.json();
    setBusy(false);
    if (body.ok) {
      const nextPin = normalizePin(body.pin);
      setCreatedPin(nextPin);
      setPins((current) => [nextPin, ...current.filter((pin) => pin.id !== nextPin.id)]);
    } else {
      alert(body.error || "Could not create PIN");
    }
  }

  async function signOut() {
    await fetch("/api/key-logout", { method: "POST" });
    window.location.href = "/";
  }

  return (
    <main className="min-h-screen px-6 py-6">
      <div className="mx-auto max-w-7xl">
        <header className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-md bg-primary/15 p-2 text-primary"><ShieldCheck /></div>
            <div>
              <h1 className="text-2xl font-bold">Securo Dashboard</h1>
              <p className="text-sm text-zinc-400">Roblox PC checks, PIN sessions, and evidence review</p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button onClick={createPin} disabled={busy}><Plus size={16} />Create New PIN</Button>
            <Button onClick={signOut} className="bg-zinc-800 text-white"><LogOut size={16} />Sign out</Button>
          </div>
        </header>

        {createdPin ? (
          <Card className="mb-5 border-primary/40 bg-primary/10">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <CardTitle>Active PIN</CardTitle>
                <div className="mt-2 text-5xl font-bold tracking-[.2em] text-primary">{displayPin(createdPin)}</div>
                <p className="mt-2 text-sm text-zinc-300">Give this PIN to the user being checked. Expires {formatDate(createdPin.expires_at)}.</p>
              </div>
              <Badge label={createdPin.status} />
            </div>
          </Card>
        ) : null}

        <section className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
          <Stat icon={<Timer />} title="Scan Time" value={latest ? formatDate(latest.scan_time) : "No reports"} />
          <Stat icon={<Monitor />} title="Hostname" value={latest?.hostname || "Waiting"} />
          <Stat icon={<Activity />} title="Sessions" value={String(sessions)} />
          <Stat icon={<ShieldAlert />} title="Confirmed Findings" value={String(confirmed)} />
          <Stat icon={<ShieldAlert />} title="Likely Findings" value={String(likely)} />
          <Stat icon={<ShieldAlert />} title="Possible Findings" value={String(possible)} />
        </section>
        <section className="mt-4 grid gap-4 md:grid-cols-4">
          <Stat icon={<ShieldAlert />} title="Packed Files" value={String(packed)} />
          <Stat icon={<ShieldAlert />} title=".NET Detections" value={String(dotnet)} />
          <Stat icon={<ShieldAlert />} title="AutoIT/AHK" value={String(autoit)} />
          <Stat icon={<ShieldAlert />} title="Tampered Files" value={String(tampered)} />
        </section>

        <section className="mt-5 grid gap-4 lg:grid-cols-[1fr_360px]">
          <Card>
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold">Reports</h2>
                <p className="text-sm text-zinc-400">Realtime updates appear as soon as Securo uploads.</p>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-3">
                <div className="flex rounded-md border border-border bg-black/20 p-1">
                  {timeRanges.map((range) => (
                    <button
                      key={range.value}
                      className={`rounded px-3 py-1.5 text-xs font-semibold ${timeRange === range.value ? "bg-primary text-black" : "text-zinc-400 hover:text-white"}`}
                      type="button"
                      onClick={() => setTimeRange(range.value)}
                    >
                      {range.label}
                    </button>
                  ))}
                </div>
                <div className="relative w-72 max-w-full">
                  <Search className="absolute left-3 top-2.5 text-zinc-500" size={16} />
                  <Input className="pl-9" placeholder="Search reports" value={query} onChange={(event) => setQuery(event.target.value)} />
                </div>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-zinc-500">
                  <tr className="border-b border-border">
                    <SortTh label="Username" active={sortKey === "username"} onClick={() => setSortKey("username")} />
                    <SortTh label="User ID" active={sortKey === "userId"} onClick={() => setSortKey("userId")} />
                    <SortTh label="Place ID" active={sortKey === "placeId"} onClick={() => setSortKey("placeId")} />
                    <th>Duration</th>
                    <th>Status</th>
                    <th>Host</th>
                    <SortTh label="Risk" active={sortKey === "risk"} onClick={() => setSortKey("risk")} />
                    <th>Score</th>
                    <SortTh label="Scan Time" active={sortKey === "scanTime"} onClick={() => setSortKey("scanTime")} />
                    <th>Findings</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((report) => (
                    <tr key={report.id} className="border-b border-border/70">
                      {(() => {
                        const session = primarySession(report.report_json);
                        return (
                          <>
                            <td className="py-3 font-medium">{session.username || "Unknown"}</td>
                            <td>{session.userId || ""}</td>
                            <td>{session.placeId || session.gameId || ""}</td>
                            <td>{session.duration || "unknown"}</td>
                            <td>{session.status || "Clean"}</td>
                          </>
                        );
                      })()}
                      <td className="py-3 font-medium">{report.hostname}</td>
                      <td><Badge label={report.risk_level} /></td>
                      <td>{report.evidence_score}</td>
                      <td>{formatDate(report.scan_time)}</td>
                      <td>{report.report_json.findings.length}</td>
                      <td className="text-right"><Link className="text-primary hover:underline" href={`/reports/${report.id}`}>Open</Link></td>
                    </tr>
                  ))}
                  {!filtered.length ? (
                    <tr><td className="py-6 text-zinc-500" colSpan={11}>No reports found.</td></tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </Card>

          <aside className="space-y-4">
            <Card>
              <CardTitle>Risk Section</CardTitle>
              <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                <Risk label="High" value={rangedReports.filter((r) => r.risk_level === "High").length} />
                <Risk label="Medium" value={rangedReports.filter((r) => r.risk_level === "Medium").length} />
                <Risk label="Low" value={rangedReports.filter((r) => r.risk_level === "Low").length} />
              </div>
            </Card>
            <Card>
              <CardTitle>Evidence Coverage Gauge</CardTitle>
              <div className="mt-4 h-3 rounded-full bg-zinc-800">
                <div className="h-3 rounded-full bg-primary" style={{ width: `${coverage}%` }} />
              </div>
              <p className="mt-2 text-sm text-zinc-400">{coverage}% of available evidence sources present in latest report.</p>
            </Card>
            <Card>
              <CardTitle>Recent PIN Sessions</CardTitle>
              <div className="mt-3 space-y-3">
                {pins.slice(0, 6).map((pin) => (
                  <div key={pin.id} className="flex items-center justify-between rounded-md bg-black/20 p-3">
                    <div>
                      <div className="font-semibold tracking-widest">{displayPin(pin)}</div>
                      <div className="text-xs text-zinc-500">{formatDate(pin.created_at)}</div>
                    </div>
                    <Badge label={pin.status} />
                  </div>
                ))}
              </div>
            </Card>
          </aside>
        </section>
      </div>
    </main>
  );
}

function filterReportsByTimeRange(reports: ReportRow[], range: TimeRange) {
  const selected = timeRanges.find((item) => item.value === range) || timeRanges[2];
  const cutoff = Date.now() - selected.days * 24 * 60 * 60 * 1000;
  return reports.filter((report) => {
    const value = new Date(report.scan_time || report.uploaded_at || "").getTime();
    return Number.isFinite(value) && value >= cutoff;
  });
}

function Stat({ icon, title, value }: { icon: React.ReactNode; title: string; value: string }) {
  return (
    <Card>
      <div className="text-primary">{icon}</div>
      <CardTitle className="mt-3">{title}</CardTitle>
      <CardValue className="text-lg">{value}</CardValue>
    </Card>
  );
}

function SortTh({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <th className="cursor-pointer select-none py-3" onClick={onClick}>
      <span className={active ? "text-primary" : ""}>{label}</span>
    </th>
  );
}

function Risk({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-black/20 p-3">
      <Badge label={label} />
      <div className="mt-2 text-2xl font-bold">{value}</div>
    </div>
  );
}

function coveragePercent(sources: Record<string, unknown>) {
  const values = Object.values(sources);
  if (!values.length) return 0;
  return Math.round((values.filter(Boolean).length / values.length) * 100);
}

function displayPin(pin: Partial<PinRow> & Record<string, unknown>) {
  return String(pin.pin_code || pin.pin || pin.pinCode || "Unknown");
}

function normalizePin(pin: Partial<PinRow> & Record<string, unknown>): PinRow {
  return {
    id: String(pin.id || crypto.randomUUID()),
    pin_code: displayPin(pin),
    owner_user_id: (pin.owner_user_id as string | null) || null,
    owner_email: (pin.owner_email as string | null) || null,
    status: ((pin.status || "queued") as PinRow["status"]),
    created_at: String(pin.created_at || new Date().toISOString()),
    expires_at: String(pin.expires_at || new Date(Date.now() + 15 * 60 * 1000).toISOString())
  };
}

function sortReports(reports: ReportRow[], key: "username" | "userId" | "placeId" | "risk" | "scanTime") {
  return [...reports].sort((a, b) => {
    if (key === "scanTime") return new Date(b.scan_time).getTime() - new Date(a.scan_time).getTime();
    if (key === "risk") return String(a.risk_level).localeCompare(String(b.risk_level));
    const aSession = primarySession(a.report_json);
    const bSession = primarySession(b.report_json);
    const pick = (reportSession: typeof aSession) => {
      if (key === "username") return reportSession.username || "";
      if (key === "userId") return reportSession.userId || "";
      return reportSession.placeId || reportSession.gameId || "";
    };
    return String(pick(aSession)).localeCompare(String(pick(bSession)));
  });
}
