"use client";

import { useMemo } from "react";
import Link from "next/link";
import { ArrowLeft, Download } from "lucide-react";
import type { AccountIdentifier, ReportRow, RobloxLogArtifact, SecuroFinding, SecuroSession } from "@/lib/types";
import { countFindings } from "@/lib/report";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, CardValue } from "@/components/ui/card";
import { AnimatedBackground, Reveal, Stagger, StaggerItem } from "@/components/motion-shell";

export function ReportDetail({ report }: { report: ReportRow }) {
  const currentReport = report;
  const data = currentReport.report_json;
  const primary = data.sessions[0] || {};
  const visibleFindings = useMemo(() => data.findings.filter((finding) => !isSecuroSuppressedFinding(finding)), [data.findings]);
  const detectionFindings = useMemo(
    () => visibleFindings.filter((finding) => (finding.detections || []).length || (finding.detectionCategories || []).length),
    [visibleFindings]
  );
  const extraEvidence = useMemo(() => reportEvidenceGroups(data), [data]);
  const filteredTimeline = data.timeline;
  const filteredFindings = visibleFindings;
  const groupedFindings = useMemo(() => ({
    Confirmed: filteredFindings.filter((finding) => findingConfidence(finding) === "Confirmed"),
    Likely: filteredFindings.filter((finding) => findingConfidence(finding) === "Likely"),
    Possible: filteredFindings.filter((finding) => findingConfidence(finding) === "Possible")
  }), [filteredFindings]);
  const filteredDetections = detectionFindings;
  const filteredRobloxLogs = data.robloxLogs || [];
  const filteredFastFlags = data.detectedFastFlags || [];
  const filteredShellBags = data.shellBagArtifacts || [];
  const accountContext = data.accountIdentifiers || {};
  const accountRows = accountContext.roblox || [];
  const discordRows = accountContext.discord || [];
  const accountGroups = useMemo(
    () => groupRobloxAccounts(accountRows, data.sessions || [], filteredRobloxLogs),
    [accountRows, data.sessions, filteredRobloxLogs]
  );
  const installHistory = data.windowsInstallHistory || [];
  const sysMain = data.sysMainService || {};
  const defenderExclusions = data.defenderExclusions || [];
  const reviewDefenderExclusions = defenderExclusions.filter((item) => item.manualReviewRequired);
  const resetHistory = useMemo(
    () => [...(data.systemResetEvidence || [])].sort((a, b) => {
      const priority = (item: { type?: string }) => {
        if (item.type === "Possible Windows Reset/Reinstall") return 0;
        if (item.type === "Reset/Install Artifact") return 1;
        return 2;
      };
      const priorityDifference = priority(a) - priority(b);
      if (priorityDifference) return priorityDifference;
      const left = parseTimestamp(a.timestamp)?.getTime() || 0;
      const right = parseTimestamp(b.timestamp)?.getTime() || 0;
      return right - left;
    }),
    [data.systemResetEvidence]
  );
  const filteredEvidence = extraEvidence;

  function exportHtml() {
    const html = buildExportHtml(currentReport);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `securo-report-${currentReport.hostname}-${currentReport.id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="min-h-screen px-6 py-6">
      <AnimatedBackground variant="report" />
      <div className="relative z-10 mx-auto max-w-6xl">
        <Reveal className="mb-5 flex flex-wrap items-center justify-between gap-4">
          <Link className="inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-primary" href="/dashboard">
            <ArrowLeft size={16} /> Dashboard
          </Link>
          <Button onClick={exportHtml}><Download size={16} />Export HTML</Button>
        </Reveal>

        <Stagger className="grid gap-4 md:grid-cols-4">
          <StaggerItem><Card><CardTitle>Scan timestamp</CardTitle><CardValue className="text-lg">{formatDate(data.scanTime)}</CardValue></Card></StaggerItem>
          <StaggerItem><Card><CardTitle>Hostname</CardTitle><CardValue>{currentReport.hostname}</CardValue></Card></StaggerItem>
          <StaggerItem><Card><CardTitle>Risk level</CardTitle><div className="mt-3"><Badge label={currentReport.risk_level} /></div></Card></StaggerItem>
          <StaggerItem><Card><CardTitle>Evidence score</CardTitle><CardValue>{currentReport.evidence_score}</CardValue></Card></StaggerItem>
        </Stagger>

        <Reveal delay={0.08}>
        <Card className="mt-5 border-primary/40 bg-primary/10">
          <h2 className="mb-3 text-lg font-semibold">Summary</h2>
          <div className="grid gap-3 md:grid-cols-5">
            <Summary label="User" value={primary.username || "Unknown"} />
            <Summary label="User ID" value={primary.userId || ""} />
            <Summary label="Place ID" value={primary.placeId || primary.gameId || ""} />
            <Summary label="Risk Level" value={currentReport.risk_level} />
            <Summary label="Injection Evidence" value={data.highestResult || "Not confirmed"} />
          </div>
        </Card>
        </Reveal>

        <Stagger className="mt-5 grid gap-4 md:grid-cols-3">
          <StaggerItem><Card><CardTitle>Confirmed</CardTitle><CardValue>{countFindings(data, "Confirmed")}</CardValue></Card></StaggerItem>
          <StaggerItem><Card><CardTitle>Likely</CardTitle><CardValue>{countFindings(data, "Likely")}</CardValue></Card></StaggerItem>
          <StaggerItem><Card><CardTitle>Possible</CardTitle><CardValue>{countFindings(data, "Possible")}</CardValue></Card></StaggerItem>
        </Stagger>

        <section className="mt-5 grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
          <Card>
            <h2 className="mb-4 text-lg font-semibold">Timeline</h2>
            <div className="space-y-2">
              {filteredTimeline.map((event, index) => (
                <div
                  key={`${event.time}-${event.text}-${index}`}
                  className={`grid max-w-full gap-3 overflow-hidden rounded-md border p-3 text-sm md:grid-cols-[160px_minmax(0,1fr)_180px] md:gap-4 ${confidenceClasses(event.confidence || "Possible")}`}
                >
                  <div className="text-zinc-400">{formatDate(event.time)}</div>
                  <div className="min-w-0 whitespace-normal break-words [overflow-wrap:anywhere]">{event.text || "Timeline event"}</div>
                  <div className="text-zinc-500 md:whitespace-nowrap">{event.source || "Evidence"}</div>
                </div>
              ))}
              {!filteredTimeline.length ? <p className="text-sm text-zinc-500">No timeline entries were included in this report.</p> : null}
            </div>
          </Card>

          <div className="space-y-4">
            <Card>
              <h2 className="text-lg font-semibold">Factory Reset Information</h2>
              <p className="mt-1 text-xs text-zinc-500">Install records may represent a reset, reinstall, or major Windows upgrade.</p>
              <div className="mt-4 space-y-3">
                {installHistory.slice(0, 8).map((item, index) => (
                  <div key={`${item.installDate}-${item.currentBuild}-${index}`} className="border-l-2 border-primary/50 pl-3 text-xs">
                    <div className="font-medium text-zinc-200">{item.productName || "Windows"}</div>
                    <div className="mt-1 text-zinc-400">Release: {item.releaseId || "Unknown"} · Build: {item.currentBuild || "Unknown"}</div>
                    <div className="mt-1 text-primary">{item.installDate ? formatDate(item.installDate) : "Install time unavailable"}</div>
                  </div>
                ))}
                {!installHistory.length ? <p className="text-sm text-zinc-500">No Windows installation records were available.</p> : null}
                {resetHistory.slice(0, 4).map((item, index) => (
                  <div key={`${item.timestamp}-${item.source}-${index}`} className="border-l-2 border-zinc-700 pl-3 text-xs text-zinc-500">
                    <div>{item.type || "Reset/install evidence"}</div>
                    <div>{item.timestamp ? formatDate(item.timestamp) : item.source}</div>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <h2 className="text-lg font-semibold">Services</h2>
              <div className="mt-3 rounded-md border border-border bg-black/20 p-3 text-sm">
                <div className="font-semibold text-primary">{sysMain.serviceName || "SysMain"}</div>
                <div className="mt-2 text-zinc-300">Current State: {sysMain.currentState || "Unavailable"}</div>
                <div className="text-zinc-300">Startup Type: {sysMain.startupType || "Unavailable"}</div>
                <div className="mt-1 text-xs text-zinc-500">
                  Last Changed: {sysMain.lastChanged ? formatDate(sysMain.lastChanged) : "Could not determine"}
                </div>
              </div>
              {sysMain.manualReviewRequired ? (
                <p className="mt-3 text-xs text-yellow-300">SysMain is disabled. This reduces Prefetch coverage and requires manual review.</p>
              ) : null}
            </Card>

            <Card>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold">Defender Exclusions</h2>
                  <p className="mt-1 text-xs text-zinc-500">Configured AV exclusions. Review entries can hide executor folders from Defender.</p>
                </div>
                <span className={reviewDefenderExclusions.length ? "text-sm text-yellow-300" : "text-sm text-primary"}>
                  {reviewDefenderExclusions.length}/{defenderExclusions.length}
                </span>
              </div>
              <div className="mt-3 space-y-2">
                {defenderExclusions.slice(0, 6).map((item, index) => (
                  <div key={`${item.type}-${item.value}-${index}`} className={`rounded-md border p-3 text-xs ${item.manualReviewRequired ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-100" : "border-border bg-black/20 text-zinc-300"}`}>
                    <div className="font-semibold">{item.type || "Exclusion"}</div>
                    <div className="mt-1 break-words [overflow-wrap:anywhere]">{item.value || "Value unavailable"}</div>
                    {(item.reasons || []).length ? <div className="mt-2 text-yellow-100/80">{(item.reasons || []).join("; ")}</div> : null}
                  </div>
                ))}
                {!defenderExclusions.length ? <p className="text-sm text-zinc-500">No Defender exclusions were found or accessible.</p> : null}
                {defenderExclusions.length > 6 ? <p className="text-xs text-zinc-500">Showing first 6 of {defenderExclusions.length}. Full list is in Detailed Evidence.</p> : null}
              </div>
            </Card>
          </div>
        </section>

        <Card className="mt-5">
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">ShellBag Analyzer</h2>
              <p className="mt-1 text-sm text-zinc-400">Read-only folder history recovered by SBECmd. These traces are context, not proof of execution.</p>
            </div>
            <span className="text-sm text-primary">{filteredShellBags.length} artifacts</span>
          </div>
          <div className="space-y-2">
            {filteredShellBags.map((item, index) => (
              <details key={`${item.path}-${item.timestamp}-${index}`} className="rounded-md border border-border bg-black/20 p-3">
                <summary className="cursor-pointer text-sm font-medium text-zinc-200">
                  {item.classification || "ShellBag Folder Trace"}: {item.path || "Path unavailable"}
                </summary>
                <div className="mt-3 grid gap-2 text-xs text-zinc-400 md:grid-cols-2">
                  <div>Time: {item.timestamp ? formatDate(item.timestamp) : "Unavailable"}</div>
                  <div>Shell type: {item.shellType || "Unknown"}</div>
                  <div>Source hive: {item.sourceHive || "Unknown"}</div>
                  <div>Slot / MRU: {item.slot || "-"} / {item.mruPosition || "-"}</div>
                </div>
              </details>
            ))}
            {!filteredShellBags.length ? <p className="text-sm text-zinc-500">No SBECmd ShellBag artifacts were included in this report.</p> : null}
          </div>
        </Card>

        <Card className="mt-5">
          <h2 className="mb-4 text-lg font-semibold">Findings</h2>
          <div className="mb-4 space-y-3">
            {filteredDetections.map((finding, index) => (
              <div key={`${finding.name}-warning-${index}`} className="rounded-md border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-100">
                <h3 className="font-semibold text-red-200">{(finding.detections || [])[0]?.category || (finding.detectionCategories || [])[0] || "Detection"} detected</h3>
                <div>File: {finding.name || "Unknown"}</div>
                <div>Path: {finding.path || ""}</div>
                <div>SHA256: {finding.sha256 || ""}</div>
                <div>First seen: {finding.firstSeen || ""}</div>
                <div>Reason: {(finding.detections || [])[0]?.reason || finding.supportingEvidence?.[0] || ""}</div>
              </div>
            ))}
          </div>
          <div className="overflow-x-auto">
            {(["Confirmed", "Likely", "Possible"] as const).map((group) => (
              <section key={group} className="mb-5">
                <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-zinc-400">{group} Findings</h3>
                <div className="space-y-3">
                  {groupedFindings[group].map((finding, index) => (
                    <div key={`${group}-${finding.name}-${index}`} className={`rounded-md border p-4 text-sm ${confidenceClasses(group)}`}>
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="font-semibold">{finding.name || "Finding"}</div>
                        <div className="rounded-full border border-current/30 px-2 py-0.5 text-xs">{group}</div>
                      </div>
                      <div className="mt-2 text-zinc-300">Class: {finding.classification || finding.category || "Unknown"}</div>
                      <div className="text-zinc-300">Score: {Number(finding.score || 0)}</div>
                      <div className="mt-2 min-w-0 break-words text-zinc-400 [overflow-wrap:anywhere]">{finding.path || ""}</div>
                    </div>
                  ))}
                  {!groupedFindings[group].length ? <p className="text-sm text-zinc-500">None.</p> : null}
                </div>
              </section>
            ))}
          </div>
        </Card>

        <Card className="mt-5">
          <h2 className="mb-2 text-lg font-semibold">Account History</h2>
          <p className="mb-4 text-sm text-zinc-400">
            {accountContext.privacyNote || "Only non-secret account identifiers are collected. Tokens, cookies, messages, and credentials are excluded."}
          </p>
          <AccountGroup
            title="Played Accounts"
            description="Accounts tied to Roblox session, join, place, or teleport evidence in the available logs."
            accounts={accountGroups.played}
            tone="played"
            idLabel="Roblox User ID"
          />
          <AccountGroup
            title="Historical Account IDs Found"
            description="IDs found in Roblox logs or metadata, but not enough evidence to say this scan proved active play."
            accounts={accountGroups.historical}
            tone="historical"
            idLabel="Roblox User ID"
          />
          <AccountGroup
            title="Weak/Old Account Artifacts"
            description="Old crash or residue-only account artifacts. These are context only and should not be treated as proof of play."
            accounts={accountGroups.weak}
            tone="weak"
            idLabel="Roblox User ID"
          />
          <AccountGroup
            title="Discord Account Evidence"
            description="Safe Discord log identifier evidence only. Tokens, cookies, Local Storage, IndexedDB, Session Storage, cache, DMs, private messages, friend lists, and server lists are excluded."
            accounts={discordRows}
            tone="historical"
            idLabel="Discord User ID"
          />
        </Card>

        <Card className="mt-5">
          <h2 className="mb-2 text-lg font-semibold">Detected FastFlags</h2>
          <p className="mb-4 text-sm text-zinc-400">FastFlags are grouped with the Roblox log where they were detected.</p>
          <div className="space-y-2">
            {filteredFastFlags.map((flag, index) => (
              <div key={`${flag.name}-${flag.sourceLog}-${index}`} className="rounded-md border border-yellow-500/40 bg-yellow-500/10 p-3 text-sm text-yellow-100">
                <div className="font-semibold">{flag.name || "FastFlag"}{flag.value ? ` = ${flag.value}` : ""}</div>
                <div className="mt-1 text-yellow-100/80">Timestamp: {formatDate(flag.timestamp)}</div>
                <div className="min-w-0 break-words text-yellow-100/80 [overflow-wrap:anywhere]">Source: {flag.sourceLog || "Roblox log"}</div>
                <div className="text-yellow-100/80">Place: {flag.placeId || ""} Job: {flag.jobId || ""}</div>
                {flag.line ? <div className="mt-2 min-w-0 break-words text-yellow-100/80 [overflow-wrap:anywhere]">{flag.line}</div> : null}
              </div>
            ))}
            {!filteredFastFlags.length ? <p className="text-sm text-zinc-500">No FastFlags were detected in this report.</p> : null}
          </div>
        </Card>

        <Card className="mt-5">
          <h2 className="mb-2 text-lg font-semibold">Show All Roblox Logs</h2>
          <p className="mb-4 text-sm text-zinc-400">Expand each captured Roblox log to inspect extracted events, FastFlags, and the raw log text.</p>
          <div className="space-y-3">
            {filteredRobloxLogs.map((log, index) => (
              <details key={`${log.logFile}-${index}`} className="rounded-md border border-border bg-black/20 p-3">
                <summary className="cursor-pointer font-semibold">
                  {log.logFile?.split(/[\\/]/).pop() || "Roblox log"} · {formatDate(log.startTime || log.modifiedTime)}
                </summary>
                <div className="mt-3 grid gap-2 text-sm text-zinc-400 md:grid-cols-3">
                  <div>Username: {log.username || "Unknown"}</div>
                  <div>User ID: {log.userId || ""}</div>
                  <div>Place ID: {log.placeId || ""}</div>
                  <div>Job ID: {log.jobId || ""}</div>
                  <div>Duration: {log.duration || "unknown"}</div>
                  <div>Version: {log.version || ""}</div>
                </div>
                <h3 className="mt-4 text-sm font-semibold text-zinc-200">FastFlags in this log</h3>
                <div className="mt-2 space-y-2">
                  {(log.fastFlags || []).map((flag, flagIndex) => (
                    <div key={`${flag.name}-${flagIndex}`} className="rounded-md border border-yellow-500/30 bg-yellow-500/10 p-2 text-xs text-yellow-100">
                      <div className="font-semibold">{flag.name || "FastFlag"}{flag.value ? ` = ${flag.value}` : ""}</div>
                      <div>{formatDate(flag.timestamp)}</div>
                    </div>
                  ))}
                  {!(log.fastFlags || []).length ? <p className="text-sm text-zinc-500">None found in this log.</p> : null}
                </div>
                <h3 className="mt-4 text-sm font-semibold text-zinc-200">Captured Roblox Events</h3>
                <div className="mt-2 space-y-2">
                  {(log.events || []).map((event, eventIndex) => (
                    <div key={`${event.timestamp}-${eventIndex}`} className="grid gap-2 rounded-md border border-border/70 bg-black/20 p-2 text-xs md:grid-cols-[150px_110px_minmax(0,1fr)]">
                      <div className="text-zinc-500">{formatDate(event.timestamp)}</div>
                      <div className="text-primary">{event.type || "Event"}</div>
                      <div className="min-w-0 break-words text-zinc-300 [overflow-wrap:anywhere]">{event.message || ""}</div>
                    </div>
                  ))}
                  {!(log.events || []).length ? <p className="text-sm text-zinc-500">No structured events extracted.</p> : null}
                </div>
                <h3 className="mt-4 text-sm font-semibold text-zinc-200">Raw Roblox Log</h3>
                <pre className="mt-2 max-h-[520px] overflow-auto whitespace-pre-wrap break-words rounded-md bg-black/40 p-3 text-xs text-zinc-300">{log.rawLog || ""}</pre>
              </details>
            ))}
            {!filteredRobloxLogs.length ? <p className="text-sm text-zinc-500">No Roblox logs were included in this report.</p> : null}
          </div>
        </Card>

        <Card className="mt-5">
          <h2 className="mb-4 text-lg font-semibold">Detailed Evidence</h2>
          <div className="space-y-3">
            {filteredEvidence.map((group) => (
              <details key={group.title} open className="rounded-md border border-border bg-black/20 p-3">
                <summary className="cursor-pointer font-semibold">{group.title} ({group.items.length})</summary>
                <div className="mt-3 space-y-2">
                  {group.items.map((item, index) => (
                    <div key={index} className="rounded-md border border-border/70 bg-black/20 p-3 text-sm">
                      <div className="mb-1 text-xs text-zinc-500">{formatDate(evidenceTimestamp(item))}</div>
                      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words bg-transparent p-0 text-xs text-zinc-300">{JSON.stringify(item, null, 2)}</pre>
                    </div>
                  ))}
                  {!group.items.length ? <p className="text-sm text-zinc-500">No entries were included.</p> : null}
                </div>
              </details>
            ))}
            {!filteredEvidence.length ? <p className="text-sm text-zinc-500">No detailed evidence sections were included in this report.</p> : null}
          </div>
        </Card>

        <Card className="mt-5">
          <h2 className="mb-4 text-lg font-semibold">Raw report data</h2>
          <pre className="max-h-[520px] overflow-auto rounded-md bg-black/40 p-4 text-xs text-zinc-300">{JSON.stringify(data, null, 2)}</pre>
        </Card>
      </div>
    </main>
  );
}

function Summary({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-black/20 p-3">
      <div className="text-xs text-zinc-500">{label}</div>
      <div className="mt-1 break-words font-semibold">{value || "Unknown"}</div>
    </div>
  );
}

function AccountGroup({
  title,
  description,
  accounts,
  tone,
  idLabel
}: {
  title: string;
  description: string;
  accounts: AccountIdentifier[];
  tone: "played" | "historical" | "weak";
  idLabel: string;
}) {
  const toneClass = {
    played: "border-primary/50 bg-primary/10",
    historical: "border-zinc-700 bg-black/20",
    weak: "border-zinc-800 bg-black/10"
  }[tone];

  return (
    <section className="mt-5">
      <div className="mb-3">
        <h3 className="text-base font-semibold text-zinc-100">{title}</h3>
        <p className="mt-1 text-sm text-zinc-500">{description}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {accounts.map((account, index) => (
          <div key={`${title}-${account.platform}-${account.userId}-${index}`} className={`rounded-md border p-4 text-sm ${toneClass}`}>
            <div className="font-semibold text-zinc-300">{account.platform || "Roblox"}</div>
            <div className="mt-3 text-xs font-semibold uppercase text-zinc-500">{idLabel}</div>
            <div className="mt-1 break-all text-3xl font-bold text-primary">{account.userId || "ID unavailable"}</div>
            <div className="mt-3 text-zinc-300">Username: {account.username || "Unknown"}</div>
            {account.displayName ? <div className="text-zinc-400">Display Name: {account.displayName}</div> : null}
            <div className="text-zinc-400">First evidence: {formatDate(account.firstSeen)}</div>
            <div className="text-zinc-400">Last evidence: {formatDate(account.lastSeen)}</div>
            {(account.places || []).length ? <div className="mt-2 break-words text-zinc-500">Place IDs: {(account.places || []).join(", ")}</div> : null}
            {account.evidenceNote ? <div className="mt-2 text-xs text-zinc-500">{account.evidenceNote}</div> : null}
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-zinc-400">Evidence sources ({(account.sources || []).length})</summary>
              <div className="mt-2 space-y-1">
                {(account.sources || []).map((source, sourceIndex) => (
                  <div key={sourceIndex} className="break-words text-xs text-zinc-500 [overflow-wrap:anywhere]">{source}</div>
                ))}
              </div>
            </details>
          </div>
        ))}
        {!accounts.length ? <p className="text-sm text-zinc-500">None.</p> : null}
      </div>
    </section>
  );
}

type EvidenceGroup = {
  title: string;
  items: Record<string, unknown>[];
};

type AccountGroups = {
  played: AccountIdentifier[];
  historical: AccountIdentifier[];
  weak: AccountIdentifier[];
};

function groupRobloxAccounts(accounts: AccountIdentifier[], sessions: SecuroSession[], logs: RobloxLogArtifact[]): AccountGroups {
  const playedIds = new Set<string>();
  for (const session of sessions || []) {
    const id = normalizeAccountId(session.userId);
    if (id && (session.placeId || session.gameId || session.jobId || session.launchTime || session.exitTime)) playedIds.add(id);
  }
  for (const log of logs || []) {
    const id = normalizeAccountId(log.userId);
    if (id && (log.placeId || log.jobId || robloxLogHasPlayEvidence(log))) playedIds.add(id);
  }

  const grouped: AccountGroups = { played: [], historical: [], weak: [] };
  for (const account of accounts || []) {
    const id = normalizeAccountId(account.userId);
    if (id && playedIds.has(id)) {
      grouped.played.push(account);
    } else if (isWeakOldAccountArtifact(account)) {
      grouped.weak.push(account);
    } else {
      grouped.historical.push(account);
    }
  }
  return grouped;
}

function normalizeAccountId(value: unknown) {
  return String(value || "").replace(/\D/g, "");
}

function robloxLogHasPlayEvidence(log: RobloxLogArtifact) {
  return (log.events || []).some((event) => {
    const text = `${event.type || ""} ${event.message || ""}`.toLowerCase();
    return text.includes("join") || text.includes("place") || text.includes("teleport") || text.includes("game_join");
  });
}

function isWeakOldAccountArtifact(account: AccountIdentifier) {
  const sources = account.sources || [];
  const hasCrashSource = sources.some((source) => /crashes?[\\/]+attachments?|crash/i.test(source));
  const allCrashSources = sources.length > 0 && sources.every((source) => /crashes?[\\/]+attachments?|crash/i.test(source));
  const first = parseTimestamp(account.firstSeen)?.getTime();
  const last = parseTimestamp(account.lastSeen)?.getTime();
  return allCrashSources || (hasCrashSource && first !== undefined && last !== undefined && first === last);
}

function parseTimestamp(value: unknown) {
  if (!value) return null;
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function evidenceTimestamp(item: Record<string, unknown>) {
  const value = item.timestamp || item.time || item.firstSeen || item.first_seen || item.createdAt || item.created_at || item.modifiedAt || item.modified_at || item.activated_at || item.last_seen_at || "";
  return value ? String(value) : "";
}

function findingConfidence(finding: SecuroFinding) {
  if (isMainstreamOrRuntimeFinding(finding) && (finding.confidenceLevel === "Confirmed" || finding.classification === "Confirmed Exploit")) {
    return Number(finding.score || 0) >= 50 ? "Likely" : "Possible";
  }
  if (finding.confidenceLevel === "Confirmed" || finding.classification === "Confirmed Exploit") return "Confirmed";
  if (finding.confidenceLevel === "Likely" || finding.classification === "Suspicious" || Number(finding.score || 0) >= 50) return "Likely";
  return "Possible";
}

function isConfirmedFinding(finding: SecuroFinding) {
  return findingConfidence(finding) === "Confirmed";
}

function isSecuroSuppressedFinding(finding: { name?: string; path?: string }) {
  const text = `${finding.name || ""} ${finding.path || ""}`.toLowerCase();
  return text.includes("\\securo") || text.includes("/securo") || text.includes("_internal");
}

function isMainstreamOrRuntimeFinding(finding: { name?: string; path?: string }) {
  const text = `${finding.name || ""} ${finding.path || ""}`.toLowerCase();
  const commonRuntime = [
    "sqlite3.dll",
    "libcrypto",
    "libssl",
    "python312.dll",
    "python3.dll",
    "libffi",
    "vcruntime",
    "msvcp140.dll",
    "api-ms-win",
    "webview2loader.dll",
    "base_library.zip"
  ];
  const mainstream = ["spotify", "chrome", "discord", "steam", "roblox", "microsoft", "nvidia", "amd", "edge", "razer", "logitech", "corsair", "steelseries", "mozilla", "firefox", "intel"];
  const protectedSystem = ["svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe", "dwm.exe", "taskhostw.exe", "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe"];
  const trustedLocation = text.includes("c:\\windows\\") || text.includes("c:\\program files\\") || text.includes("c:\\program files (x86)\\");
  return trustedLocation || commonRuntime.some((name) => text.includes(name)) || mainstream.some((name) => text.includes(name)) || protectedSystem.some((name) => text.includes(name));
}

function confidenceClasses(confidence: string) {
  if (confidence === "Confirmed") return "border-red-500/50 bg-red-500/10 text-red-100";
  if (confidence === "Likely") return "border-yellow-500/50 bg-yellow-500/10 text-yellow-100";
  return "border-zinc-700 bg-black/20 text-zinc-200";
}

function reportEvidenceGroups(data: ReportRow["report_json"]): EvidenceGroup[] {
  const raw = data as Record<string, unknown>;
  const groups: Array<[string, unknown]> = [
    ["Detect Logs", raw.detectLogs || raw.detect_logs],
    ["Warning Logs", raw.warningLogs || raw.warning_logs],
    ["Recovery", raw.recoveryArtifacts || raw.recovery_artifacts || raw.recoveredFiles || raw.recovered_files],
    ["Antivirus Logs", raw.antivirusLogs || raw.antivirus_logs],
    ["Defender Exclusions", raw.defenderExclusions || raw.defender_exclusions],
    ["Engine Results", raw.engineResults || raw.engine_results],
    ["Detected FastFlags", raw.detectedFastFlags || raw.detected_fast_flags],
    ["USN Journal Events", raw.usnJournalEvents || raw.usn_journal_events],
    ["ShellBag Artifacts", raw.shellBagArtifacts || raw.shellbag_artifacts],
    ["Roblox Logs", raw.robloxLogs || raw.roblox_logs],
    ["Evidence Sources", Object.entries(data.evidenceSources || {}).map(([source, value]) => ({ source, value }))],
    ["Limitations", (data.limitations || []).map((text) => ({ text }))]
  ];

  return groups
    .map(([title, value]) => ({
      title,
      items: Array.isArray(value) ? (value.filter((item) => typeof item === "object" && item !== null) as Record<string, unknown>[]) : []
    }))
    .filter((group) => group.items.length);
}

function buildExportHtml(report: ReportRow) {
  const data = report.report_json;
  const visibleFindings = data.findings.filter((finding) => !isSecuroSuppressedFinding(finding));
  const evidenceGroups = reportEvidenceGroups(data);
  const entry = (timestamp: unknown, content: string, tag = "div", keepVisible = false) => {
    const stamp = parseTimestamp(timestamp)?.toISOString() || "";
    return `<${tag} class="report-entry"${stamp ? ` data-timestamp="${escape(stamp)}"` : ""}${keepVisible ? ` data-keep-visible="true"` : ""}>${content}</${tag}>`;
  };
  const evidence = evidenceGroups.map((group) => `
    <section><h2>${escape(group.title)}</h2>
    ${group.items.map((item) => entry(evidenceTimestamp(item), `<pre>${escape(JSON.stringify(item, null, 2))}</pre>`)).join("") || "<p>No entries.</p>"}
    </section>
  `).join("");
  const fastFlags = (data.detectedFastFlags || []).map((flag) => entry(flag.timestamp, `
    <p><b>${escape(flag.name || "FastFlag")}</b>${flag.value ? ` = ${escape(flag.value)}` : ""}</p>
    <p>Source: ${escape(flag.sourceLog || "Roblox log")}</p>
    <p>Place: ${escape(flag.placeId || "")} Job: ${escape(flag.jobId || "")}</p>
    <p>${escape(flag.line || "")}</p>
  `)).join("");
  const robloxLogs = (data.robloxLogs || []).map((log) => entry(log.startTime || log.modifiedTime, `
    <details open>
      <summary>${escape(log.logFile?.split(/[\\/]/).pop() || "Roblox log")} · ${escape(formatDate(log.startTime || log.modifiedTime))}</summary>
      <p>User: ${escape(log.username || "Unknown")} (${escape(log.userId || "")}) Place: ${escape(log.placeId || "")} Job: ${escape(log.jobId || "")}</p>
      <h3>FastFlags in this log</h3>
      ${(log.fastFlags || []).map((flag) => `<p><b>${escape(flag.name || "FastFlag")}</b>${flag.value ? ` = ${escape(flag.value)}` : ""} ${escape(flag.timestamp || "")}</p>`).join("") || "<p>None found.</p>"}
      <h3>Captured Roblox Events</h3>
      ${(log.events || []).map((event) => `<div class="timeline-entry"><time>${escape(formatDate(event.timestamp))}</time><div class="timeline-message">${escape(event.message || "")}</div><small class="timeline-source">${escape(event.type || "Event")}</small></div>`).join("") || "<p>No structured events extracted.</p>"}
      <h3>Raw Roblox Log</h3>
      <pre>${escape(log.rawLog || "")}</pre>
    </details>
  `)).join("");
  const accountContext = data.accountIdentifiers || {};
  const accountGroups = groupRobloxAccounts(accountContext.roblox || [], data.sessions || [], data.robloxLogs || []);
  const accountCard = (account: AccountIdentifier, idLabel: string) => `
    <div class="report-entry account-card">
      <p><b>${escape(account.platform || "Roblox")}</b></p>
      <small>${escape(idLabel)}</small>
      <div class="account-id">${escape(account.userId || "ID unavailable")}</div>
      <p>Username: ${escape(account.username || "Unknown")} ${account.displayName ? `· Display Name: ${escape(account.displayName)}` : ""}</p>
      <p>First evidence: ${escape(account.firstSeen || "")} · Last evidence: ${escape(account.lastSeen || "")}</p>
      ${(account.places || []).length ? `<p>Place IDs: ${escape((account.places || []).join(", "))}</p>` : ""}
      ${account.evidenceNote ? `<p>${escape(account.evidenceNote)}</p>` : ""}
      <p>Sources: ${escape((account.sources || []).join("; "))}</p>
    </div>
  `;
  const accountGroup = (title: string, description: string, accounts: AccountIdentifier[], idLabel: string) => `
    <div class="account-group">
      <h3>${escape(title)}</h3>
      <p class="muted">${escape(description)}</p>
      ${accounts.map((account) => accountCard(account, idLabel)).join("") || "<p class=\"muted\">None.</p>"}
    </div>
  `;
  const accounts = [
    accountGroup("Played Accounts", "Accounts tied to Roblox session, join, place, or teleport evidence in the available logs.", accountGroups.played, "Roblox User ID"),
    accountGroup("Historical Account IDs Found", "IDs found in Roblox logs or metadata, but not enough evidence to say this scan proved active play.", accountGroups.historical, "Roblox User ID"),
    accountGroup("Weak/Old Account Artifacts", "Old crash or residue-only account artifacts. These are context only and should not be treated as proof of play.", accountGroups.weak, "Roblox User ID"),
    accountGroup("Discord Account Evidence", "Safe Discord log identifier evidence only. Tokens, cookies, Local Storage, IndexedDB, Session Storage, cache, DMs, private messages, friend lists, and server lists are excluded.", accountContext.discord || [], "Discord User ID")
  ].join("");
  const resetHistory = (data.systemResetEvidence || []).slice(0, 12).map((item) => entry(item.timestamp, `
    <p><b>${escape(item.type || "Reset/install evidence")}</b></p>
    <p>${escape(item.timestamp || "Time unavailable")}</p>
    <p>${escape(item.source || "Windows evidence")}</p>
  `)).join("");
  const installHistory = (data.windowsInstallHistory || []).slice(0, 8).map((item) => entry(item.installDate, `
    <p><b>${escape(item.productName || "Windows")}</b></p>
    <p>Release: ${escape(item.releaseId || "Unknown")} · Build: ${escape(item.currentBuild || "Unknown")}</p>
    <p>${escape(item.installDate || "Install time unavailable")}</p>
  `)).join("");
  const sysMain = data.sysMainService || {};
  const defenderExclusionRows = (data.defenderExclusions || []).slice(0, 20).map((item) => entry("", `
    <p><b>${escape(item.type || "Exclusion")}</b> ${item.manualReviewRequired ? "Review" : "Info"}</p>
    <p>${escape(item.value || "Value unavailable")}</p>
    ${(item.reasons || []).length ? `<p>Reasons: ${escape((item.reasons || []).join("; "))}</p>` : ""}
    <p>Source: ${escape(item.source || "Defender preferences")}</p>
  `)).join("");

  return `<!doctype html><html><head><meta charset="utf-8"><title>Securo Report</title>
    <style>
      body{font-family:Segoe UI,Arial;background:#07100b;color:#eefaf1;padding:24px}
      section{border:1px solid #264234;border-radius:8px;padding:16px;margin:12px 0}
      pre{white-space:pre-wrap;word-break:break-word;background:#050807;padding:12px;border-radius:8px;max-height:420px;overflow:auto}
      table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #264234;padding:8px;text-align:left;vertical-align:top}
      .report-entry{border-bottom:1px solid rgba(255,255,255,.08);padding:8px 0}
      .muted{color:#8b93a7}
      .account-group{margin:18px 0}
      .account-card{border:1px solid #264234;border-radius:8px;padding:14px;margin:10px 0}
      .account-card small{color:#8b93a7}.account-id{color:#00d26a;font-size:26px;font-weight:700;overflow-wrap:anywhere;margin:4px 0 12px}
      .timeline-reset-grid{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:16px;align-items:start}
      .timeline-reset-grid>aside{display:grid;gap:12px}
      .timeline-entry{display:grid;grid-template-columns:160px minmax(0,1fr) 180px;gap:16px;align-items:start;overflow:hidden}
      .timeline-message{min-width:0;overflow-wrap:anywhere;word-break:break-word;white-space:normal}
      .timeline-source{white-space:nowrap;color:#8b93a7}
      @media(max-width:720px){.timeline-entry,.timeline-reset-grid{grid-template-columns:1fr}.timeline-source{white-space:normal}}
    </style>
    </head><body>
    <h1>Securo Report</h1>
    <section><p>Host: ${escape(report.hostname)}</p><p>Risk: ${escape(report.risk_level)}</p><p>Score: ${report.evidence_score}</p><p>Scan: ${escape(data.scanTime)}</p></section>
    <div class="timeline-reset-grid"><section><h2>Timeline</h2>${data.timeline.map((event) => entry(event.time, `<div class="timeline-entry"><time>${escape(formatDate(event.time))}</time><div class="timeline-message">${escape(event.text || "")}</div><small class="timeline-source">${escape(event.source || "")}</small></div>`)).join("") || "<p>No timeline entries.</p>"}</section><aside><section><h2>Factory Reset Information</h2><p>Install records may represent a reset, reinstall, or major Windows upgrade.</p>${installHistory || resetHistory || "<p>No Windows installation records available.</p>"}</section><section><h2>Services</h2><p><b>${escape(sysMain.serviceName || "SysMain")}</b></p><p>Current State: ${escape(sysMain.currentState || "Unavailable")}</p><p>Startup Type: ${escape(sysMain.startupType || "Unavailable")}</p><p>Last Changed: ${escape(sysMain.lastChanged || "Could not determine")}</p></section><section><h2>Defender Exclusions</h2><p>Configured AV exclusions. Review entries can hide executor folders from Defender.</p>${defenderExclusionRows || "<p>No Defender exclusions were found or accessible.</p>"}</section></aside></div>
    <section><h2>Roblox Account History</h2><p>${escape(accountContext.privacyNote || "Only non-secret Roblox account identifiers are collected.")}</p>${accounts || "<p>No Roblox account identifiers available.</p>"}</section>
    <section><h2>Detected FastFlags</h2>${fastFlags || "<p>No FastFlags detected.</p>"}</section>
    <section><h2>Show All Roblox Logs</h2>${robloxLogs || "<p>No raw Roblox logs captured.</p>"}</section>
    <section><h2>Findings</h2>${visibleFindings.map((finding) => entry(finding.firstSeen, `<p><b>${escape(finding.name || "Finding")}</b> ${escape(finding.classification || finding.category || "")} ${Number(finding.score || 0)}</p><p>${escape(finding.path || "")}</p>`, "div", isConfirmedFinding(finding))).join("") || "<p>No findings.</p>"}</section>
    ${evidence}
    <section><h2>Raw report</h2><pre>${escape(JSON.stringify(data, null, 2))}</pre></section>
    </body></html>`;
}

function escape(value: unknown) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[char] || char));
}
