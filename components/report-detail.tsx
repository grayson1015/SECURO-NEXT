"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import Link from "next/link";
import { ArrowLeft, ChevronDown, Download } from "lucide-react";
import type { AccountIdentifier, DeletedFileArtifact, KeyArtifact, ReportRow, RobloxLogArtifact, SecuroFinding, SecuroSession } from "@/lib/types";
import { countFindings } from "@/lib/report";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, CardValue } from "@/components/ui/card";
import { AnimatedBackground, Reveal, Stagger, StaggerItem } from "@/components/motion-shell";

export function ReportDetail({ report }: { report: ReportRow }) {
  const currentReport = report;
  const data = currentReport.report_json;
  const platform = reportPlatform(data);
  const isMac = platform === "macos";
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
  const keyArtifacts = data.keyArtifacts || [];
  const prefetchArtifacts = useMemo(() => keyArtifacts.filter(isPrefetchArtifact), [keyArtifacts]);
  const [showAllPrefetch, setShowAllPrefetch] = useState(false);
  const [expandedTile, setExpandedTile] = useState<string | null>(null);
  const [deletedSearch, setDeletedSearch] = useState("");
  const [deletedSort, setDeletedSort] = useState<"deletionTimestamp" | "filename" | "source" | "fileSize">("deletionTimestamp");
  const visiblePrefetchArtifacts = showAllPrefetch ? prefetchArtifacts : prefetchArtifacts.slice(0, 6);
  const deletedFileArtifacts = useMemo(() => buildDeletedFileArtifacts(data), [data]);
  const filteredDeletedFileArtifacts = useMemo(
    () => sortDeletedFileArtifacts(
      deletedFileArtifacts.filter((item) => deletedArtifactSearchText(item).includes(deletedSearch.trim().toLowerCase())),
      deletedSort
    ),
    [deletedFileArtifacts, deletedSearch, deletedSort]
  );
  const forensicSummary = useMemo(() => buildForensicSummary(data), [data]);
  const usnEvents = data.usnJournalEvents || [];
  const usnStatus = data.usnJournalStatus || {};
  const usnAvailable = usnStatus.available ?? data.evidenceSources?.["USN Change Journal available"];
  const usnReadable = usnStatus.readable ?? data.evidenceSources?.["USN Change Journal readable"];
  const usnCollected = usnStatus.recordsCollected ?? data.evidenceSources?.["USN Journal records collected"];
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
  const detailedEvidenceCount = filteredEvidence.reduce((total, group) => total + group.items.length, 0);
  const accountCount = accountRows.length + discordRows.length;

  const toggleTile = (tile: string) => {
    setExpandedTile((current) => current === tile ? null : tile);
  };

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
          <div className="flex items-center gap-3">
            <Badge label={isMac ? "macOS" : "Windows"} />
            <Button onClick={exportHtml}><Download size={16} />Export HTML</Button>
          </div>
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
            {isMac ? (
              <MacEvidenceSidebar data={data} />
            ) : (
              <>
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

            <Card>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold">Forensic Artifacts</h2>
                  <p className="mt-1 text-xs text-zinc-500">Compact parser evidence counts. Detailed sections are shown below.</p>
                </div>
                <span className="text-sm text-primary">{forensicSummary.total}</span>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2">
                {forensicSummary.cards.map((item) => (
                  <div key={item.label} className="rounded-md border border-border bg-black/20 p-3">
                    <div className="text-xs text-zinc-500">{item.label}</div>
                    <div className="mt-1 text-xl font-bold text-zinc-100">{item.count}</div>
                  </div>
                ))}
              </div>
            </Card>
              </>
            )}
          </div>
        </section>

        <section aria-label="Report evidence categories" className="mt-5 grid items-start gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {!isMac ? (
        <>
        <ReportTile
          id="prefetch"
          title="Prefetch artifacts"
          count={prefetchArtifacts.length}
          countLabel="entries"
          description="Execution-history files collected from Windows Prefetch and parser exports."
          expanded={expandedTile === "prefetch"}
          onToggle={() => toggleTile("prefetch")}
        >
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">Prefetch Artifacts</h2>
              <p className="mt-1 text-sm text-zinc-400">Execution-history Prefetch entries collected by Securo and parser exports. These are review signals unless paired with stronger evidence.</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-sm text-primary">{prefetchArtifacts.length} prefetches</span>
              {prefetchArtifacts.length > 6 ? (
                <Button className="bg-zinc-900 text-zinc-100 shadow-none hover:bg-zinc-800" onClick={() => setShowAllPrefetch((value) => !value)}>
                  {showAllPrefetch ? "Minimize" : "Show All Prefetch"}
                </Button>
              ) : null}
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {visiblePrefetchArtifacts.map((item, index) => (
              <div key={`${item.type}-${artifactText(item)}-${index}`} className="rounded-md border border-border bg-black/20 p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold text-zinc-200">PREFETCH FILE</span>
                  <span className="text-xs text-zinc-500">{formatDate(item.timestamp)}</span>
                </div>
                <div className="mt-2 break-words text-zinc-300 [overflow-wrap:anywhere]">{artifactText(item)}</div>
                {item.path ? <div className="mt-1 break-words text-zinc-500 [overflow-wrap:anywhere]">{item.path}</div> : null}
                <div className="mt-2 text-xs text-zinc-500">{item.source || "Prefetch"} · {item.confidence || "Review"}</div>
              </div>
            ))}
            {!prefetchArtifacts.length ? <p className="text-sm text-zinc-500">No Prefetch artifacts were included in this report.</p> : null}
          </div>
          {prefetchArtifacts.length > 6 ? (
            <p className="mt-3 text-xs text-zinc-500">
              {showAllPrefetch ? `Showing all ${prefetchArtifacts.length} Prefetch artifacts.` : `Showing newest 6 of ${prefetchArtifacts.length}.`}
            </p>
          ) : null}
        </ReportTile>

        <ReportTile
          id="deleted-files"
          title="Deleted files"
          count={deletedFileArtifacts.length}
          countLabel="artifacts"
          description="Merged deletion evidence from MFT, Recycle Bin, USN, and recovery metadata."
          expanded={expandedTile === "deleted-files"}
          onToggle={() => toggleTile("deleted-files")}
        >
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">Deleted File Artifacts</h2>
              <p className="mt-1 text-sm text-zinc-400">Merged deleted-file evidence from MFTECmd, JLECmd/LECmd, Recycle Bin, USN Journal, and recovery metadata when available.</p>
            </div>
            <span className="text-sm text-primary">{filteredDeletedFileArtifacts.length}/{deletedFileArtifacts.length} deleted</span>
          </div>
          <div className="mb-3 flex flex-wrap gap-2">
            <input
              value={deletedSearch}
              onChange={(event) => setDeletedSearch(event.target.value)}
              placeholder="Search deleted files"
              className="min-h-10 flex-1 rounded-md border border-border bg-black/30 px-3 text-sm text-zinc-100 outline-none focus:border-primary"
            />
            <select
              value={deletedSort}
              onChange={(event) => setDeletedSort(event.target.value as typeof deletedSort)}
              className="min-h-10 rounded-md border border-border bg-black/30 px-3 text-sm text-zinc-100 outline-none focus:border-primary"
            >
              <option value="deletionTimestamp">Deletion time</option>
              <option value="filename">Filename</option>
              <option value="source">Source</option>
              <option value="fileSize">File size</option>
            </select>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr>
                  <th className="border-b border-border px-3 py-2">File</th>
                  <th className="border-b border-border px-3 py-2">Deleted</th>
                  <th className="border-b border-border px-3 py-2">Source</th>
                  <th className="border-b border-border px-3 py-2">USN reason</th>
                  <th className="border-b border-border px-3 py-2">Size</th>
                </tr>
              </thead>
              <tbody>
                {filteredDeletedFileArtifacts.map((item, index) => (
                  <tr key={`${item.originalPath}-${item.deletionTimestamp}-${index}`} className={item.recent ? "bg-yellow-500/5" : ""}>
                    <td colSpan…9636 tokens truncated…Name || "",
      path: event.path || event.fileName || "",
      deletionTimestamp: event.timestamp,
      timestamp: event.timestamp,
      mftRecordNumber: event.fileId,
      usn: event.usn,
      usnReason: event.reason || event.eventType,
      source: "USN Journal",
      sources: ["USN Journal"],
      confidence: "Possible",
      metadata: event as Record<string, unknown>,
    });
  });

  return [...seen.values()].map((item) => ({
    ...item,
    recent: item.recent ?? isRecentTimestamp(item.deletionTimestamp || item.timestamp),
  })).sort((a, b) => (parseTimestamp(b.deletionTimestamp || b.timestamp)?.getTime() || 0) - (parseTimestamp(a.deletionTimestamp || a.timestamp)?.getTime() || 0));
}

function mergeDeletedArtifact(left: DeletedFileArtifact, right: DeletedFileArtifact): DeletedFileArtifact {
  const sources = [...(left.sources || []), ...(right.sources || [])].filter(Boolean);
  const uniqueSources = [...new Set(sources)];
  return {
    ...left,
    ...Object.fromEntries(Object.entries(right).filter(([, value]) => value !== undefined && value !== "" && value !== null)),
    filename: left.filename || right.filename,
    originalPath: left.originalPath || right.originalPath,
    path: left.path || right.path,
    deletionTimestamp: left.deletionTimestamp || right.deletionTimestamp,
    timestamp: left.timestamp || right.timestamp,
    source: uniqueSources.join(" + ") || left.source || right.source,
    sources: uniqueSources,
    metadata: { ...(left.metadata || {}), ...(right.metadata || {}) },
    recent: Boolean(left.recent || right.recent || isRecentTimestamp(left.deletionTimestamp || right.deletionTimestamp || left.timestamp || right.timestamp)),
  };
}

function sortDeletedFileArtifacts(items: DeletedFileArtifact[], sortKey: "deletionTimestamp" | "filename" | "source" | "fileSize") {
  return [...items].sort((a, b) => {
    if (sortKey === "deletionTimestamp") {
      return (parseTimestamp(b.deletionTimestamp || b.timestamp)?.getTime() || 0) - (parseTimestamp(a.deletionTimestamp || a.timestamp)?.getTime() || 0);
    }
    if (sortKey === "fileSize") {
      return numericFileSize(b.fileSize) - numericFileSize(a.fileSize);
    }
    return String(a[sortKey] || "").localeCompare(String(b[sortKey] || ""));
  });
}

function deletedArtifactSearchText(item: DeletedFileArtifact) {
  return [
    item.filename,
    item.originalPath,
    item.path,
    item.source,
    ...(item.sources || []),
    item.usnReason,
    item.usn,
    item.mftRecordNumber,
  ].join(" ").toLowerCase();
}

function formatDeletedSources(item: DeletedFileArtifact) {
  return (item.sources && item.sources.length ? item.sources : [item.source]).filter(Boolean).join(" + ") || "Unknown";
}

function pathBasename(path: string) {
  const cleaned = String(path || "").replace(/^DELETED FILE:\s*/i, "");
  return cleaned.split(/[\\/]/).filter(Boolean).pop() || "";
}

function isRecentTimestamp(timestamp?: string) {
  const parsed = parseTimestamp(timestamp);
  return Boolean(parsed && Date.now() - parsed.getTime() <= 7 * 24 * 60 * 60 * 1000);
}

function numericFileSize(value: unknown) {
  const parsed = Number(String(value || "").replace(/[^0-9.]/g, ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatFileSize(value: unknown) {
  const bytes = numericFileSize(value);
  if (!bytes) return value ? String(value) : "Unavailable";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function buildForensicSummary(data: ReportRow["report_json"]) {
  const keyArtifacts = data.keyArtifacts || [];
  const countType = (patterns: RegExp[]) =>
    keyArtifacts.filter((item) => patterns.some((pattern) => pattern.test(`${item.type || ""} ${artifactText(item)} ${item.source || ""}`))).length;
  const cards = [
    { label: "Prefetch", count: countType([/prefetch/i]) },
    { label: "Deleted", count: countType([/deleted|deletion|recycle/i]) + (data.usnJournalEvents || []).filter((item) => /delete/i.test(`${item.eventType || ""} ${item.reason || ""}`)).length },
    { label: "ShellBags", count: (data.shellBagArtifacts || []).length },
    { label: "USN", count: (data.usnJournalEvents || []).length },
    { label: "FastFlags", count: (data.detectedFastFlags || []).length },
    { label: "Defender", count: (data.defenderExclusions || []).length }
  ];
  return {
    cards,
    total: cards.reduce((sum, item) => sum + item.count, 0)
  };
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
  const platform = reportPlatform(data);
  const isMac = platform === "macos";
  const visibleFindings = data.findings.filter((finding) => !isSecuroSuppressedFinding(finding));
  const evidenceGroups = reportEvidenceGroups(data);
  const forensicSummary = buildForensicSummary(data);
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
  const forensicCards = forensicSummary.cards.map((item) => `<div class="mini-card"><small>${escape(item.label)}</small><b>${item.count}</b></div>`).join("");
  const deletedFileArtifacts = buildDeletedFileArtifacts(data);
  const deletedFileRows = deletedFileArtifacts.map((item) => entry(item.deletionTimestamp || item.timestamp, `
    <details>
      <summary><b>${escape(item.filename || "Deleted file")}</b> · ${escape(formatDate(item.deletionTimestamp || item.timestamp))} · ${escape(formatDeletedSources(item))}${item.recent ? " · Recent" : ""}</summary>
      <p>Original path: ${escape(item.originalPath || item.path || "Unavailable")}</p>
      <p>MFT record: ${escape(item.mftRecordNumber || "Unavailable")} · USN: ${escape(item.usn || "Unavailable")}</p>
      <p>USN reason: ${escape(item.usnReason || "Unavailable")} · Size: ${escape(formatFileSize(item.fileSize))}</p>
      <p>Created: ${escape(formatDate(item.created))} · Modified: ${escape(formatDate(item.modified))} · Accessed: ${escape(formatDate(item.accessed))}</p>
      <p>Source export: ${escape(item.sourceExport || "Unavailable")}</p>
      ${item.metadata ? `<pre>${escape(JSON.stringify(item.metadata, null, 2))}</pre>` : ""}
    </details>
  `)).join("");
  const prefetchArtifacts = (data.keyArtifacts || []).filter(isPrefetchArtifact);
  const prefetchRow = (item: KeyArtifact) => entry(item.timestamp, `
    <p><b>PREFETCH FILE</b> · ${escape(formatDate(item.timestamp))}</p>
    <p>${escape(artifactText(item))}</p>
    ${item.path ? `<p>${escape(item.path)}</p>` : ""}
    <p>${escape(item.source || "Prefetch")} · ${escape(item.confidence || "Review")}</p>
  `);
  const prefetchPreviewRows = prefetchArtifacts.slice(0, 6).map(prefetchRow).join("");
  const prefetchAllRows = prefetchArtifacts.map(prefetchRow).join("");
  const macContext = data.systemContext || {};
  const macEvidenceRows = Object.entries(data.evidenceSources || {}).map(([source, value]) =>
    `<div class="report-entry"><b>${escape(source)}</b><span style="float:right">${escape(formatEvidenceValue(value))}</span></div>`
  ).join("");
  const sidePanel = isMac
    ? `<section><h2>macOS System</h2><p>Version: ${escape(macContext.productVersion || data.platformVersion || "Unavailable")}</p><p>Build: ${escape(macContext.buildVersion || "Unavailable")}</p><p>Architecture: ${escape(macContext.architecture || "Unavailable")}</p><p>Scanner: ${escape(data.scannerVersion || "Mac alpha")}</p><p>Profile: ${escape(data.scanProfile || "Unknown")}</p></section><section><h2>Mac Evidence Coverage</h2>${macEvidenceRows || "<p>No coverage data included.</p>"}</section><section><h2>Mac Coverage Limits</h2>${(data.limitations || []).map((item) => `<p>${escape(item)}</p>`).join("") || "<p>No limitations reported.</p>"}</section>`
    : `<section><h2>Factory Reset Information</h2><p>Install records may represent a reset, reinstall, or major Windows upgrade.</p>${installHistory || resetHistory || "<p>No Windows installation records available.</p>"}</section><section><h2>Services</h2><p><b>${escape(sysMain.serviceName || "SysMain")}</b></p><p>Current State: ${escape(sysMain.currentState || "Unavailable")}</p><p>Startup Type: ${escape(sysMain.startupType || "Unavailable")}</p><p>Last Changed: ${escape(sysMain.lastChanged || "Could not determine")}</p></section><section><h2>Defender Exclusions</h2><p>Configured AV exclusions. Review entries can hide executor folders from Defender.</p>${defenderExclusionRows || "<p>No Defender exclusions were found or accessible.</p>"}</section><section><h2>Forensic Artifacts</h2><p>Compact parser evidence counts. Detailed sections are shown below.</p><div class="mini-grid">${forensicCards}</div></section>`;
  const platformArtifactSections = isMac ? "" : `
    <section><h2>Prefetch Artifacts</h2><p>Execution-history Prefetch entries collected by Securo and parser exports. These are review signals unless paired with stronger evidence.</p>${prefetchPreviewRows || "<p>No Prefetch artifacts were included in this report.</p>"}${prefetchArtifacts.length > 6 ? `<details><summary>Show all ${prefetchArtifacts.length} Prefetch artifacts</summary>${prefetchAllRows}</details>` : ""}</section>
    <section><h2>Deleted File Artifacts</h2><p>Merged deleted-file evidence from MFTECmd, JLECmd/LECmd, Recycle Bin, USN Journal, and recovery metadata when available.</p>${deletedFileRows || "<p>No deleted-file artifacts were found in this report.</p>"}</section>`;

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
      .mini-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
      .mini-card{border:1px solid #264234;border-radius:8px;padding:10px;background:rgba(0,0,0,.22)}
      .mini-card small{display:block;color:#8b93a7}.mini-card b{font-size:22px}
      @media(max-width:720px){.timeline-entry,.timeline-reset-grid{grid-template-columns:1fr}.timeline-source{white-space:normal}}
    </style>
    </head><body>
    <h1>Securo Report</h1>
    <section><p>Platform: ${isMac ? "macOS" : "Windows"}</p><p>Host: ${escape(report.hostname)}</p><p>Risk: ${escape(report.risk_level)}</p><p>Score: ${report.evidence_score}</p><p>Scan: ${escape(data.scanTime)}</p></section>
    <div class="timeline-reset-grid"><section><h2>Timeline</h2>${data.timeline.map((event) => entry(event.time, `<div class="timeline-entry"><time>${escape(formatDate(event.time))}</time><div class="timeline-message">${escape(event.text || "")}</div><small class="timeline-source">${escape(event.source || "")}</small></div>`)).join("") || "<p>No timeline entries.</p>"}</section><aside>${sidePanel}</aside></div>
    ${platformArtifactSections}
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

