"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Clock, Download } from "lucide-react";
import type { ReportRow, SecuroFinding } from "@/lib/types";
import { countFindings } from "@/lib/report";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, CardValue } from "@/components/ui/card";

export function ReportDetail({ report }: { report: ReportRow }) {
  const [currentReport, setCurrentReport] = useState(report);
  const [fullReportLoaded, setFullReportLoaded] = useState(false);
  const [loadingFullReport, setLoadingFullReport] = useState(false);
  const data = currentReport.report_json;
  const primary = data.sessions[0] || {};
  const [timeRange, setTimeRange] = useState("7");
  const visibleFindings = useMemo(() => data.findings.filter((finding) => !isSecuroSuppressedFinding(finding)), [data.findings]);
  const detectionFindings = useMemo(
    () => visibleFindings.filter((finding) => (finding.detections || []).length || (finding.detectionCategories || []).length),
    [visibleFindings]
  );
  const extraEvidence = useMemo(() => reportEvidenceGroups(data), [data]);
  const filteredTimeline = useMemo(() => filterTimedItems(data.timeline, timeRange, (item) => item.time), [data.timeline, timeRange]);
  const filteredFindings = useMemo(() => filterFindingsForPanel(visibleFindings, timeRange), [visibleFindings, timeRange]);
  const groupedFindings = useMemo(() => ({
    Confirmed: filteredFindings.filter((finding) => findingConfidence(finding) === "Confirmed"),
    Likely: filteredFindings.filter((finding) => findingConfidence(finding) === "Likely"),
    Possible: filteredFindings.filter((finding) => findingConfidence(finding) === "Possible")
  }), [filteredFindings]);
  const filteredDetections = useMemo(() => filterTimedItems(detectionFindings, timeRange, (item) => item.firstSeen), [detectionFindings, timeRange]);
  const filteredSessions = useMemo(() => filterTimedItems(data.sessions, timeRange, (item) => item.launchTime || item.exitTime), [data.sessions, timeRange]);
  const filteredRobloxLogs = useMemo(() => filterTimedItems(data.robloxLogs || [], timeRange, (item) => item.startTime || item.modifiedTime), [data.robloxLogs, timeRange]);
  const filteredFastFlags = useMemo(() => filterTimedItems(data.detectedFastFlags || [], timeRange, (item) => item.timestamp), [data.detectedFastFlags, timeRange]);
  const filteredEvidence = useMemo(
    () => extraEvidence.map((group) => ({
      ...group,
      items: filterTimedItems(group.items, timeRange, (item) => evidenceTimestamp(item))
    })),
    [extraEvidence, timeRange]
  );

  useEffect(() => {
    setCurrentReport(report);
    setFullReportLoaded(false);
    setLoadingFullReport(false);
  }, [report]);

  async function changeTimeRange(value: string) {
    setTimeRange(value);
    if ((value === "30" || value === "all") && !fullReportLoaded && !loadingFullReport) {
      setLoadingFullReport(true);
      const days = value === "all" ? 3650 : 30;
      const result = await fetch(`/api/report/${report.id}?days=${days}`).then((res) => res.json()).catch(() => null);
      if (result?.ok && result.report) {
        setCurrentReport(result.report as ReportRow);
        setFullReportLoaded(true);
      }
      setLoadingFullReport(false);
    }
  }

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
      <div className="mx-auto max-w-6xl">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
          <Link className="inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-primary" href="/dashboard">
            <ArrowLeft size={16} /> Dashboard
          </Link>
          <Button onClick={exportHtml}><Download size={16} />Export HTML</Button>
        </div>

        <section className="grid gap-4 md:grid-cols-4">
          <Card><CardTitle>Scan timestamp</CardTitle><CardValue className="text-lg">{formatDate(data.scanTime)}</CardValue></Card>
          <Card><CardTitle>Hostname</CardTitle><CardValue>{currentReport.hostname}</CardValue></Card>
          <Card><CardTitle>Risk level</CardTitle><div className="mt-3"><Badge label={currentReport.risk_level} /></div></Card>
          <Card><CardTitle>Evidence score</CardTitle><CardValue>{currentReport.evidence_score}</CardValue></Card>
        </section>

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

        <section className="mt-5 grid gap-4 md:grid-cols-3">
          <Card><CardTitle>Confirmed</CardTitle><CardValue>{countFindings(data, "Confirmed")}</CardValue></Card>
          <Card><CardTitle>Likely</CardTitle><CardValue>{countFindings(data, "Likely")}</CardValue></Card>
          <Card><CardTitle>Possible</CardTitle><CardValue>{countFindings(data, "Possible")}</CardValue></Card>
        </section>

        <Card className="mt-5 border-primary/30">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 className="flex items-center gap-2 text-lg font-semibold"><Clock size={18} className="text-primary" />Report time range</h2>
              <p className="mt-1 text-sm text-zinc-400">Filter this report's sessions, timeline, files, process activity, and evidence sections.</p>
            </div>
            <select
              className="h-10 rounded-md border border-border bg-black/30 px-3 text-sm text-white outline-none"
              value={timeRange}
              onChange={(event) => changeTimeRange(event.target.value)}
            >
              <option value="30">1 month</option>
              <option value="14">2 weeks</option>
              <option value="7">1 week</option>
              <option value="3">3 days</option>
              <option value="all">All logs</option>
            </select>
          </div>
          {loadingFullReport ? <p className="mt-3 text-sm text-primary">Loading full report history...</p> : null}
          {!fullReportLoaded && (timeRange === "30" || timeRange === "all") ? (
            <p className="mt-3 text-sm text-zinc-500">Full raw history loads only for 1 month or All logs to keep normal report viewing fast.</p>
          ) : null}
        </Card>

        <Card className="mt-5">
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
            {!filteredTimeline.length ? <p className="text-sm text-zinc-500">No timeline entries in this time range.</p> : null}
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
          <h2 className="mb-4 text-lg font-semibold">Session Information</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {filteredSessions.map((session, index) => (
              <div key={index} className={`rounded-md border p-3 text-sm ${session.status === "Suspicious" || session.status === "Confirmed" ? "border-red-500/50 bg-red-500/10 text-red-100" : "border-border bg-black/20"}`}>
                <div className="font-semibold">{session.username || "Unknown user"}</div>
                <div className="text-zinc-400">Display Name: {session.displayName || ""}</div>
                <div className="text-zinc-400">User ID: {session.userId || ""}</div>
                <div className="text-zinc-400">Place: {session.placeId || session.gameId || "Unknown"}</div>
                <div className="text-zinc-400">Job ID: {session.jobId || ""}</div>
                <div className="text-zinc-400">Duration: {session.duration || "unknown"}</div>
                <div className="text-zinc-400">Status: {session.status || "Clean"}</div>
                {(session.linkedDetections || []).map((detection, i) => (
                  <div key={i} className="mt-2 rounded bg-black/20 p-2">
                    <div>Detection: {detection.name}</div>
                    <div>Responsible file: {detection.path}</div>
                  </div>
                ))}
              </div>
            ))}
            {!filteredSessions.length ? <p className="text-sm text-zinc-500">No sessions in this time range.</p> : null}
          </div>
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
            {!filteredFastFlags.length ? <p className="text-sm text-zinc-500">No FastFlags detected in this time range.</p> : null}
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
            {!filteredRobloxLogs.length ? <p className="text-sm text-zinc-500">No Roblox logs in this time range.</p> : null}
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
                  {!group.items.length ? <p className="text-sm text-zinc-500">No entries in this time range.</p> : null}
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

type EvidenceGroup = {
  title: string;
  items: Record<string, unknown>[];
};

function filterTimedItems<T>(items: T[], range: string, getTimestamp: (item: T) => unknown) {
  if (range === "all") return items;

  const days = Number(range);
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;

  return items.filter((item) => {
    const timestamp = parseTimestamp(getTimestamp(item));
    if (!timestamp) return true;
    return timestamp.getTime() >= cutoff;
  });
}

function filterFindingsForPanel(findings: SecuroFinding[], range: string) {
  if (range === "all") return findings;
  const filtered = filterTimedItems(findings, range, (item) => item.firstSeen);
  const included = new Set(filtered);
  return findings.filter((finding) => included.has(finding) || isConfirmedFinding(finding));
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
    ["Engine Results", raw.engineResults || raw.engine_results],
    ["Detected FastFlags", raw.detectedFastFlags || raw.detected_fast_flags],
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

  return `<!doctype html><html><head><meta charset="utf-8"><title>Securo Report</title>
    <style>
      body{font-family:Segoe UI,Arial;background:#07100b;color:#eefaf1;padding:24px}
      section{border:1px solid #264234;border-radius:8px;padding:16px;margin:12px 0}
      pre{white-space:pre-wrap;word-break:break-word;background:#050807;padding:12px;border-radius:8px;max-height:420px;overflow:auto}
      table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #264234;padding:8px;text-align:left;vertical-align:top}
      .controls{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
      select{background:#050807;color:#eefaf1;border:1px solid #264234;border-radius:6px;padding:8px 10px}
      .report-entry{border-bottom:1px solid rgba(255,255,255,.08);padding:8px 0}
      .timeline-entry{display:grid;grid-template-columns:160px minmax(0,1fr) 180px;gap:16px;align-items:start;overflow:hidden}
      .timeline-message{min-width:0;overflow-wrap:anywhere;word-break:break-word;white-space:normal}
      .timeline-source{white-space:nowrap;color:#8b93a7}
      .hidden-by-time{display:none!important}
      @media(max-width:720px){.timeline-entry{grid-template-columns:1fr}.timeline-source{white-space:normal}}
    </style>
    </head><body>
    <h1>Securo Report</h1>
    <section><p>Host: ${escape(report.hostname)}</p><p>Risk: ${escape(report.risk_level)}</p><p>Score: ${report.evidence_score}</p><p>Scan: ${escape(data.scanTime)}</p></section>
    <section class="controls"><div><h2>Report Time Range</h2><p>Filter this report's evidence without rescanning.</p></div><label>Show <select id="report-time-filter"><option value="30">1 month</option><option value="14">2 weeks</option><option value="7" selected>1 week</option><option value="3">3 days</option><option value="all">All logs</option></select></label></section>
    <section><h2>Timeline</h2>${data.timeline.map((event) => entry(event.time, `<div class="timeline-entry"><time>${escape(formatDate(event.time))}</time><div class="timeline-message">${escape(event.text || "")}</div><small class="timeline-source">${escape(event.source || "")}</small></div>`)).join("") || "<p>No timeline entries.</p>"}</section>
    <section><h2>Sessions</h2>${data.sessions.map((session) => entry(session.launchTime || session.exitTime, `<p><b>${escape(session.username || "Unknown user")}</b></p><p>User ID: ${escape(session.userId || "")}</p><p>Place: ${escape(session.placeId || session.gameId || "")}</p><p>Duration: ${escape(session.duration || "unknown")}</p><p>Status: ${escape(session.status || "Clean")}</p>`)).join("") || "<p>No sessions.</p>"}</section>
    <section><h2>Detected FastFlags</h2>${fastFlags || "<p>No FastFlags detected.</p>"}</section>
    <section><h2>Show All Roblox Logs</h2>${robloxLogs || "<p>No raw Roblox logs captured.</p>"}</section>
    <section><h2>Findings</h2>${visibleFindings.map((finding) => entry(finding.firstSeen, `<p><b>${escape(finding.name || "Finding")}</b> ${escape(finding.classification || finding.category || "")} ${Number(finding.score || 0)}</p><p>${escape(finding.path || "")}</p>`, "div", isConfirmedFinding(finding))).join("") || "<p>No findings.</p>"}</section>
    ${evidence}
    <section><h2>Raw report</h2><pre>${escape(JSON.stringify(data, null, 2))}</pre></section>
    <script>
      function parseEntryTime(entry){var value=entry.getAttribute("data-timestamp");if(!value)return null;var time=Date.parse(value);return Number.isNaN(time)?null:time}
      function applyReportTimeFilter(){var select=document.getElementById("report-time-filter");var selected=select?select.value:"7";var cutoff=selected==="all"?0:Date.now()-(Number(selected)*24*60*60*1000);document.querySelectorAll(".report-entry").forEach(function(entry){var keepVisible=entry.getAttribute("data-keep-visible")==="true";var time=parseEntryTime(entry);var show=keepVisible||selected==="all"||!time||time>=cutoff;entry.classList.toggle("hidden-by-time",!show)})}
      document.getElementById("report-time-filter").addEventListener("change",applyReportTimeFilter);applyReportTimeFilter();
    </script>
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
