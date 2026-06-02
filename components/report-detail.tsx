"use client";

import Link from "next/link";
import { ArrowLeft, Download } from "lucide-react";
import type { ReportRow } from "@/lib/types";
import { countFindings } from "@/lib/report";
import { formatDate } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle, CardValue } from "@/components/ui/card";

export function ReportDetail({ report }: { report: ReportRow }) {
  const data = report.report_json;
  const primary = data.sessions[0] || {};
  const detectionFindings = data.findings.filter((finding) => (finding.detections || []).length || (finding.detectionCategories || []).length);

  function exportHtml() {
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Securo Report</title>
    <style>body{font-family:Segoe UI,Arial;background:#07100b;color:#eefaf1;padding:24px}section{border:1px solid #264234;border-radius:8px;padding:16px;margin:12px 0}pre{white-space:pre-wrap;background:#050807;padding:12px;border-radius:8px}</style>
    </head><body><h1>Securo Report</h1><section><p>Host: ${escape(report.hostname)}</p><p>Risk: ${escape(report.risk_level)}</p><p>Score: ${report.evidence_score}</p><p>Scan: ${escape(data.scanTime)}</p></section>
    <section><h2>Findings</h2>${data.findings.map((f) => `<p><b>${escape(f.name || "Finding")}</b> ${escape(f.classification || f.category || "")} ${Number(f.score || 0)}</p>`).join("")}</section>
    <section><h2>Raw report</h2><pre>${escape(JSON.stringify(data, null, 2))}</pre></section></body></html>`;
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `securo-report-${report.hostname}-${report.id}.html`;
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
          <Card><CardTitle>Hostname</CardTitle><CardValue>{report.hostname}</CardValue></Card>
          <Card><CardTitle>Risk level</CardTitle><div className="mt-3"><Badge label={report.risk_level} /></div></Card>
          <Card><CardTitle>Evidence score</CardTitle><CardValue>{report.evidence_score}</CardValue></Card>
        </section>

        <Card className="mt-5 border-primary/40 bg-primary/10">
          <h2 className="mb-3 text-lg font-semibold">Summary</h2>
          <div className="grid gap-3 md:grid-cols-5">
            <Summary label="User" value={primary.username || "Unknown"} />
            <Summary label="User ID" value={primary.userId || ""} />
            <Summary label="Place ID" value={primary.placeId || primary.gameId || ""} />
            <Summary label="Risk Level" value={report.risk_level} />
            <Summary label="Injection Evidence" value={data.highestResult || "Not confirmed"} />
          </div>
        </Card>

        <section className="mt-5 grid gap-4 md:grid-cols-3">
          <Card><CardTitle>Confirmed</CardTitle><CardValue>{countFindings(data, "Confirmed")}</CardValue></Card>
          <Card><CardTitle>Likely</CardTitle><CardValue>{countFindings(data, "Suspicious")}</CardValue></Card>
          <Card><CardTitle>Possible</CardTitle><CardValue>{countFindings(data, "Weak")}</CardValue></Card>
        </section>

        <Card className="mt-5">
          <h2 className="mb-4 text-lg font-semibold">Findings</h2>
          <div className="mb-4 space-y-3">
            {detectionFindings.map((finding, index) => (
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
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr className="border-b border-border"><th className="py-3">Name</th><th>Class</th><th>Score</th><th>Path</th></tr>
              </thead>
              <tbody>
                {data.findings.map((finding, index) => (
                  <tr key={`${finding.name}-${index}`} className="border-b border-border/70">
                    <td className="py-3 font-medium">{finding.name || "Finding"}</td>
                    <td>{finding.classification || finding.category || "Unknown"}</td>
                    <td>{Number(finding.score || 0)}</td>
                    <td className="max-w-xl truncate text-zinc-400">{finding.path || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card className="mt-5">
          <h2 className="mb-4 text-lg font-semibold">Session Information</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {data.sessions.map((session, index) => (
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

function escape(value: unknown) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[char] || char));
}
