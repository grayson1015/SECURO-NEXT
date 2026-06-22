"use client";

import { useEffect, useState } from "react";
import type { PinRow, ReportRow } from "@/lib/types";
import { Dashboard } from "@/components/dashboard";
import { LoginPanel } from "@/components/login-panel";

const defaultReportDays = 7;

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [activated, setActivated] = useState(false);
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [pins, setPins] = useState<PinRow[]>([]);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const session = await fetchJsonWithTimeout("/api/key-session", 10000);
        if (cancelled) return;
        if (!session?.ok) {
          setActivated(false);
          return;
        }

        setActivated(true);
        const [reportsResult, pinsResult] = await Promise.all([
          fetchJsonWithTimeout(`/api/reports?days=${defaultReportDays}`, 15000),
          fetchJsonWithTimeout("/api/pins", 15000)
        ]);
        if (cancelled) return;
        setReports((reportsResult?.reports || []) as ReportRow[]);
        setPins((pinsResult?.pins || []) as PinRow[]);
        if (!reportsResult?.ok) setLoadError(reportsResult?.error || "Reports could not load.");
      } catch (error) {
        if (!cancelled) {
          setActivated(true);
          setLoadError(error instanceof Error ? error.message : "Dashboard could not load.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <main className="flex min-h-screen items-center justify-center text-zinc-400">Loading Securo...</main>;
  if (!activated) {
    return <LoginPanel />;
  }
  return <Dashboard initialReports={reports} initialPins={pins} initialLoadError={loadError} />;
}

async function fetchJsonWithTimeout(url: string, timeoutMs: number) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    return await response.json().catch(() => ({ ok: false, error: `Bad response from ${url}` }));
  } finally {
    window.clearTimeout(timer);
  }
}
