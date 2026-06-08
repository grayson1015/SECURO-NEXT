"use client";

import { useEffect, useState } from "react";
import type { PinRow, ReportSummaryRow } from "@/lib/types";
import { Dashboard } from "@/components/dashboard";
import { LoginPanel } from "@/components/login-panel";

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [activated, setActivated] = useState(false);
  const [reports, setReports] = useState<ReportSummaryRow[]>([]);
  const [pins, setPins] = useState<PinRow[]>([]);

  useEffect(() => {
    async function load() {
      const session = await fetch("/api/key-session").then((res) => res.json()).catch(() => null);
      if (!session?.ok) {
        setActivated(false);
        setLoading(false);
        return;
      }

      setActivated(true);
      const [reportsResult, pinsResult] = await Promise.all([
        fetch("/api/reports?summary=1&limit=500").then((res) => res.json()),
        fetch("/api/pins").then((res) => res.json())
      ]);
      setReports((reportsResult.reports || []) as ReportSummaryRow[]);
      setPins((pinsResult.pins || []) as PinRow[]);
      setLoading(false);
    }
    load();
  }, []);

  if (loading) return <main className="flex min-h-screen items-center justify-center text-zinc-400">Loading Securo...</main>;
  if (!activated) {
    return <LoginPanel />;
  }
  return <Dashboard initialReports={reports} initialPins={pins} />;
}
