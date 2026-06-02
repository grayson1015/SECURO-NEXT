"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { ReportRow } from "@/lib/types";
import { LoginPanel } from "@/components/login-panel";
import { ReportDetail } from "@/components/report-detail";

export default function ReportPage({ params }: { params: { id: string } }) {
  const [loading, setLoading] = useState(true);
  const [activated, setActivated] = useState(false);
  const [report, setReport] = useState<ReportRow | null>(null);

  useEffect(() => {
    async function load() {
      const session = await fetch("/api/key-session").then((res) => res.json()).catch(() => null);
      if (!session?.ok) {
        setActivated(false);
        setLoading(false);
        return;
      }

      setActivated(true);
      const reportResult = await fetch(`/api/report/${params.id}`).then((res) => res.json()).catch(() => null);
      setReport((reportResult?.report || null) as ReportRow | null);
      setLoading(false);
    }
    load();
  }, [params.id]);

  if (loading) return <main className="flex min-h-screen items-center justify-center text-zinc-400">Loading report...</main>;
  if (!activated) {
    return <LoginPanel />;
  }
  if (!report) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-3 text-zinc-400">
        <p>Report not found or access denied.</p>
        <Link className="text-primary" href="/dashboard">Back to dashboard</Link>
      </main>
    );
  }
  return <ReportDetail report={report} />;
}
