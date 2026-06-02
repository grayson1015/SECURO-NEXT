import { Download, ShieldCheck } from "lucide-react";
import { SiteNav } from "@/components/site-nav";
import { Card } from "@/components/ui/card";

export default function DownloadPage() {
  return (
    <main className="min-h-screen">
      <SiteNav />
      <section className="mx-auto max-w-5xl px-6 py-14">
        <p className="text-sm font-semibold text-primary">Download</p>
        <h1 className="mt-3 text-5xl font-bold">Securo desktop checker</h1>
        <p className="mt-5 max-w-3xl leading-7 text-zinc-300">
          Download the GUI checker used for PIN-based Securo scans. The checker runs locally, asks consent before upload, and keeps a local report if upload fails.
        </p>
        <Card className="mt-8">
          <div className="flex flex-wrap items-center justify-between gap-5">
            <div className="flex items-center gap-4">
              <div className="rounded-md bg-primary/15 p-3 text-primary"><ShieldCheck /></div>
              <div>
                <h2 className="text-xl font-bold">SecuroChecker.exe</h2>
                <p className="mt-1 text-sm text-zinc-400">Windows GUI app. No Python install required.</p>
              </div>
            </div>
            <a className="inline-flex h-11 items-center justify-center gap-2 rounded-md bg-primary px-5 text-sm font-semibold text-black hover:brightness-110" href="/downloads/SecuroChecker.exe" download>
              <Download size={18} /> Download
            </a>
          </div>
        </Card>
        <div className="mt-6 rounded-lg border border-border bg-card p-5 text-sm leading-6 text-zinc-400">
          Securo scans are consent-based and read-only. The checker must not collect credentials, cookies, tokens, passwords, private messages, or add stealth, persistence, bypasses, or hidden behavior.
        </div>
      </section>
    </main>
  );
}
