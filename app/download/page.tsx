import { Download } from "lucide-react";
import { PageTransition, Reveal } from "@/components/motion-shell";
import { SecuroLogo } from "@/components/securo-logo";
import { SiteNav } from "@/components/site-nav";
import { Card } from "@/components/ui/card";

export default function DownloadPage() {
  return (
    <PageTransition backgroundVariant="download">
      <SiteNav />
      <section className="mx-auto max-w-5xl px-6 py-14">
        <Reveal>
          <p className="text-sm font-semibold text-primary">Download</p>
          <h1 className="mt-3 text-5xl font-bold">Securo desktop checker</h1>
          <p className="mt-5 max-w-3xl leading-7 text-zinc-300">
            Download the GUI checker used for PIN-based Securo scans. The checker runs locally, asks consent before upload, and keeps a local report if upload fails.
          </p>
        </Reveal>
        <Reveal delay={0.08}>
        <Card className="premium-panel mt-8">
          <div className="flex flex-wrap items-center justify-between gap-5">
            <div className="flex items-center gap-4">
              <SecuroLogo size={48} />
              <div>
                <h2 className="text-xl font-bold">Securo.zip</h2>
                <p className="mt-1 text-sm text-zinc-400">Portable Windows folder with Securo.exe and forensic helper tools. No Python install required.</p>
              </div>
            </div>
            <a className="inline-flex h-11 items-center justify-center gap-2 rounded-md bg-primary px-5 text-sm font-semibold text-black shadow-lg shadow-primary/20 transition duration-300 hover:-translate-y-0.5 hover:shadow-primary/35 hover:brightness-110 active:scale-[.98]" href="/downloads/Securo.zip" download>
              <Download size={18} /> Download
            </a>
          </div>
        </Card>
        </Reveal>
        <Reveal delay={0.14} className="mt-6 rounded-xl border border-white/10 bg-card/75 p-5 text-sm leading-6 text-zinc-400 shadow-2xl shadow-black/20 backdrop-blur">
          Securo scans are consent-based and read-only. The checker must not collect credentials, cookies, tokens, passwords, private messages, or add stealth, persistence, bypasses, or hidden behavior.
        </Reveal>
      </section>
    </PageTransition>
  );
}
