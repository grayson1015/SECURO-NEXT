import Link from "next/link";
import { Activity, BadgeCheck, Cpu, FileSearch, Fingerprint } from "lucide-react";
import { Card, CardTitle } from "@/components/ui/card";
import { PageTransition, Reveal, Stagger, StaggerItem } from "@/components/motion-shell";
import { SiteNav } from "@/components/site-nav";

const checks = [
  { title: "System & Hardware", text: "Captures safe machine context such as OS, host, CPU, memory, storage, GPU, and virtualization signals.", icon: Cpu },
  { title: "Roblox Logs", text: "Parses Roblox logs for account, session, place, job, launch, crash, and configuration evidence.", icon: FileSearch },
  { title: "Sessions", text: "Builds a readable timeline of Roblox play sessions and nearby suspicious activity.", icon: Activity },
  { title: "Pins & Results", text: "Moderators create short-lived PINs and receive uploaded reports after user consent.", icon: Fingerprint },
  { title: "Detection Categories", text: "Highlights injection, packed files, .NET assemblies, AutoIT/AHK, tampering, and persistence evidence.", icon: BadgeCheck }
];

export default function LandingPage() {
  return (
    <PageTransition>
      <SiteNav />

      <section className="mx-auto grid max-w-7xl gap-10 px-6 pb-14 pt-14 lg:grid-cols-[1fr_420px] lg:items-center">
        <Reveal>
          <div className="mb-5 inline-flex rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-sm text-primary shadow-lg shadow-primary/10 backdrop-blur">
            PIN-based Roblox PC checks
          </div>
          <h1 className="max-w-4xl text-5xl font-bold leading-tight text-white md:text-7xl">
            Playing Clean? Prove it.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-300">
            Securo lets approved staff create a short-lived PIN, have the desktop checker scan locally with consent, and receive a structured Roblox evidence report in a private dashboard.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a className="inline-flex h-11 items-center justify-center rounded-md bg-primary px-5 text-sm font-semibold text-black shadow-lg shadow-primary/20 transition duration-300 hover:-translate-y-0.5 hover:shadow-primary/35 hover:brightness-110 active:scale-[.98]" href="https://discord.gg/jQKua2xvC" target="_blank" rel="noreferrer">
              Join Discord
            </a>
            <Link className="inline-flex h-11 items-center justify-center rounded-md border border-white/10 bg-white/[.04] px-5 text-sm font-semibold text-white shadow-lg shadow-black/20 backdrop-blur transition duration-300 hover:-translate-y-0.5 hover:border-primary/30 hover:bg-white/[.07]" href="/dashboard">
              Dashboard
            </Link>
          </div>
        </Reveal>

        <Reveal delay={0.12} className="premium-panel securo-glow rounded-xl border border-primary/25 bg-zinc-950/72 p-6 shadow-2xl shadow-primary/10 backdrop-blur-xl">
          <p className="text-sm font-semibold text-primary">TRANSPARENT BY DESIGN</p>
          <h2 className="mt-2 text-2xl font-bold">WHAT IS SECURO?</h2>
          <div className="mt-5 space-y-4 text-sm leading-6 text-zinc-300">
            <p>
              Securo performs a read-only local audit of this Windows PC. It may inspect system metadata plus Roblox-specific logs, Roblox folder file timestamps, Roblox-related deleted-file metadata, Roblox-related shell history matches, Roblox process metadata, Roblox startup entries, and Roblox-related Windows Event Logs when available.
            </p>
            <p>
              It will NOT collect passwords, cookies, authentication tokens, browser sessions, private messages, or clipboard data. It will NOT upload data, delete files, quarantine files, bypass security tools, inject into processes, or modify Roblox.
            </p>
            <p className="border-l-2 border-primary pl-4 text-zinc-400">
              Findings are indicators only. Legitimate developer tools, overlays, antivirus software, virtual machines, corrupt installs, and normal Windows behavior can produce false positives.
            </p>
          </div>
        </Reveal>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-16">
        <Reveal className="mb-5 flex items-end justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-primary">What it checks</p>
            <h2 className="mt-2 text-3xl font-bold">Focused Roblox evidence, clear limitations</h2>
          </div>
        </Reveal>
        <Stagger className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          {checks.map((item) => {
            const Icon = item.icon;
            return (
              <StaggerItem key={item.title}>
              <Card className="min-h-56">
                <Icon className="text-primary" />
                <CardTitle className="mt-5 text-base text-white">{item.title}</CardTitle>
                <p className="mt-3 text-sm leading-6 text-zinc-400">{item.text}</p>
              </Card>
              </StaggerItem>
            );
          })}
        </Stagger>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-12">
        <Reveal className="premium-panel rounded-xl border border-white/10 bg-card/80 p-6 shadow-2xl shadow-black/20 backdrop-blur">
          <h2 className="text-xl font-bold">Download</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
            The desktop checker is distributed by Securo staff. It scans read-only, asks consent before upload, and does not collect passwords, cookies, tokens, credentials, or private messages.
          </p>
          <a className="mt-5 inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-sm font-semibold text-black shadow-lg shadow-primary/20 transition duration-300 hover:-translate-y-0.5 hover:shadow-primary/35 hover:brightness-110 active:scale-[.98]" href="/downloads/Securo.zip" download>
            Download Securo
          </a>
        </Reveal>
      </section>
    </PageTransition>
  );
}
