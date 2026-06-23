import Link from "next/link";
import { Activity, BadgeCheck, Cpu, FileSearch, Fingerprint } from "lucide-react";
import { Card, CardTitle } from "@/components/ui/card";
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
    <main className="min-h-screen overflow-hidden">
      <SiteNav />

      <section className="mx-auto grid max-w-7xl gap-10 px-6 pb-14 pt-14 lg:grid-cols-[1fr_420px] lg:items-center">
        <div>
          <div className="mb-5 inline-flex rounded-md border border-primary/30 bg-primary/10 px-3 py-1 text-sm text-primary">
            PIN-based Roblox PC checks
          </div>
          <h1 className="max-w-4xl text-5xl font-bold leading-tight text-white md:text-7xl">
            Roblox screenshare & detection
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-300">
            Securo lets approved staff create a short-lived PIN, have the desktop checker scan locally with consent, and receive a structured Roblox evidence report in a private dashboard.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a className="inline-flex h-11 items-center justify-center rounded-md bg-primary px-5 text-sm font-semibold text-black hover:brightness-110" href="https://discord.gg/JNW36eYC" target="_blank" rel="noreferrer">
              Join Discord
            </a>
            <Link className="inline-flex h-11 items-center justify-center rounded-md border border-border bg-zinc-900 px-5 text-sm font-semibold text-white hover:bg-zinc-800" href="/dashboard">
              Dashboard
            </Link>
          </div>
        </div>

        <div className="rounded-lg border border-primary/25 bg-zinc-950/80 p-5 shadow-2xl shadow-primary/10">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <p className="text-sm text-zinc-400">Latest risk summary</p>
              <h2 className="text-2xl font-bold">Private moderator view</h2>
            </div>
            <span className="rounded-md bg-primary/15 px-3 py-1 text-sm font-semibold text-primary">Live</span>
          </div>
          <div className="grid gap-3">
            {["Evidence score", "Roblox sessions", "Injection findings", "Coverage limits"].map((label, index) => (
              <div key={label} className="flex items-center justify-between rounded-md border border-border bg-black/25 p-4">
                <span className="text-zinc-300">{label}</span>
                <span className="font-semibold text-white">{["78", "3", "Confirmed", "Shown"][index]}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-16">
        <div className="mb-5 flex items-end justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-primary">What it checks</p>
            <h2 className="mt-2 text-3xl font-bold">Focused Roblox evidence, clear limitations</h2>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          {checks.map((item) => {
            const Icon = item.icon;
            return (
              <Card key={item.title} className="min-h-56">
                <Icon className="text-primary" />
                <CardTitle className="mt-5 text-base text-white">{item.title}</CardTitle>
                <p className="mt-3 text-sm leading-6 text-zinc-400">{item.text}</p>
              </Card>
            );
          })}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-12">
        <div className="rounded-lg border border-border bg-card p-6">
          <h2 className="text-xl font-bold">Download</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
            The desktop checker is distributed by Securo staff. It scans read-only, asks consent before upload, and does not collect passwords, cookies, tokens, credentials, or private messages.
          </p>
          <a className="mt-5 inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-sm font-semibold text-black hover:brightness-110" href="/downloads/SecuroChecker-DeepFix-625fd42e.exe" download>
            Download SecuroChecker
          </a>
        </div>
      </section>
    </main>
  );
}
