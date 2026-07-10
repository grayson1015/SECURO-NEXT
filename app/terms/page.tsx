import Link from "next/link";
import { PageTransition, Reveal } from "@/components/motion-shell";
import { SiteNav } from "@/components/site-nav";

export default function TermsPage() {
  return (
    <PageTransition backgroundVariant="legal">
      <SiteNav />
      <Reveal className="mx-auto flex max-w-3xl flex-col justify-center px-6 py-20">
        <Link className="mb-8 text-primary" href="/">Securo</Link>
        <h1 className="text-4xl font-bold">Terms</h1>
        <p className="mt-4 leading-7 text-zinc-300">
          Securo is intended for consent-based Roblox PC checks by activated Securo staff. Scans are read-only, reports should be reviewed responsibly, and missing telemetry must not be described as proof that a system is clean.
        </p>
      </Reveal>
    </PageTransition>
  );
}
