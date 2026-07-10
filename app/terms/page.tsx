import Link from "next/link";
import { PageTransition, Reveal } from "@/components/motion-shell";
import { SiteNav } from "@/components/site-nav";

export default function TermsPage() {
  return (
    <PageTransition backgroundVariant="legal">
      <SiteNav />
      <Reveal className="mx-auto flex max-w-4xl flex-col justify-center px-6 py-20">
        <Link className="mb-8 text-primary" href="/">Securo</Link>
        <h1 className="text-4xl font-bold">Terms</h1>
        <div className="mt-6 space-y-8 rounded-xl border border-white/10 bg-card/75 p-6 text-sm leading-7 text-zinc-300 shadow-2xl shadow-black/20 backdrop-blur">
          <section>
            <h2 className="text-xl font-semibold text-white">Purpose</h2>
            <p className="mt-3">
              Securo is intended for consent-based Roblox PC checks by activated Securo staff, moderators, league owners, and approved review teams. The purpose of Securo is to help organize local system evidence into a structured report so staff can make better moderation decisions. Securo reports are indicators for review, not automatic proof of wrongdoing.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">Consent and Local Scanning</h2>
            <p className="mt-3">
              Securo should only be used when the person being checked understands that a scan is being performed and gives permission to continue. The checker runs locally on the Windows PC being reviewed. The scan is designed to be read-only, meaning it should inspect available system metadata and report evidence without deleting, modifying, quarantining, bypassing, or injecting into anything.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">How Securo Searches</h2>
            <p className="mt-3">
              Securo may inspect local Windows metadata, application activity records, Roblox-related activity, execution traces, file timestamps, system logs, and other available forensic-style artifacts. Securo may compare timestamps, correlate activity across sources, and organize evidence into summaries, timelines, findings, limitations, and raw artifact sections.
            </p>
            <p className="mt-3">
              Securo does not publicly disclose every detection rule, search pattern, scoring rule, artifact source, or correlation method. These details are kept private to protect the integrity of checks and reduce abuse, evasion, and manipulation. Reports should still explain the evidence found in a clear way without exposing the full internal detection system.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">What Securo Will Not Search or Collect</h2>
            <p className="mt-3">
              Securo must not collect passwords, browser cookies, authentication tokens, Discord tokens, Roblox cookies, saved browser sessions, private messages, direct messages, chat contents, clipboard contents, payment information, personal photos, personal documents, private files unrelated to the check, or account secrets.
            </p>
            <p className="mt-3">
              Securo must not attempt to log into accounts, take over accounts, read private conversations, scrape personal communications, bypass security tools, disable antivirus, install persistence, hide itself, monitor users after the scan, remotely control the computer, or upload raw private files.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">Reports and Uploads</h2>
            <p className="mt-3">
              Reports may be uploaded to the Securo dashboard only for the moderator or staff account that created the check session. A report may include scan time, hostname, evidence scores, risk summaries, account/session indicators, timeline entries, findings, limitations, and artifact metadata. If upload fails, the checker should keep a local report so the scan is not lost.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">Evidence Limits</h2>
            <p className="mt-3">
              Missing evidence does not always mean nothing happened. Logs can be disabled, unavailable, expired, cleared by normal system behavior, blocked by permissions, or missing because of Windows settings. Securo should not describe a computer as clean simply because no confirmed evidence was found. The correct standard is that no confirmed evidence was found in the available data, and coverage may be limited.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">False Positives and Manual Review</h2>
            <p className="mt-3">
              Legitimate developer tools, overlays, antivirus software, virtual machines, corrupt installs, normal Windows behavior, game launchers, accessibility tools, and trusted software can sometimes produce suspicious-looking artifacts. Findings should be reviewed by trained staff before action is taken. Securo is a review tool, not a replacement for judgment.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white">Staff Responsibility</h2>
            <p className="mt-3">
              Staff using Securo are responsible for using reports fairly, protecting user privacy, avoiding harassment, and keeping reports limited to legitimate moderation needs. Reports should not be shared publicly unless required by the league or community rules and only after removing anything unnecessary or sensitive.
            </p>
          </section>
        </div>
      </Reveal>
    </PageTransition>
  );
}
