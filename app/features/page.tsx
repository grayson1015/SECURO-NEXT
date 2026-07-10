import { Activity, BadgeCheck, Cpu, FileSearch, Fingerprint, ShieldAlert } from "lucide-react";
import { Card, CardTitle } from "@/components/ui/card";
import { PageTransition, Reveal, Stagger, StaggerItem } from "@/components/motion-shell";
import { SiteNav } from "@/components/site-nav";

const features = [
  { title: "System & Hardware", text: "Records safe system context to help moderators understand the environment around a scan.", icon: Cpu },
  { title: "Roblox Logs", text: "Extracts account, place, job, launch, exit, crash, and configuration evidence from Roblox logs.", icon: FileSearch },
  { title: "Sessions", text: "Deduplicates Roblox sessions and correlates nearby file, process, Defender, and browser artifacts.", icon: Activity },
  { title: "Pins & Results", text: "Approved moderators create short-lived PINs and receive reports after user consent.", icon: Fingerprint },
  { title: "Detection Categories", text: "Shows confirmed, suspicious, and weak evidence with scoring and reasoning.", icon: BadgeCheck },
  { title: "Evidence Limits", text: "Clearly shows missing telemetry instead of calling a machine clean without enough proof.", icon: ShieldAlert }
];

export default function FeaturesPage() {
  return (
    <PageTransition backgroundVariant="features">
      <SiteNav />
      <section className="mx-auto max-w-7xl px-6 py-14">
        <Reveal>
          <p className="text-sm font-semibold text-primary">Features</p>
          <h1 className="mt-3 max-w-3xl text-5xl font-bold">Roblox-focused evidence, organized for moderator review</h1>
          <p className="mt-5 max-w-3xl leading-7 text-zinc-300">
            Securo keeps checks consent-based and read-only while presenting logs, sessions, findings, limitations, and upload status in one private dashboard.
          </p>
        </Reveal>
        <Stagger className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => {
            const Icon = feature.icon;
            return (
              <StaggerItem key={feature.title}>
              <Card className="min-h-52">
                <Icon className="text-primary" />
                <CardTitle className="mt-5 text-base text-white">{feature.title}</CardTitle>
                <p className="mt-3 text-sm leading-6 text-zinc-400">{feature.text}</p>
              </Card>
              </StaggerItem>
            );
          })}
        </Stagger>
      </section>
    </PageTransition>
  );
}
