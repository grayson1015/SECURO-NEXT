import Link from "next/link";
import { PageTransition, Reveal } from "@/components/motion-shell";
import { SiteNav } from "@/components/site-nav";

export default function PrivacyPage() {
  return (
    <PageTransition>
      <SiteNav />
      <Reveal className="mx-auto flex max-w-3xl flex-col justify-center px-6 py-20">
        <Link className="mb-8 text-primary" href="/">Securo</Link>
        <h1 className="text-4xl font-bold">Privacy</h1>
        <p className="mt-4 leading-7 text-zinc-300">
          Securo reports are linked to the moderator who created the PIN. The checker must not upload passwords, cookies, tokens, credentials, private messages, or raw private files.
        </p>
      </Reveal>
    </PageTransition>
  );
}
