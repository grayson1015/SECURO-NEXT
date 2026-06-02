import Link from "next/link";
import { ShieldCheck } from "lucide-react";

const links = [
  { label: "Home", href: "/" },
  { label: "Features", href: "/features" },
  { label: "Download", href: "/download" },
  { label: "Terms", href: "/terms" },
  { label: "Privacy", href: "/privacy" },
  { label: "Dashboard", href: "/dashboard", accent: true }
];

export function SiteNav() {
  return (
    <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
      <Link href="/" className="flex items-center gap-3 text-lg font-bold">
        <span className="rounded-md bg-primary/15 p-2 text-primary"><ShieldCheck size={22} /></span>
        Securo
      </Link>
      <div className="hidden items-center gap-6 text-sm text-zinc-300 md:flex">
        {links.map((link) => (
          <Link key={link.href} className={link.accent ? "text-primary" : "hover:text-white"} href={link.href}>
            {link.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
