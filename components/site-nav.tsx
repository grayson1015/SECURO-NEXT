"use client";

import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

const links = [
  { label: "Home", href: "/" },
  { label: "Features", href: "/features" },
  { label: "Download", href: "/download" },
  { label: "Terms", href: "/terms" },
  { label: "Privacy", href: "/privacy" },
  { label: "Dashboard", href: "/dashboard", accent: true }
];

export function SiteNav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 10);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className={cn("sticky top-0 z-40 transition-all duration-300", scrolled ? "border-b border-white/10 bg-[#07090d]/78 shadow-2xl shadow-black/30 backdrop-blur-xl" : "bg-transparent")}>
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
        <Link href="/" className="group flex items-center gap-3 text-lg font-bold">
          <span className="rounded-md border border-primary/20 bg-primary/15 p-2 text-primary shadow-lg shadow-primary/10 transition duration-300 group-hover:scale-105 group-hover:bg-primary/20 group-hover:shadow-primary/25"><ShieldCheck size={22} /></span>
          Securo
        </Link>
        <div className="hidden items-center gap-1 rounded-full border border-white/10 bg-white/[.035] p-1 text-sm text-zinc-300 shadow-2xl shadow-black/20 backdrop-blur md:flex">
          {links.map((link) => (
            <Link
              key={link.href}
              className={cn(
                "rounded-full px-4 py-2 transition duration-300 hover:bg-white/[.06] hover:text-white",
                link.accent ? "text-primary hover:text-primary" : ""
              )}
              href={link.href}
            >
              {link.label}
            </Link>
          ))}
        </div>
      </nav>
    </div>
  );
}
