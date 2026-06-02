"use client";

import { LoginPanel } from "@/components/login-panel";
import { SiteNav } from "@/components/site-nav";

export default function ActivatePage() {
  return (
    <main className="min-h-screen">
      <SiteNav />
      <LoginPanel />
    </main>
  );
}
