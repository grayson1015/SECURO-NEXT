import * as React from "react";
import { cn } from "@/lib/utils";

const styles: Record<string, string> = {
  High: "border-red-500/40 bg-red-500/15 text-red-300",
  Medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-200",
  Low: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  pending: "border-zinc-500/40 bg-zinc-500/15 text-zinc-300",
  connected: "border-blue-500/40 bg-blue-500/15 text-blue-300",
  completed: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
};

export function Badge({ label, className }: { label: string; className?: string }) {
  return (
    <span className={cn("inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold", styles[label] || styles.pending, className)}>
      {label}
    </span>
  );
}
