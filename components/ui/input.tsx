import * as React from "react";
import { cn } from "@/lib/utils";

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-10 w-full rounded-md border border-border bg-black/30 px-3 text-sm text-white outline-none ring-primary/40 placeholder:text-zinc-500 focus:ring-2",
        className
      )}
      {...props}
    />
  );
}
