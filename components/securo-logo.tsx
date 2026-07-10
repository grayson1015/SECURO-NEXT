import { cn } from "@/lib/utils";

export function SecuroLogo({ className, size = 40 }: { className?: string; size?: number }) {
  return (
    <span
      className={cn("inline-flex shrink-0 items-center justify-center", className)}
      style={{ width: size, height: size }}
      aria-hidden="true"
    >
      <svg viewBox="0 0 100 100" className="h-full w-full drop-shadow-[0_0_18px_rgba(0,210,106,.28)]">
        <polygon
          points="50 4 89.8 27 89.8 73 50 96 10.2 73 10.2 27"
          className="fill-primary"
        />
        <path
          d="M36 63 H57 V50 H67 V36 H46 V49 H35 V63 Z"
          fill="#050607"
        />
      </svg>
    </span>
  );
}
