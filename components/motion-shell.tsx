"use client";

import { motion } from "framer-motion";
import * as React from "react";
import { cn } from "@/lib/utils";

const fadeUp = {
  hidden: { opacity: 0, y: 24, filter: "blur(8px)" },
  show: { opacity: 1, y: 0, filter: "blur(0px)" }
};

type BackgroundVariant = "landing" | "features" | "download" | "dashboard" | "report" | "auth" | "legal";

const variantClasses: Record<BackgroundVariant, { beam: string; pattern: string; orb: string; detail: string }> = {
  landing: {
    beam: "left-[-12vw] top-[-12vh] h-[120vh] w-[18vw] -rotate-[28deg] bg-primary/28",
    pattern: "left-[-18vw] top-[18vh] h-[78vh] w-[76vw] bg-[repeating-radial-gradient(ellipse_at_20%_55%,transparent_0_13px,rgba(0,255,106,.34)_14px_15px)] opacity-[.52]",
    orb: "left-[28vw] top-[22vh] h-[30vmax] w-[30vmax] bg-primary/35",
    detail: "right-[22vw] top-[14vh] h-[58vmin] w-[58vmin] rounded-full border border-white/30 opacity-50"
  },
  features: {
    beam: "left-[8vw] top-[-10vh] h-[120vh] w-[13vw] -rotate-[31deg] bg-primary/22",
    pattern: "left-[4vw] bottom-[-20vh] h-[72vh] w-[70vw] bg-[repeating-radial-gradient(ellipse_at_24%_68%,transparent_0_12px,rgba(0,255,106,.28)_13px_14px)] opacity-[.42]",
    orb: "right-[10vw] top-[10vh] h-[26vmax] w-[26vmax] bg-primary/28",
    detail: "right-[8vw] top-[18vh] h-[40vh] w-[34vw] bg-[radial-gradient(circle,rgba(0,255,106,.7)_1px,transparent_2px)] bg-[size:22px_22px] opacity-45"
  },
  download: {
    beam: "left-[1vw] top-[5vh] h-[112vh] w-[11vw] -rotate-[29deg] bg-primary/24",
    pattern: "right-[-22vw] top-[2vh] h-[94vh] w-[74vw] bg-[repeating-radial-gradient(ellipse_at_75%_35%,transparent_0_14px,rgba(0,255,106,.30)_15px_16px)] opacity-[.48]",
    orb: "left-[12vw] bottom-[2vh] h-[20vmax] w-[20vmax] bg-emerald-400/24",
    detail: "right-[20vw] bottom-[8vh] h-[42vmin] w-[42vmin] rounded-full border border-primary/40 opacity-60"
  },
  dashboard: {
    beam: "right-[4vw] top-[-8vh] h-[118vh] w-[10vw] rotate-[31deg] bg-primary/18",
    pattern: "right-[3vw] top-[12vh] h-[72vh] w-[45vw] bg-[radial-gradient(circle,rgba(0,255,106,.58)_1px,transparent_2px)] bg-[size:20px_20px] opacity-[.32]",
    orb: "left-[8vw] top-[18vh] h-[24vmax] w-[24vmax] bg-primary/18",
    detail: "left-[-12vw] bottom-[-18vh] h-[62vh] w-[70vw] bg-[repeating-radial-gradient(ellipse_at_32%_56%,transparent_0_16px,rgba(0,255,106,.22)_17px_18px)] opacity-[.34]"
  },
  report: {
    beam: "left-[0vw] top-[-12vh] h-[125vh] w-[12vw] -rotate-[24deg] bg-primary/18",
    pattern: "left-[-20vw] top-[8vh] h-[80vh] w-[62vw] bg-[repeating-radial-gradient(ellipse_at_35%_50%,transparent_0_13px,rgba(0,255,106,.27)_14px_15px)] opacity-[.36]",
    orb: "right-[14vw] top-[12vh] h-[22vmax] w-[22vmax] bg-primary/22",
    detail: "right-[12vw] top-[18vh] h-[48vmin] w-[48vmin] rounded-full border border-white/25 opacity-45"
  },
  auth: {
    beam: "left-[12vw] top-[-20vh] h-[130vh] w-[14vw] -rotate-[32deg] bg-primary/24",
    pattern: "left-[10vw] bottom-[-16vh] h-[58vh] w-[70vw] bg-[repeating-radial-gradient(ellipse_at_48%_70%,transparent_0_12px,rgba(0,255,106,.24)_13px_14px)] opacity-[.36]",
    orb: "right-[18vw] top-[18vh] h-[26vmax] w-[26vmax] bg-primary/28",
    detail: "right-[10vw] bottom-[12vh] h-[36vmin] w-[36vmin] rounded-full border border-primary/35 opacity-50"
  },
  legal: {
    beam: "right-[8vw] top-[-10vh] h-[110vh] w-[10vw] rotate-[26deg] bg-primary/16",
    pattern: "right-[-26vw] top-[8vh] h-[78vh] w-[72vw] bg-[repeating-radial-gradient(ellipse_at_72%_42%,transparent_0_15px,rgba(0,255,106,.22)_16px_17px)] opacity-[.34]",
    orb: "left-[12vw] top-[18vh] h-[22vmax] w-[22vmax] bg-primary/18",
    detail: "left-[5vw] bottom-[10vh] h-[30vh] w-[44vw] bg-[radial-gradient(circle,rgba(0,255,106,.45)_1px,transparent_2px)] bg-[size:24px_24px] opacity-25"
  }
};

export function AnimatedBackground({ variant = "landing" }: { variant?: BackgroundVariant }) {
  const styles = variantClasses[variant];
  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden bg-[#030507]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_52%_0%,rgba(0,210,106,.16),transparent_35rem),linear-gradient(180deg,rgba(3,5,7,.50),rgba(3,5,7,.96))]" />
      <motion.div
        className={cn("absolute blur-xl", styles.pattern)}
        animate={{ x: [0, 18, -8, 0], y: [0, -14, 10, 0], opacity: [0.32, 0.58, 0.42, 0.32] }}
        transition={{ duration: 26, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className={cn("absolute rounded-full blur-[90px]", styles.orb)}
        animate={{ x: [0, 48, 12, 0], y: [0, 18, 56, 0], opacity: [0.38, 0.62, 0.42, 0.38] }}
        transition={{ duration: 18, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className={cn("absolute blur-2xl", styles.beam)}
        animate={{ x: [0, 16, -6, 0], opacity: [0.5, 0.82, 0.62, 0.5] }}
        transition={{ duration: 20, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className={cn("absolute", styles.detail)}
        animate={{ scale: [1, 1.04, 1], opacity: [0.28, 0.55, 0.28] }}
        transition={{ duration: 19, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="absolute right-[-10rem] top-[18rem] h-[28rem] w-[28rem] rounded-full bg-emerald-400/10 blur-[110px]"
        animate={{ x: [0, -38, -12, 0], y: [0, 48, 18, 0], opacity: [0.22, 0.46, 0.32, 0.22] }}
        transition={{ duration: 22, repeat: Infinity, ease: "easeInOut" }}
      />
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,.028)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.018)_1px,transparent_1px)] bg-[size:72px_72px] opacity-[.12]" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_0,rgba(0,0,0,.38)_72%),linear-gradient(90deg,rgba(0,0,0,.52),transparent_42%,rgba(0,0,0,.72))]" />
    </div>
  );
}

export function PageTransition({ children, className, backgroundVariant = "landing" }: { children: React.ReactNode; className?: string; backgroundVariant?: BackgroundVariant }) {
  return (
    <motion.main
      className={cn("relative isolate min-h-screen overflow-hidden bg-transparent", className)}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
    >
      <AnimatedBackground variant={backgroundVariant} />
      <div className="relative z-10">{children}</div>
    </motion.main>
  );
}

export function Reveal({ children, className, delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) {
  return (
    <motion.div
      className={className}
      variants={fadeUp}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.62, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

export function Stagger({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      className={className}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-80px" }}
      variants={{ hidden: {}, show: { transition: { staggerChildren: 0.075 } } }}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      className={className}
      variants={fadeUp}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}
