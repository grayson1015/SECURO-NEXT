"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { AnimatedBackground, Reveal } from "@/components/motion-shell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export function LoginPanel() {
  const [email, setEmail] = useState("");
  const [key, setKey] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function continueWithKey() {
    const cleanEmail = email.trim().toLowerCase();
    const cleanKey = key.trim().toUpperCase();

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleanEmail)) {
      setMessage("Enter a valid email.");
      return;
    }

    try {
      setBusy(true);
      setMessage("Checking access key...");

      const res = await fetch("/api/key-login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: cleanEmail,
          key: cleanKey,
        }),
      });

      const text = await res.text();

      let body: any = {
        ok: false,
        error: "empty_server_response",
      };

      if (text) {
        try {
          body = JSON.parse(text);
        } catch (err) {
          console.error("JSON parse error:", err);
          console.error("Response text:", text);

          setBusy(false);
          setMessage("Server returned invalid JSON");
          return;
        }
      }

      setBusy(false);

      if (!res.ok || !body.ok) {
        setMessage(body.error || "invalid_email_or_key");
        return;
      }

      window.location.href = "/dashboard";
    } catch (err) {
      console.error(err);
      setBusy(false);
      setMessage("Network or server error");
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <AnimatedBackground variant="auth" />
      <Reveal className="relative z-10 w-full max-w-md">
      <Card className="premium-panel w-full">
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-md border border-primary/20 bg-primary/15 p-2 text-primary shadow-lg shadow-primary/10">
            <ShieldCheck size={26} />
          </div>

          <div>
            <h1 className="text-2xl font-bold">Securo</h1>
            <p className="text-sm text-zinc-400">
              Moderator access
            </p>
          </div>
        </div>

        <div className="space-y-3">
          <Input
            placeholder="Email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />

          <Input
            placeholder="Access Key"
            className="uppercase tracking-widest"
            value={key}
            onChange={(event) =>
              setKey(event.target.value.toUpperCase())
            }
          />

          <Button
            onClick={continueWithKey}
            className="w-full"
            disabled={busy}
          >
            {busy ? "Checking..." : "Continue"}
          </Button>

          <p className="text-xs leading-5 text-zinc-500">
            Access is controlled by your email and Securo invite key. Business licenses can be shared by up to 20 approved emails.
          </p>

          {message ? (
            <p className="text-sm text-zinc-400">
              {message}
            </p>
          ) : null}
        </div>
      </Card>
      </Reveal>
    </main>
  );
}
