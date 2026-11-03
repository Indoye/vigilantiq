"use client";

import { useState } from "react";

export default function AcceptInvite({ token }: { token: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const accept = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await fetch("/api/invitation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      window.location.assign("/compte#organisation");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Réseau indisponible.");
      setBusy(false);
    }
  };
  return (
    <>
      {err && <p className="form-msg form-err">{err}</p>}
      <button type="button" className="btn-primary" onClick={accept} disabled={busy}>
        {busy ? "Un instant…" : "Rejoindre l’organisation"}
      </button>
    </>
  );
}
