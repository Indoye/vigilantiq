"use client";

import { useState } from "react";
import type { CveDetail } from "@/lib/types";
import CveDetailView from "./CveDetailView";
import type { CveStatusValue } from "./useMe";

export default function CveStandalone({ detail, initialStatus, guest = false }: { detail: CveDetail; initialStatus: CveStatusValue; guest?: boolean }) {
  const [status, setStatus] = useState<CveStatusValue>(initialStatus);
  const [err, setErr] = useState<string | null>(null);

  const change = async (s: CveStatusValue) => {
    if (guest) return; // lecture seule sans compte
    const prev = status;
    setStatus(s);
    const r = await fetch("/api/me/status", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cveId: detail.id, status: s }),
    }).catch(() => null);
    if (!r?.ok) {
      setStatus(prev);
      setErr("Le suivi n’a pas été enregistré. Réessayez.");
    } else setErr(null);
  };

  return (
    <CveDetailView
      base={detail}
      full={detail}
      error={err ?? (detail.errors.length ? `Sources partielles : ${detail.errors.join(" ; ")}` : null)}
      status={status}
      onStatus={change}
      standalone
      guest={guest}
    />
  );
}
