"use client";

import { useEffect, useState } from "react";
import type { CveDetail } from "@/lib/types";
import CveDetailView from "./CveDetailView";
import type { CveStatusValue } from "./useMe";

export default function CveStandalone({ detail, initialStatus, guest = false }: { detail: CveDetail; initialStatus: CveStatusValue; guest?: boolean }) {
  const [status, setStatus] = useState<CveStatusValue>(initialStatus);
  const [err, setErr] = useState<string | null>(null);
  const [view, setView] = useState<CveDetail>(detail);

  // Sans résumé IA côté serveur (visiteur), on reprend celui du flux du jour transmis par le tableau.
  useEffect(() => {
    if (detail.ai) return;
    try {
      const raw = sessionStorage.getItem(`vq-ai-${detail.id}`);
      if (raw) setView({ ...detail, ai: JSON.parse(raw) });
    } catch {
      /* stockage indisponible */
    }
  }, [detail]);

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
      base={view}
      full={view}
      error={err ?? (detail.errors.length ? `Sources partielles : ${detail.errors.join(" ; ")}` : null)}
      status={status}
      onStatus={change}
      standalone
      guest={guest}
    />
  );
}
