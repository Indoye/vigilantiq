"use client";

import { navigate } from "@/lib/nav";
import { useCallback, useEffect, useRef, useState } from "react";

export type CveStatusValue = "a_traiter" | "en_cours" | "traitee" | "non_concernee";

export const STATUS_LABEL: Record<CveStatusValue, string> = {
  a_traiter: "À traiter",
  en_cours: "En cours",
  traitee: "Traitée",
  non_concernee: "Non concernée",
};

export interface Settings {
  stack: string;
  digestEnabled: boolean;
  digestMinPriority: "urgente" | "haute" | "moyenne";
  digestStackOnly: boolean;
}

export interface Me {
  user: { id: string; name: string; email: string; image: string | null; emailVerified: boolean };
  settings: Settings;
  statuses: Record<string, CveStatusValue>;
  providers: string[];
  features: { mail: boolean; google: boolean };
}

export function isClosed(s: CveStatusValue | undefined): boolean {
  return s === "traitee" || s === "non_concernee";
}

// Les changements s'affichent tout de suite, puis sont enregistrés en base ; en cas d'échec ils sont annulés.
const GUEST_KEY = "vq-guest-statuses";

export function readGuestStatuses(): Record<string, CveStatusValue> {
  try {
    const raw = JSON.parse(localStorage.getItem(GUEST_KEY) ?? "{}");
    return raw && typeof raw === "object" ? raw : {};
  } catch {
    return {};
  }
}

export function writeGuestStatus(cveId: string, status: CveStatusValue): Record<string, CveStatusValue> {
  const next = { ...readGuestStatuses() };
  if (status === "a_traiter") delete next[cveId];
  else next[cveId] = status;
  try {
    localStorage.setItem(GUEST_KEY, JSON.stringify(next));
  } catch {
    /* stockage indisponible : le suivi vaut pour cette page */
  }
  return next;
}

/**
 * Compte de l'utilisateur connecté : profil, préférences et suivi des CVE.
 * Avec `guestOk`, un visiteur sans compte reste sur la page (mode invité) : son suivi est gardé dans ce navigateur.
 */
export function useMe(initial: Me | null = null, opts: { guestOk?: boolean } = {}) {
  const [me, setMe] = useState<Me | null>(initial);
  const [guest, setGuest] = useState(false);
  const [guestStatuses, setGuestStatuses] = useState<Record<string, CveStatusValue>>({});
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const stackTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (initial) return;
    let alive = true;
    fetch("/api/me", { cache: "no-store" })
      .then(async (r) => {
        if (r.status === 401) {
          if (opts.guestOk) {
            if (alive) {
              setGuest(true);
              setGuestStatuses(readGuestStatuses());
            }
            return;
          }
          navigate(`/connexion?suite=${encodeURIComponent(window.location.pathname)}`);
          return;
        }
        if (!r.ok) throw new Error(`Erreur ${r.status}`);
        const j = (await r.json()) as Me;
        if (alive) setMe(j);
      })
      .catch(() => alive && setError("Impossible de charger votre compte. Rechargez la page."));
    return () => {
      alive = false;
    };
  }, [initial, opts.guestOk]);

  const setStatus = useCallback(async (cveId: string, status: CveStatusValue) => {
    if (guest) {
      setGuestStatuses(writeGuestStatus(cveId, status));
      return;
    }
    let previous: CveStatusValue | undefined;
    setMe((m) => {
      if (!m) return m;
      previous = m.statuses[cveId];
      const statuses = { ...m.statuses };
      if (status === "a_traiter") delete statuses[cveId];
      else statuses[cveId] = status;
      return { ...m, statuses };
    });
    try {
      const r = await fetch("/api/me/status", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cveId, status }),
      });
      if (!r.ok) throw new Error();
      setError(null);
    } catch {
      setMe((m) => {
        if (!m) return m;
        const statuses = { ...m.statuses };
        if (previous) statuses[cveId] = previous;
        else delete statuses[cveId];
        return { ...m, statuses };
      });
      setError("Le suivi n’a pas été enregistré. Vérifiez votre connexion et réessayez.");
    }
  }, [guest]);

  const pushSettings = useCallback(async (patch: Partial<Settings>) => {
    setSaving(true);
    try {
      const r = await fetch("/api/me/settings", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!r.ok) throw new Error();
      setError(null);
    } catch {
      setError("Vos préférences n’ont pas été enregistrées. Réessayez.");
    } finally {
      setSaving(false);
    }
  }, []);

  /** La stack est enregistrée 600 ms après la dernière frappe ; le reste immédiatement. */
  const saveSettings = useCallback(
    (patch: Partial<Settings>) => {
      setMe((m) => (m ? { ...m, settings: { ...m.settings, ...patch } } : m));
      if ("stack" in patch && Object.keys(patch).length === 1) {
        if (stackTimer.current) clearTimeout(stackTimer.current);
        stackTimer.current = setTimeout(() => pushSettings(patch), 600);
      } else {
        void pushSettings(patch);
      }
    },
    [pushSettings],
  );

  const statuses = me?.statuses ?? guestStatuses;
  return { me, setMe, guest, statuses, error, saving, setStatus, saveSettings };
}

export function initials(name: string, email: string): string {
  const src = name?.trim() || email;
  const parts = src.split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}
