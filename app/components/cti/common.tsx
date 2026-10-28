"use client";

import { useCallback, useEffect, useState } from "react";

/** Chargement JSON avec rafraîchissement périodique optionnel. */
export function useJson<T>(url: string | null, refreshMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(Boolean(url));
  const load = useCallback(async () => {
    if (!url) return;
    setLoading(true);
    try {
      const r = await fetch(url, { cache: "no-store" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setData(j as T);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Données indisponibles");
    } finally {
      setLoading(false);
    }
  }, [url]);
  useEffect(() => {
    load();
    if (!refreshMs) return;
    const id = setInterval(() => document.visibilityState === "visible" && load(), refreshMs);
    return () => clearInterval(id);
  }, [load, refreshMs]);
  return { data, error, loading, reload: load, setData };
}

export const fmtInt = (n: number) => n.toLocaleString("fr-FR");

export function Kpi({ k, v, n }: { k: string; v: string | number; n?: string }) {
  return (
    <div className="tile">
      <span className="tile-k">{k}</span>
      <span className="tile-v">{v}</span>
      {n && <span className="tile-n">{n}</span>}
    </div>
  );
}

export function BarList({ rows, label, onPick, active }: { rows: { key: string; count: number }[]; label?: (k: string) => string; onPick?: (k: string) => void; active?: string }) {
  const max = rows[0]?.count ?? 1;
  return (
    <ol className="tm-list tm-list-compact">
      {rows.map((r) => (
        <li key={r.key}>
          {onPick ? (
            <button type="button" className={`tm-cc${active === r.key ? " is-active" : ""}`} onClick={() => onPick(active === r.key ? "" : r.key)}>
              {label ? label(r.key) : r.key}
            </button>
          ) : (
            <span className="tm-cc">{label ? label(r.key) : r.key}</span>
          )}
          <span className="tm-bar">
            <span style={{ width: `${Math.max(4, (r.count / max) * 100)}%` }} className="tm-fill-L7" />
          </span>
          <span className="tm-val">{r.count}</span>
        </li>
      ))}
    </ol>
  );
}

export function Skeleton() {
  return (
    <div className="skeleton" aria-busy="true" aria-label="Chargement">
      <span />
      <span />
      <span />
    </div>
  );
}
