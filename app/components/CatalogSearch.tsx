"use client";

import { useEffect, useState } from "react";
import { makeDeadline } from "@/lib/deadlines";
import { DueChip } from "./DeadlinesView";

interface Hit {
  id: string;
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
}

/**
 * Résultats de recherche hors du tableau du jour : tout le catalogue CISA KEV (y compris les failles dont
 * l'échéance est dépassée depuis plus d'un mois) et, pour un identifiant exact, la fiche de n'importe quelle CVE.
 */
export default function CatalogSearch({ q, exclude, onOpen, now }: { q: string; exclude: Map<string, unknown>; onOpen: (id: string) => void; now: number }) {
  const [data, setData] = useState<{ q: string; items: Hit[]; total: number; cve: string | null; error?: string } | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    const t = setTimeout(async () => {
      try {
        const r = await fetch(`/api/recherche?q=${encodeURIComponent(q)}`, { signal: ctrl.signal });
        const j = await r.json();
        setData({ q, ...j });
      } catch {
        /* recherche abandonnée ou réseau indisponible */
      }
    }, 300);
    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  }, [q]);

  if (!data || data.q !== q) return <p className="hint">Recherche dans le catalogue CISA…</p>;
  const items = data.items.filter((i) => !exclude.has(i.id));
  const cveOutside = data.cve && !exclude.has(data.cve) && !items.some((i) => i.id === data.cve) ? data.cve : null;
  if (!items.length && !cveOutside) return data.error ? <p className="hint">{data.error}</p> : null;

  return (
    <section className="catalog" aria-label="Autres résultats">
      <h2 className="catalog-title">
        Autres résultats
        <span className="hint">
          {" "}
          · catalogue CISA des failles exploitées{data.total > data.items.length ? ` (${data.items.length} premiers sur ${data.total})` : ""}
        </span>
      </h2>
      <ul className="list card">
        {cveOutside && (
          <li>
            <button type="button" className="row" onClick={() => onOpen(cveOutside)}>
              <span className="row-main">
                <span className="row-top">
                  <span className="row-product">Ouvrir la fiche</span>
                  <span className="row-id">{cveOutside}</span>
                </span>
                <span className="row-text">Vulnérabilité absente du tableau du jour : sa fiche complète est chargée depuis la NVD et CVE.org.</span>
              </span>
            </button>
          </li>
        )}
        {items.map((k) => {
          const d = k.dueDate ? makeDeadline(k.dueDate, "cisa", now) : null;
          return (
            <li key={k.id}>
              <button type="button" className="row p-urgente" onClick={() => onOpen(k.id)}>
                <span className="row-main">
                  <span className="row-top">
                    <span className="row-product">{[k.vendor, k.product].filter(Boolean).join(" ") || k.id}</span>
                    <span className="row-id">{k.id}</span>
                  </span>
                  {k.name && <span className="row-text">{k.name}</span>}
                  <span className="chips">
                    {d && <DueChip d={d} engaged={false} />}
                    <span className="tag tag-kev">Exploitée</span>
                    {k.ransomware && <span className="tag tag-bad">Rançongiciel</span>}
                  </span>
                </span>
                <span className="row-meta">
                  <span>Ajoutée au catalogue</span>
                  <span>{k.dateAdded ? new Date(k.dateAdded).toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" }) : "—"}</span>
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
