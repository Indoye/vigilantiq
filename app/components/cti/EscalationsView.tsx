"use client";

import { useEffect, useMemo, useState } from "react";
import { ESCALATION_FR, ESCALATION_KINDS, sevRank, SEVERITY_FR, type Escalation, type EscalationKind } from "@/lib/sc-core";
import { Icon } from "../ui";

type Filter = "all" | "mine" | EscalationKind;

/** Une escalade concerne-t-elle l'organisation ? CVE ouverte sur le parc, ou technologie de la stack citée. */
function relevance(e: Escalation, parcIds: Set<string>, stack: string[]): string | null {
  if (parcIds.has(e.cve)) return "Détectée sur votre parc";
  const text = e.summary.toLowerCase();
  const hit = stack.find((s) => s.length >= 3 && new RegExp(`\\b${s.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(text));
  return hit ? `Stack : ${hit}` : null;
}

/**
 * Escalades des 30 derniers jours (SecurityContext) : CVE nouvellement exploitées (CISA, VulnCheck),
 * premier exploit public ou d'accès initial, modèle Nuclei publié, sévérité relevée à critique.
 * C'est le signal à surveiller entre deux publications : une faille ancienne qui devient dangereuse.
 */
export default function EscalationsView({ parcIds, stack }: { parcIds: Set<string>; stack: string[] }) {
  const [items, setItems] = useState<Escalation[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");

  useEffect(() => {
    fetch("/api/securitycontext/escalations", { cache: "no-store" })
      .then(async (r) => {
        const j = await r.json();
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        setItems(j.items);
      })
      .catch((e: Error) => setErr(e.message));
  }, []);

  const rows = useMemo(() => {
    const byCve = new Map<string, { e: Escalation; kinds: EscalationKind[]; why: string | null }>();
    for (const e of items ?? []) {
      const cur = byCve.get(e.cve);
      if (cur) {
        if (!cur.kinds.includes(e.kind)) cur.kinds.push(e.kind);
        if (e.date > cur.e.date) cur.e = { ...e, summary: cur.e.summary };
      } else byCve.set(e.cve, { e, kinds: [e.kind], why: relevance(e, parcIds, stack) });
    }
    return [...byCve.values()]
      .map((r) => ({ ...r, kinds: r.kinds.sort((a, b) => ESCALATION_KINDS.indexOf(a) - ESCALATION_KINDS.indexOf(b)) }))
      .sort((a, b) => Number(Boolean(b.why)) - Number(Boolean(a.why)) || b.e.date.localeCompare(a.e.date) || sevRank(b.e.severity) - sevRank(a.e.severity));
  }, [items, parcIds, stack]);

  const shown = rows.filter((r) => (filter === "all" ? true : filter === "mine" ? Boolean(r.why) : r.kinds.includes(filter)));
  const count = (f: Filter) => rows.filter((r) => (f === "all" ? true : f === "mine" ? Boolean(r.why) : r.kinds.includes(f))).length;

  return (
    <div className="esc">
      <p className="hint esc-intro">
        Failles qui deviennent plus dangereuses : nouvellement exploitées, premier exploit public, détectables avec Nuclei, ou passées critiques. 30 derniers jours, mis à jour
        en continu. Source :{" "}
        <a href="https://securitycontext.com/activity" target="_blank" rel="noreferrer">
          SecurityContext par ProjectDiscovery
        </a>
        .
      </p>
      <div className="segmented esc-seg" role="group" aria-label="Filtrer les escalades">
        {(["all", "mine", "known_exploited", "vulncheck_known_exploited", "public_exploit", "nuclei_template", "raised_to_critical"] as Filter[]).map((f) => (
          <button key={f} type="button" aria-pressed={filter === f} className={filter === f ? "is-on" : ""} onClick={() => setFilter(f)}>
            {f === "all" ? "Toutes" : f === "mine" ? "Me concernent" : ESCALATION_FR[f]} <span className="seg-n">{count(f)}</span>
          </button>
        ))}
      </div>
      {err ? (
        <p className="callout">{err}</p>
      ) : items === null ? (
        <div className="skeleton" aria-busy="true" aria-label="Chargement des escalades">
          <span />
          <span />
          <span />
        </div>
      ) : shown.length === 0 ? (
        <p className="muted-box">{filter === "mine" ? "Aucune escalade ne touche votre parc ou les technologies de votre stack sur les 30 derniers jours." : "Aucune escalade pour ce filtre."}</p>
      ) : (
        <ul className="list card">
          {shown.slice(0, 150).map(({ e, kinds, why }) => (
            <li key={e.cve}>
              <a className="row esc-row" href={`/cve/${e.cve}`}>
                <span className="row-main">
                  <span className="row-top">
                    <span className="row-product">{e.cve}</span>
                    {e.severity && <span className="row-id">{SEVERITY_FR[e.severity] ?? e.severity}</span>}
                  </span>
                  <span className="row-text">{e.summary.replace(/^severity [a-z]+ \(CVSS [\d.]+\); EPSS [\d.]+\. /, "")}</span>
                  <span className="chips">
                    {kinds.map((k) => (
                      <span key={k} className={`tag ${k === "known_exploited" || k === "vulncheck_known_exploited" || k === "initial_access_published" ? "tag-esc" : "tag-esc-soft"}`}>
                        {ESCALATION_FR[k]}
                      </span>
                    ))}
                    {why && <span className="tag tag-stack">{why}</span>}
                  </span>
                </span>
                <span className="row-meta">
                  {new Date(e.date + "T00:00:00Z").toLocaleDateString("fr-FR", { day: "numeric", month: "short", timeZone: "UTC" })}
                  <Icon name="chevron" size={14} />
                </span>
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
