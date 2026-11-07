"use client";

import { useEffect, useState } from "react";
import Term from "./Term";
import { Icon } from "./ui";

interface Metrics {
  org: string;
  statuses: { en_cours: number; traitee: number; non_concernee: number };
  treated30: number;
  weekly: { week: string; treated: number; alerts: number }[];
  alerts30: Record<string, number>;
  darkweb30: number;
  members: number;
  assigned: number;
  parc: { devices: number; compliance: number | null; urgent: number; high: number; mttrDays: number | null; deploySuccess: number | null; trend: { day: string; high: number; total: number }[] } | null;
}

export interface Exposure {
  overdue: number;
  urgentStack: number;
  highStack: number;
  exploitedStack: number;
  stackSet: boolean;
}

const fmtWeek = (d: string) => new Date(d).toLocaleDateString("fr-FR", { day: "numeric", month: "short" });

/** Indice d'exposition (0 = rien à signaler, 100 = maximal) : règle simple et explicable, détaillée dans l'infobulle. */
function exposureIndex(e: Exposure, m: Metrics | null): number {
  const crit = (m?.alerts30.critique ?? 0) + (m?.alerts30.haute ?? 0);
  const raw = e.overdue * 18 + e.exploitedStack * 15 + e.urgentStack * 10 + e.highStack * 4 + Math.min(crit, 5) * 5 + Math.min(m?.parc?.urgent ?? 0, 10) * 2;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

/** Accueil « Direction » : quelques indicateurs lisibles en un coup d'œil, et leur évolution sur 12 semaines. */
export default function DirectionView({ exposure }: { exposure: Exposure }) {
  const [m, setM] = useState<Metrics | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    fetch("/api/direction", { cache: "no-store" })
      .then(async (r) => {
        const j = await r.json();
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        setM(j);
      })
      .catch((e: Error) => setErr(e.message));
  }, []);

  const idx = exposureIndex(exposure, m);
  const level = idx >= 60 ? { l: "Élevée", c: "dir-high" } : idx >= 25 ? { l: "Modérée", c: "dir-mid" } : { l: "Faible", c: "dir-low" };
  const maxBar = Math.max(1, ...(m?.weekly.map((w) => Math.max(w.treated, w.alerts)) ?? [1]));
  const alerts30 = Object.values(m?.alerts30 ?? {}).reduce((a, b) => a + b, 0);
  const parcTrend = m?.parc?.trend ?? [];
  const trendMax = Math.max(1, ...parcTrend.map((t) => t.total));
  const path = parcTrend
    .map((t, i) => `${i ? "L" : "M"}${((i / Math.max(1, parcTrend.length - 1)) * 300).toFixed(1)},${(60 - (t.high / trendMax) * 56).toFixed(1)}`)
    .join(" ");

  return (
    <div className="dir">
      <section className={`card dir-hero ${level.c}`}>
        <div className="dir-gauge" style={{ "--p": `${idx}%` } as React.CSSProperties} aria-hidden="true">
          <span>{idx}</span>
        </div>
        <div>
          <p className="dir-k">
            <Term k="exposition">Exposition aux menaces</Term>
          </p>
          <p className="dir-level">{level.l}</p>
          <p className="dir-say">
            {!exposure.stackSet
              ? "Renseignez la stack de l’organisation pour mesurer votre exposition réelle."
              : exposure.overdue
                ? `${exposure.overdue} échéance${exposure.overdue > 1 ? "s" : ""} de correction dépassée${exposure.overdue > 1 ? "s" : ""} : à traiter en priorité.`
                : exposure.exploitedStack
                  ? `${exposure.exploitedStack} faille${exposure.exploitedStack > 1 ? "s" : ""} exploitée${exposure.exploitedStack > 1 ? "s" : ""} touche${exposure.exploitedStack > 1 ? "nt" : ""} vos technologies.`
                  : "Aucune faille exploitée ne touche vos technologies aujourd’hui."}
          </p>
        </div>
        <button type="button" className="btn-secondary btn-sm dir-print" onClick={() => window.print()}>
          <Icon name="file" size={14} /> Imprimer / PDF
        </button>
      </section>

      {err && <p className="callout">{err}</p>}

      <div className="tiles dir-tiles">
        <div className="tile">
          <span className="tile-k">Traitées (30 j)</span>
          <span className="tile-v">{m ? m.treated30 : "–"}</span>
          <span className="tile-n">{m ? `${m.statuses.en_cours} en cours · ${m.assigned} assignée${m.assigned > 1 ? "s" : ""}` : ""}</span>
        </div>
        <div className="tile">
          <span className="tile-k">Urgentes / hautes sur la stack</span>
          <span className="tile-v">{exposure.urgentStack + exposure.highStack}</span>
          <span className="tile-n">dont {exposure.urgentStack} urgente{exposure.urgentStack > 1 ? "s" : ""}</span>
        </div>
        <div className="tile">
          <span className="tile-k">Alertes (30 j)</span>
          <span className="tile-v">{m ? alerts30 : "–"}</span>
          <span className="tile-n">{m ? `${(m.alerts30.critique ?? 0) + (m.alerts30.haute ?? 0)} critiques ou hautes · ${m.darkweb30} dark web` : ""}</span>
        </div>
        <div className="tile">
          <span className="tile-k">
            <Term k="mttr">Délai de correction</Term>
          </span>
          <span className="tile-v">{m?.parc?.mttrDays != null ? `${m.parc.mttrDays} j` : "–"}</span>
          <span className="tile-n">
            {m?.parc?.devices ? `${m.parc.compliance ?? "–"} % du parc conforme · ${m.parc.devices} équipement${m.parc.devices > 1 ? "s" : ""}` : "agent Parc non installé"}
          </span>
        </div>
      </div>

      <section className="card dir-chart" aria-labelledby="dir-weekly">
        <h3 id="dir-weekly">Activité sur 12 semaines</h3>
        <div className="dir-legend">
          <span className="dir-sw dir-sw-t" /> CVE traitées <span className="dir-sw dir-sw-a" /> Alertes reçues
        </div>
        <div className="dir-bars" role="img" aria-label={m ? m.weekly.map((w) => `semaine du ${fmtWeek(w.week)} : ${w.treated} traitées, ${w.alerts} alertes`).join(" ; ") : "Chargement"}>
          {(m?.weekly ?? Array.from({ length: 12 }, (_, i) => ({ week: String(i), treated: 0, alerts: 0 }))).map((w) => (
            <div key={w.week} className="dir-col" title={m ? `Semaine du ${fmtWeek(w.week)} : ${w.treated} traitée(s), ${w.alerts} alerte(s)` : ""}>
              <div className="dir-pair">
                <span className="dir-bar dir-bar-t" style={{ height: `${(w.treated / maxBar) * 100}%` }} />
                <span className="dir-bar dir-bar-a" style={{ height: `${(w.alerts / maxBar) * 100}%` }} />
              </div>
              <span className="dir-x">{m ? fmtWeek(w.week) : ""}</span>
            </div>
          ))}
        </div>
      </section>

      {parcTrend.length > 1 && (m?.parc?.devices ?? 0) > 0 && (
        <section className="card dir-chart" aria-labelledby="dir-parc">
          <h3 id="dir-parc">Failles urgentes ou hautes ouvertes sur le parc (90 jours)</h3>
          <svg viewBox="0 0 300 62" className="dir-line" preserveAspectRatio="none" role="img" aria-label={`De ${parcTrend[0].high} à ${parcTrend[parcTrend.length - 1].high}`}>
            <path d={path} fill="none" stroke="var(--orange)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
          </svg>
          <p className="hint">
            Aujourd’hui : {parcTrend[parcTrend.length - 1].high} · il y a 90 jours : {parcTrend[0].high}
          </p>
        </section>
      )}
    </div>
  );
}
