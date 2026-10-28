"use client";

import { useMemo, useState } from "react";
import type { Breach } from "@/lib/cti/sources";
import { dateFr, relTime } from "@/lib/format";
import { Icon } from "../ui";
import { DATA_FR } from "@/lib/cti/labels";
import { fmtInt, Kpi, Skeleton, useJson } from "./common";

interface Resp {
  generatedAt: string;
  days: number;
  total: number;
  accounts: number;
  items: Breach[];
}


/** Fuites de données récemment publiées (catalogue Have I Been Pwned). */
export default function BreachesView({ now }: { now: number }) {
  const { data, error, loading } = useJson<Resp>("/api/cti/breaches?jours=90", 60 * 60 * 1000);
  const [q, setQ] = useState("");
  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (data?.items ?? []).filter((b) => !s || `${b.title} ${b.domain} ${b.dataClasses.join(" ")}`.toLowerCase().includes(s));
  }, [data, q]);
  const withPasswords = (data?.items ?? []).filter((b) => b.dataClasses.includes("Passwords")).length;

  return (
    <div className="cti">
      {error && <p className="callout callout-err">{error}</p>}
      <div className="tm-kpis">
        <Kpi k="Fuites sur 90 jours" v={data ? data.items.length : "–"} n="ajoutées au catalogue" />
        <Kpi k="Comptes exposés" v={data ? fmtInt(data.accounts) : "–"} n="sur 90 jours" />
        <Kpi k="Avec mots de passe" v={data ? withPasswords : "–"} n="fuites concernées" />
        <Kpi k="Catalogue complet" v={data ? fmtInt(data.total) : "–"} n="fuites recensées" />
      </div>
      <div className="cti-filters">
        <label className="search cti-search">
          <Icon name="search" size={15} />
          <span className="sr-only">Rechercher une fuite</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rechercher un service, un domaine, un type de données" />
        </label>
      </div>
      {loading && !data ? (
        <Skeleton />
      ) : list.length === 0 ? (
        <div className="empty card">
          <p className="empty-title">Aucune fuite</p>
          <p>Aucune fuite récente ne correspond à cette recherche.</p>
        </div>
      ) : (
        <ul className="list card">
          {list.map((b) => (
            <li key={b.name} className="cti-item">
              <div className="cti-main">
                <p className="cti-title">
                  {b.title}
                  {b.domain && <span className="cti-sub"> · {b.domain}</span>}
                </p>
                {b.description && <p className="cti-desc">{b.description}</p>}
                <div className="chips">
                  <span className="tag tag-bad">{fmtInt(b.pwnCount)} comptes</span>
                  {b.stealerLog && <span className="tag tag-bad">Journaux d’infostealer</span>}
                  {!b.verified && <span className="tag">Non vérifiée</span>}
                  {b.dataClasses.slice(0, 6).map((d) => (
                    <span key={d} className={`tag${d === "Passwords" || d === "Credit cards" ? " tag-prio p-haute" : ""}`}>
                      {DATA_FR[d] ?? d}
                    </span>
                  ))}
                </div>
              </div>
              <div className="cti-side">
                <span className="hint" title={b.breachDate ? `Fuite du ${dateFr(b.breachDate)}` : undefined}>
                  ajoutée {relTime(b.addedDate, now)}
                </span>
                <a href={`https://haveibeenpwned.com/Breach/${encodeURIComponent(b.name)}`} target="_blank" rel="noreferrer" className="cti-link">
                  Détails <Icon name="external" size={12} />
                </a>
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="foot-note">
        Source : <a href="https://haveibeenpwned.com/" target="_blank" rel="noreferrer">Have I Been Pwned</a>. Pour être alerté quand vos domaines sont
        concernés, ajoutez-les dans « Ma surveillance ».
      </p>
    </div>
  );
}
