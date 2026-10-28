"use client";

import { useMemo, useState } from "react";
import type { RansomVictim } from "@/lib/cti/sources";
import { relTime } from "@/lib/format";
import { countryName, flag } from "@/lib/geo/zones";
import { Icon } from "../ui";
import { BarList, Kpi, Skeleton, useJson } from "./common";

interface Resp {
  generatedAt: string;
  count: number;
  items: RansomVictim[];
  groups: { key: string; count: number }[];
  countries: { key: string; count: number }[];
  sectors: { key: string; count: number }[];
}

/** Victimes revendiquées sur les sites de fuite des rançongiciels (dark web), via ransomware.live. */
export default function RansomwareView({ now }: { now: number }) {
  const { data, error, loading } = useJson<Resp>("/api/cti/ransomware", 15 * 60 * 1000);
  const [q, setQ] = useState("");
  const [group, setGroup] = useState("");
  const [country, setCountry] = useState("");

  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (data?.items ?? []).filter(
      (v) => (!group || v.group === group) && (!country || v.country === country) && (!s || `${v.victim} ${v.domain} ${v.sector} ${v.group}`.toLowerCase().includes(s)),
    );
  }, [data, q, group, country]);

  const last24 = (data?.items ?? []).filter((v) => v.discovered && now - Date.parse(v.discovered) < 86400_000).length;

  return (
    <div className="cti">
      {error && <p className="callout callout-err">{error}</p>}
      <div className="tm-kpis">
        <Kpi k="Victimes récentes" v={data?.count ?? "–"} n="dernières revendications" />
        <Kpi k="Dernières 24 h" v={data ? last24 : "–"} n="nouvelles victimes" />
        <Kpi k="Groupes actifs" v={data ? new Set(data.items.map((v) => v.group)).size : "–"} n={data?.groups[0] ? `en tête : ${data.groups[0].key}` : ""} />
        <Kpi k="Pays touchés" v={data ? new Set(data.items.map((v) => v.country).filter(Boolean)).size : "–"} n={data?.countries[0] ? `surtout ${countryName(data.countries[0].key)}` : ""} />
      </div>

      <div className="tm-grid">
        <section className="card tm-panel">
          <h2>Groupes les plus actifs</h2>
          {data ? <BarList rows={data.groups} onPick={setGroup} active={group} /> : <Skeleton />}
        </section>
        <section className="card tm-panel">
          <h2>Pays des victimes</h2>
          {data ? <BarList rows={data.countries} label={(k) => `${flag(k)} ${countryName(k)}`} onPick={setCountry} active={country} /> : <Skeleton />}
        </section>
      </div>

      <div className="cti-filters">
        <label className="search cti-search">
          <Icon name="search" size={15} />
          <span className="sr-only">Rechercher une victime</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rechercher une organisation, un domaine, un secteur" />
        </label>
        {(group || country) && (
          <button type="button" className="btn-plain" onClick={() => (setGroup(""), setCountry(""))}>
            Effacer les filtres ({[group, country && countryName(country)].filter(Boolean).join(", ")})
          </button>
        )}
      </div>

      {loading && !data ? (
        <Skeleton />
      ) : list.length === 0 ? (
        <div className="empty card">
          <p className="empty-title">Aucune victime</p>
          <p>Aucune revendication ne correspond à ces filtres.</p>
        </div>
      ) : (
        <ul className="list card">
          {list.map((v) => (
            <li key={v.id} className="cti-item">
              <div className="cti-main">
                <p className="cti-title">{v.victim}</p>
                <div className="chips">
                  <span className="tag tag-bad">{v.group}</span>
                  {v.country && (
                    <span className="tag">
                      {flag(v.country)} {countryName(v.country)}
                    </span>
                  )}
                  {v.sector && <span className="tag">{v.sector}</span>}
                  {v.domain && <span className="tag tag-ver">{v.domain}</span>}
                </div>
              </div>
              <div className="cti-side">
                <span className="hint">{relTime(v.discovered, now)}</span>
                {v.url && (
                  <a href={v.url} target="_blank" rel="noreferrer" className="cti-link">
                    Détails <Icon name="external" size={12} />
                  </a>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="foot-note">
        Source : <a href="https://www.ransomware.live/" target="_blank" rel="noreferrer">ransomware.live</a>, qui relève les annonces publiées sur les
        sites de fuite des groupes de rançongiciels. Une revendication n’est pas une preuve d’attaque ; aucune donnée volée n’est affichée ni téléchargée.
      </p>
    </div>
  );
}
