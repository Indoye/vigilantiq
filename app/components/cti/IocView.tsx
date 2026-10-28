"use client";

import { useEffect, useMemo, useState } from "react";
import type { Ioc } from "@/lib/cti/sources";
import { relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Kpi, Skeleton, useJson } from "./common";

interface Resp {
  generatedAt: string;
  total: number;
  sources: { name: string; ok: boolean; count: number; note?: string }[];
  types: { key: string; count: number }[];
  malware: { key: string; count: number }[];
  items: Ioc[];
}

type TypeSel = "" | "url" | "ip" | "domain" | "hash";
const TYPE_LABEL: Record<string, string> = { url: "URL", ip: "IP", "ip:port": "IP:port", domain: "Domaine", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", hash: "Hash" };

/** Indicateurs de compromission récents, filtrables et exportables (CSV, STIX 2.1, JSON). */
export default function IocView({ now }: { now: number }) {
  const [type, setType] = useState<TypeSel>("");
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(q.trim()), 300);
    return () => clearTimeout(id);
  }, [q]);
  const params = useMemo(() => {
    const p = new URLSearchParams();
    if (type) p.set("type", type);
    if (debounced) p.set("q", debounced);
    return p;
  }, [type, debounced]);
  const { data, error, loading } = useJson<Resp>(`/api/cti/iocs?${params.toString()}&limit=300`, 15 * 60 * 1000);
  const count = (k: string) => data?.types.find((t) => t.key === k)?.count ?? 0;
  const exportUrl = (format: string) => `/api/cti/iocs?${params.toString()}&limit=5000&format=${format}`;

  const copy = async (v: string) => {
    try {
      await navigator.clipboard.writeText(v);
      setCopied(v);
      setTimeout(() => setCopied(null), 1400);
    } catch {
      /* presse-papiers indisponible */
    }
  };

  return (
    <div className="cti">
      {error && <p className="callout callout-err">{error}</p>}
      <div className="tm-kpis">
        <Kpi k="URL malveillantes" v={data ? fmtInt(count("url")) : "–"} n="hameçonnage, malwares" />
        <Kpi k="Adresses IP" v={data ? fmtInt(count("ip")) : "–"} n="serveurs C2" />
        <Kpi k="Domaines" v={data ? fmtInt(count("domain")) : "–"} n={count("domain") ? "infrastructures" : "avec ThreatFox"} />
        <Kpi k="Empreintes" v={data ? fmtInt(count("hash")) : "–"} n={count("hash") ? "fichiers malveillants" : "avec ThreatFox"} />
      </div>

      <div className="cti-filters">
        <div className="segmented" role="group" aria-label="Type d’indicateur">
          {(
            [
              ["", "Tous"],
              ["url", "URL"],
              ["ip", "IP"],
              ["domain", "Domaines"],
              ["hash", "Empreintes"],
            ] as [TypeSel, string][]
          ).map(([k, l]) => (
            <button key={k} type="button" aria-pressed={type === k} className={type === k ? "is-on" : ""} onClick={() => setType(k)}>
              {l}
            </button>
          ))}
        </div>
        <label className="search cti-search">
          <Icon name="search" size={15} />
          <span className="sr-only">Rechercher un indicateur</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rechercher une IP, un domaine, un malware" />
        </label>
        <div className="cti-export" role="group" aria-label="Exporter">
          <a className="btn-pdf" href={exportUrl("csv")} download>
            <Icon name="file" size={15} /> CSV
          </a>
          <a className="btn-pdf" href={exportUrl("stix")} download title="STIX 2.1 : MISP, OpenCTI, SIEM">
            <Icon name="file" size={15} /> STIX 2.1
          </a>
          <a className="btn-pdf" href={exportUrl("json")} target="_blank" rel="noreferrer">
            <Icon name="code" size={15} /> JSON
          </a>
        </div>
      </div>

      {loading && !data ? (
        <Skeleton />
      ) : (data?.items.length ?? 0) === 0 ? (
        <div className="empty card">
          <p className="empty-title">Aucun indicateur</p>
          <p>Aucun indicateur ne correspond à ces filtres.</p>
        </div>
      ) : (
        <ul className="list card">
          {data!.items.map((i) => (
            <li key={`${i.type}|${i.value}`} className="cti-item ioc-item">
              <div className="cti-main">
                <div className="ioc-line">
                  <span className="tag ioc-type">{TYPE_LABEL[i.type] ?? i.type}</span>
                  <code className="ioc-val">{i.value}</code>
                  <button type="button" className="icon-btn ioc-copy" onClick={() => copy(i.value)} aria-label={`Copier ${i.value}`}>
                    <Icon name={copied === i.value ? "check" : "copy"} size={14} />
                  </button>
                </div>
                <p className="cti-desc">
                  {i.threat}
                  {i.malware ? ` · ${i.malware}` : ""}
                  {i.tags.length ? ` · ${i.tags.slice(0, 4).join(", ")}` : ""}
                </p>
              </div>
              <div className="cti-side">
                <span className="hint">{i.firstSeen ? relTime(i.firstSeen, now) : ""}</span>
                <a href={i.ref} target="_blank" rel="noreferrer" className="cti-link">
                  {i.source.replace("abuse.ch ", "")} <Icon name="external" size={12} />
                </a>
              </div>
            </li>
          ))}
        </ul>
      )}
      {data && data.total > data.items.length && (
        <p className="hint">
          {fmtInt(data.items.length)} indicateurs affichés sur {fmtInt(data.total)} : affinez la recherche ou exportez la liste complète.
        </p>
      )}
      <p className="foot-note">
        Sources :{" "}
        {data?.sources.map((s, n) => (
          <span key={s.name}>
            {n > 0 && " · "}
            {s.name} {s.ok ? `(${fmtInt(s.count)})` : `(${s.note ?? "indisponible"})`}
          </span>
        )) ?? "abuse.ch, OpenPhish"}
        . Ne bloquez jamais un indicateur sans vérification : certaines URL hébergent aussi des contenus légitimes.
      </p>
    </div>
  );
}
