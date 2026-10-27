"use client";

import Link from "next/link";
import { useState } from "react";
import { cvssFr, dateFr, hostOf, pct, productName, relTime, SSVC_FR, vendorName } from "@/lib/format";
import { cweLink } from "@/lib/references";
import { PRIORITY_LABEL } from "@/lib/score";
import type { AffectedProduct, CveDetail, Vuln } from "@/lib/types";
import { Icon, PRIO_CLASS, Ring } from "./ui";
import { STATUS_LABEL, type CveStatusValue } from "./useMe";

const SOURCE_LABEL: Record<AffectedProduct["source"], string> = { CNA: "Éditeur", NVD: "NVD", OSV: "OSV" };

function AffectedCard({ a }: { a: AffectedProduct }) {
  return (
    <li className="aff">
      <div className="aff-head">
        <div className="aff-name">
          <span className="aff-product">{a.product}</span>
          {a.vendor && <span className="aff-vendor">{a.vendor}</span>}
        </div>
        <span className="badge">{SOURCE_LABEL[a.source]}{a.ecosystem ? ` · ${a.ecosystem}` : ""}</span>
      </div>
      {a.ranges.length > 0 && (
        <div className="aff-row">
          <span className="aff-label">Impactées</span>
          <span className="chips">
            {a.ranges.map((r) => (
              <span key={r} className="vchip vchip-bad">{r}</span>
            ))}
          </span>
        </div>
      )}
      {a.fixed.length > 0 && (
        <div className="aff-row">
          <span className="aff-label">Corrigée en</span>
          <span className="chips">
            {a.fixed.map((f) => (
              <span key={f} className="vchip vchip-good">{f}</span>
            ))}
          </span>
        </div>
      )}
      {a.platforms.length > 0 && <p className="aff-plat">Avec : {a.platforms.join(", ")}</p>}
    </li>
  );
}

export default function CveDetailView({
  base,
  full,
  loading = false,
  error,
  status,
  onStatus,
  onClose,
  standalone = false,
}: {
  base: Vuln | CveDetail;
  full: CveDetail | null;
  loading?: boolean;
  error?: string | null;
  status: CveStatusValue;
  onStatus: (s: CveStatusValue) => void;
  onClose?: () => void;
  standalone?: boolean;
}) {
  const v: Vuln = full ?? base;
  const [allRefs, setAllRefs] = useState(false);
  const [copied, setCopied] = useState(false);
  const refs = allRefs ? v.references : v.references.slice(0, 8);
  const vendor = vendorName(v);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(`${window.location.origin}/cve/${v.id}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* presse-papiers indisponible */
    }
  };

  return (
    <article className={`detail ${PRIO_CLASS[v.priority]}`} aria-labelledby={`t-${v.id}`}>
      {onClose && (
        <div className="sheet-bar">
          <span className="grabber" aria-hidden="true" />
          <button type="button" className="btn-plain" onClick={onClose}>
            Fermer
          </button>
        </div>
      )}

      <header className="d-head">
        <Ring score={v.score} size={68} stroke={8} big label={`Score de priorité ${v.score} sur 100`} />
        <div className="d-title">
          <p className="d-prio">Priorité {PRIORITY_LABEL[v.priority].toLowerCase()}</p>
          <h2 id={`t-${v.id}`}>{productName(v)}</h2>
          <p className="d-sub">
            {v.id}
            {vendor ? ` chez ${vendor}` : ""}
          </p>
        </div>
      </header>

      <div className="tiles">
        <div className="tile">
          <span className="tile-k">CVSS{v.cvssVersion ? ` ${v.cvssVersion}` : ""}</span>
          <span className="tile-v">{cvssFr(v.cvss)}</span>
          {v.cvssSource && <span className="tile-n">{v.cvssSource === "NVD" ? "NVD" : `par ${v.cvssSource}`}</span>}
        </div>
        <div className="tile">
          <span className="tile-k">EPSS</span>
          <span className="tile-v">{pct(v.epss)}</span>
          {v.epssPercentile != null && <span className="tile-n">plus que {Math.round(v.epssPercentile * 100)} % des CVE</span>}
        </div>
        <div className="tile">
          <span className="tile-k">Exploitée</span>
          <span className="tile-v">{v.kev || v.ssvc?.exploitation === "active" ? "Oui" : v.ssvc?.exploitation === "poc" ? "PoC" : "Non"}</span>
          <span className="tile-n">{v.kev ? "CISA KEV" : v.ssvc ? "SSVC CISA" : "pas de signal"}</span>
        </div>
        <div className="tile">
          <span className="tile-k">Publiée</span>
          <span className="tile-v tile-v-sm">{dateFr(v.published) || "–"}</span>
          <span className="tile-n">{relTime(v.published)}</span>
        </div>
      </div>

      {v.kev && (
        <div className="callout callout-kev" role="note">
          <Icon name="warning" size={18} />
          <p>
            Exploitée activement selon la CISA{v.kev.ransomware ? ", y compris par des rançongiciels" : ""}. Échéance de
            correction : {dateFr(v.kev.dueDate, true)}.
          </p>
        </div>
      )}

      {v.ssvc && (v.ssvc.exploitation || v.ssvc.automatable) && (
        <p className="ssvc">
          Évaluation SSVC de la CISA : exploitation {SSVC_FR[v.ssvc.exploitation ?? ""] ?? v.ssvc.exploitation ?? "inconnue"}
          {v.ssvc.automatable ? `, automatisable ${SSVC_FR[v.ssvc.automatable] ?? v.ssvc.automatable}` : ""}
          {v.ssvc.technicalImpact ? `, impact technique ${SSVC_FR[v.ssvc.technicalImpact] ?? v.ssvc.technicalImpact}` : ""}.
        </p>
      )}

      {v.ai ? (
        <section className="group">
          <div className="group-item">
            <h3>Résumé</h3>
            <p>{v.ai.resume}</p>
          </div>
          <div className="group-item">
            <h3>Impact</h3>
            <p>{v.ai.impact}</p>
          </div>
          <div className="group-item">
            <h3>À faire</h3>
            <p>{v.ai.action}</p>
          </div>
        </section>
      ) : (
        <section className="group">
          <div className="group-item">
            <h3>Description</h3>
            <p lang="en">{v.description || "Pas encore de description publiée."}</p>
          </div>
        </section>
      )}

      <section aria-labelledby={`aff-${v.id}`}>
        <h3 className="sec-title" id={`aff-${v.id}`}>
          Versions impactées
        </h3>
        {loading && v.affected.length === 0 ? (
          <div className="skeleton" aria-busy="true" aria-label="Chargement des versions">
            <span />
            <span />
          </div>
        ) : v.affected.length > 0 ? (
          <ul className="aff-list">
            {v.affected.map((a) => (
              <AffectedCard key={`${a.source}-${a.vendor}-${a.product}`} a={a} />
            ))}
          </ul>
        ) : (
          <p className="muted-box">
            Aucune version précise n’est encore publiée par l’éditeur, la NVD ou OSV. Consultez l’avis de l’éditeur dans
            les références.
          </p>
        )}
        {loading && v.affected.length > 0 && <p className="hint">Recherche d’autres sources de versions…</p>}
      </section>

      {v.mentions.length > 0 && (
        <section aria-labelledby={`men-${v.id}`}>
          <h3 className="sec-title" id={`men-${v.id}`}>
            Signalée par
          </h3>
          <ul className="group linklist">
            {v.mentions.map((m) => (
              <li key={m.link}>
                <a href={m.link} target="_blank" rel="noreferrer" className="linkrow">
                  <span className="linkrow-main">
                    <span className="linkrow-title">{m.title}</span>
                    <span className="linkrow-sub">
                      {m.source}
                      {m.published ? `, ${relTime(m.published)}` : ""}
                    </span>
                  </span>
                  <Icon name="external" size={15} className="linkrow-icon" />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby={`ref-${v.id}`}>
        <h3 className="sec-title" id={`ref-${v.id}`}>
          Références{v.references.length ? ` (${v.references.length})` : ""}
        </h3>
        {v.references.length === 0 ? (
          <p className="muted-box">{loading ? "Chargement des références…" : "Aucune référence publiée."}</p>
        ) : (
          <>
            <ul className="group linklist">
              {refs.map((r) => (
                <li key={r.url}>
                  <a href={r.url} target="_blank" rel="noreferrer" className="linkrow">
                    <span className="linkrow-main">
                      <span className="linkrow-title">{hostOf(r.url)}</span>
                      {r.tags.length > 0 && (
                        <span className="chips">
                          {r.tags.map((t) => (
                            <span key={t} className={`tag ${t === "Correctif" ? "tag-good" : t === "Exploit" ? "tag-bad" : ""}`}>
                              {t}
                            </span>
                          ))}
                        </span>
                      )}
                    </span>
                    <Icon name="external" size={15} className="linkrow-icon" />
                  </a>
                </li>
              ))}
            </ul>
            {v.references.length > 8 && (
              <button type="button" className="btn-plain more" onClick={() => setAllRefs(!allRefs)}>
                {allRefs ? "Afficher moins" : `Afficher les ${v.references.length - 8} autres`}
              </button>
            )}
          </>
        )}
      </section>

      <section aria-labelledby={`db-${v.id}`}>
        <h3 className="sec-title" id={`db-${v.id}`}>
          Bases de vulnérabilités
        </h3>
        <ul className="dbgrid">
          {(full?.dbLinks ?? []).length === 0 && loading ? (
            <li className="hint">Chargement…</li>
          ) : (
            (full?.dbLinks ?? []).map((d) => (
              <li key={d.name}>
                <a href={d.url} target="_blank" rel="noreferrer" className="db">
                  <span className="db-name">{d.name}</span>
                  {d.note && <span className="db-note">{d.note}</span>}
                </a>
              </li>
            ))
          )}
        </ul>
      </section>

      {(v.reasons.length > 0 || v.cwes.length > 0) && (
        <section className="why">
          {v.reasons.length > 0 && (
            <p>
              <strong>Pourquoi ce score :</strong> {v.reasons.join(", ").replace(/^./, (c) => c.toLowerCase())}.
            </p>
          )}
          {v.cwes.length > 0 && (
            <p>
              <strong>Faiblesse :</strong>{" "}
              {v.cwes.map((c, i) => {
                const href = cweLink(c);
                return (
                  <span key={c}>
                    {i > 0 && ", "}
                    {href ? (
                      <a href={href} target="_blank" rel="noreferrer">
                        {c}
                      </a>
                    ) : (
                      c
                    )}
                  </span>
                );
              })}
            </p>
          )}
          {v.vector && <p className="vector">{v.vector}</p>}
        </section>
      )}

      {error && <p className="callout callout-err">{error}</p>}

      <div className="actions">
        <div className="status-ctl" role="group" aria-label="Suivi de cette vulnérabilité">
          <span className="status-label">Mon suivi</span>
          <div className="segmented segmented-status">
            {(Object.keys(STATUS_LABEL) as CveStatusValue[]).map((s) => (
              <button key={s} type="button" aria-pressed={status === s} className={`${status === s ? "is-on" : ""} st-${s}`} onClick={() => onStatus(s)}>
                {status === s && s === "traitee" && <Icon name="check" size={14} />}
                {STATUS_LABEL[s]}
              </button>
            ))}
          </div>
        </div>
        <div className="actions-row">
          <button type="button" className="btn-secondary" onClick={copy}>
            <Icon name={copied ? "check" : "link"} size={16} />
            {copied ? "Lien copié" : "Copier le lien"}
          </button>
          {!standalone && (
            <Link href={`/cve/${v.id}`} className="btn-secondary">
              Ouvrir la fiche
            </Link>
          )}
        </div>
      </div>
      <p className="foot-note">
        Résumé rédigé par IA à partir des fiches officielles. Vérifiez l’avis de l’éditeur avant d’agir.
      </p>
    </article>
  );
}
