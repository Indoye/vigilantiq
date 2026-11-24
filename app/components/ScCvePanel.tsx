"use client";

import { useEffect, useState } from "react";
import type { ScCve } from "@/lib/sc-core";
import { Icon } from "./ui";

const n = (x: number) => x.toLocaleString("fr-FR");
const d = (s: string | null) => (s ? new Date(s + (s.length === 10 ? "T00:00:00Z" : "")).toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "");

/**
 * Contexte SecurityContext d'une CVE, sur sa fiche : qui l'exploite (CISA, VulnCheck), exploits publics,
 * modèle de détection Nuclei, exposition sur Internet, produits et projets touchés.
 * Rien n'est affiché si l'intégration n'est pas ouverte à l'organisation.
 */
export default function ScCvePanel({ id }: { id: string }) {
  const [ctx, setCtx] = useState<ScCve | null | undefined>(undefined);
  const [err, setErr] = useState<string | null>(null);
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    let alive = true;
    setCtx(undefined);
    setErr(null);
    fetch(`/api/securitycontext/cve/${id}`, { cache: "no-store" })
      .then(async (r) => {
        if (r.status === 401 || r.status === 403) return alive && setHidden(true);
        const j = await r.json();
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        if (alive) setCtx(j.context);
      })
      .catch((e: Error) => alive && setErr(e.message));
    return () => {
      alive = false;
    };
  }, [id]);

  if (hidden) return null;
  const ex = ctx?.exploitation;
  return (
    <section aria-labelledby={`sc-${id}`} className="sc-panel">
      <h3 className="sec-title" id={`sc-${id}`}>
        Contexte d’exploitation · SecurityContext
      </h3>
      {err ? (
        <p className="muted-box">{err}</p>
      ) : ctx === undefined ? (
        <div className="skeleton" aria-busy="true" aria-label="Chargement du contexte SecurityContext">
          <span />
          <span />
        </div>
      ) : ctx === null ? (
        <p className="muted-box">SecurityContext n’a pas encore ce CVE dans son index (il apparaît en général dans l’heure qui suit sa publication).</p>
      ) : (
        <div className="group sc-body">
          <div className="sc-tags">
            {ex!.knownExploited ? (
              <span className="tag tag-bad">Exploitée{ex!.by.length ? ` (${ex!.by.map((b) => (b === "cisa" ? "CISA" : b === "vulncheck" ? "VulnCheck" : b)).join(", ")})` : ""}</span>
            ) : ex!.vulncheckSince ? (
              <span className="tag tag-bad">Exploitée selon VulnCheck</span>
            ) : (
              <span className="tag">Aucune exploitation connue</span>
            )}
            {ex!.ransomware && <span className="tag tag-bad">Utilisée par des rançongiciels</span>}
            {ex!.initialAccess && <span className="tag tag-bad">Accès initial</span>}
            {ex!.remote === true && ex!.authRequired === false && <span className="tag tag-prio">À distance, sans authentification</span>}
            {ex!.remote === true && ex!.authRequired === true && <span className="tag">À distance, authentification requise</span>}
            {ctx.patchAvailable === true && <span className="tag tag-good">Correctif disponible</span>}
            {ctx.patchAvailable === false && <span className="tag tag-bad">Pas de correctif</span>}
          </div>

          <div className="tiles sc-tiles">
            <div className="tile">
              <span className="tile-k">Exploits publics</span>
              <span className="tile-v">{ex!.publicExploits ? `${n(ex!.publicExploits)}${ex!.publicExploitsCapped ? "+" : ""}` : "0"}</span>
              <span className="tile-n">{ex!.firstExploit ? `premier le ${d(ex!.firstExploit)}` : "aucun recensé"}</span>
            </div>
            <div className="tile">
              <span className="tile-k">Hôtes exposés sur Internet</span>
              <span className="tile-v">{ex!.exposedHosts != null ? n(ex!.exposedHosts) : "–"}</span>
              <span className="tile-n">estimation, tous propriétaires confondus</span>
            </div>
            <div className="tile">
              <span className="tile-k">Dépôts open source exposés</span>
              <span className="tile-v">{n(ctx.exposure.repositories)}</span>
              <span className="tile-n">{ctx.productsTotal ? `${n(ctx.productsTotal)} produit${ctx.productsTotal > 1 ? "s" : ""} touché${ctx.productsTotal > 1 ? "s" : ""}` : "dans l’index SecurityContext"}</span>
            </div>
            <div className="tile">
              <span className="tile-k">Exploitée depuis</span>
              <span className="tile-v tile-v-sm">{ex!.cisaSince ? d(ex!.cisaSince) : ex!.vulncheckSince ? d(ex!.vulncheckSince) : "–"}</span>
              <span className="tile-n">{ex!.hackerone ? `${n(ex!.hackerone)} rapports HackerOne` : ex!.cisaSince ? "catalogue CISA" : ex!.vulncheckSince ? "VulnCheck" : ""}</span>
            </div>
          </div>

          {ctx.impact && <p className="sc-line"><strong>Impact :</strong> {ctx.impact}</p>}
          {ctx.remediation && <p className="sc-line"><strong>Correction :</strong> {ctx.remediation}</p>}

          {ctx.nuclei && (
            <a href={ctx.nuclei.url} target="_blank" rel="noreferrer" className="linkrow sc-nuclei">
              <span className="linkrow-main">
                <span className="linkrow-title">Détectable avec Nuclei : modèle {ctx.nuclei.id}</span>
                <span className="linkrow-sub">Pour vérifier vos propres systèmes exposés, dans le cadre d’un test autorisé</span>
              </span>
              <Icon name="external" size={15} className="linkrow-icon" />
            </a>
          )}

          {ctx.products.length > 0 && (
            <details className="sc-more">
              <summary>
                Produits touchés{ctx.productsTotal > ctx.products.length ? ` (${ctx.products.length} sur ${n(ctx.productsTotal)})` : ""}
              </summary>
              <ul className="sc-products">
                {ctx.products.map((p) => (
                  <li key={p.product}>
                    <code>{p.product}</code> <span className="hint">{p.affected.join(" · ")}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
          {ctx.projects.length > 0 && (
            <p className="hint">
              Projet open source concerné : {ctx.projects.map((p, i) => (
                <span key={p}>
                  {i ? ", " : ""}
                  <a href={`https://securitycontext.com/repo/${p}`} target="_blank" rel="noreferrer">
                    {p}
                  </a>
                </span>
              ))}
            </p>
          )}
          <p className="hint sc-src">
            Source :{" "}
            <a href={`https://securitycontext.com/cve/${id}`} target="_blank" rel="noreferrer">
              SecurityContext par ProjectDiscovery
            </a>
            {ctx.dataset ? ` · données du ${d(ctx.dataset)}` : ""} · « listé » signifie exposé, pas compromis.
          </p>
        </div>
      )}
    </section>
  );
}
