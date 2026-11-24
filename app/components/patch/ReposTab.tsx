"use client";

import { useCallback, useEffect, useState } from "react";
import { ESCALATION_FR, SEVERITY_FR, type Escalation, type ScRepoView } from "@/lib/sc-core";
import { Icon } from "../ui";

type Repo = ScRepoView & { scanId: string | null; escalations: Escalation[]; error?: string };

const SEV_CLASS: Record<string, string> = { critical: "tag-bad", high: "tag-bad", medium: "tag-prio", low: "", none: "tag-good" };
const n = (x: number) => x.toLocaleString("fr-FR");

const PATH_FR: Record<string, string> = {
  "vulnerable runtime dependency": "Dépendance d’exécution vulnérable",
  "native library": "Bibliothèque native embarquée",
  "malicious package": "Paquet malveillant",
  "leaked secret": "Secret divulgué",
  "leaked contributor login": "Identifiants de contributeur divulgués",
};
const FIX_FR: Record<string, string> = {
  "upgrade to a fixed version": "mettre à jour vers une version corrigée",
  "upgrade the wrapper package that bundles it": "mettre à jour le paquet qui l’embarque",
};
const fr = (m: Record<string, string>, s: string) => m[s] ?? s;

/**
 * Dépôts de code (SecurityContext) : l'organisation suit ses dépôts GitHub publics.
 * Pour chacun : score de risque, chemin le plus simple pour un attaquant, mises à jour de dépendances à faire d'abord,
 * escalades récentes qui touchent ses dépendances. Un dépôt absent de l'index peut être analysé à la demande.
 */
export default function ReposTab({ canEdit }: { canEdit: boolean }) {
  const [data, setData] = useState<{ repos: Repo[]; max: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [scan, setScan] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      const r = await fetch("/api/securitycontext/repos", { cache: "no-store" });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setData(j);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  // Suivi des analyses en cours
  const scanning = (data?.repos ?? []).filter((r) => r.scanId).map((r) => r.repo);
  useEffect(() => {
    if (!scanning.length) return;
    const id = setInterval(async () => {
      for (const repo of scanning) {
        const r = await fetch(`/api/securitycontext/repos/scan?repo=${encodeURIComponent(repo)}`, { cache: "no-store" }).then((x) => x.json()).catch(() => null);
        if (!r) continue;
        setScan((s) => ({ ...s, [repo]: r.status === "running" && r.step ? `analyse : ${r.step}` : r.status }));
        if (r.status === "done" || r.status === "failed") load();
      }
    }, 15_000);
    return () => clearInterval(id);
  }, [scanning.join(","), load]); // eslint-disable-line react-hooks/exhaustive-deps

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await fetch("/api/securitycontext/repos", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo: input }) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setInput("");
      setOpen(j.repo);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const remove = async (repo: string) => {
    await fetch(`/api/securitycontext/repos?repo=${encodeURIComponent(repo)}`, { method: "DELETE" });
    load();
  };
  const startScan = async (repo: string) => {
    const r = await fetch("/api/securitycontext/repos/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo }) });
    const j = await r.json();
    if (!r.ok) return setErr(j.error ?? `Erreur ${r.status}`);
    setScan((s) => ({ ...s, [repo]: "en file d’attente" }));
    load();
  };

  return (
    <div className="repos">
      <section className="card tm-panel">
        <h2>
          <Icon name="code" size={16} /> Dépôts de code suivis
        </h2>
        <p className="cti-desc">
          Ajoutez les dépôts GitHub publics de vos applications : VigilantIQ affiche leurs dépendances vulnérables, ce qu’un attaquant exploiterait en premier et les mises à
          jour à faire d’abord. Les dépôts privés ne sont pas pris en charge ici.
        </p>
        {canEdit && (
          <form className="watch-form" onSubmit={add}>
            <label className="search watch-input">
              <span className="sr-only">Dépôt GitHub</span>
              <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="propriétaire/dépôt ou https://github.com/…" required />
            </label>
            <button type="submit" className="btn-primary watch-add" disabled={busy || !input.trim() || (data ? data.repos.length >= data.max : false)}>
              Suivre
            </button>
          </form>
        )}
        {err && <p className="callout">{err}</p>}
      </section>

      {data === null && !err ? (
        <div className="skeleton" aria-busy="true" aria-label="Chargement des dépôts">
          <span />
          <span />
        </div>
      ) : data && data.repos.length === 0 ? (
        <p className="muted-box">Aucun dépôt suivi pour l’instant.</p>
      ) : (
        <ul className="list card">
          {data?.repos.map((r) => {
            const isOpen = open === r.repo;
            return (
              <li key={r.repo} className="repo-item">
                <button type="button" className="row repo-row" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : r.repo)}>
                  <span className="repo-score" data-sev={r.severity ?? "none"} aria-label={r.riskScore != null ? `Score de risque ${r.riskScore} sur 100` : "Non analysé"}>
                    {r.riskScore ?? "–"}
                  </span>
                  <span className="row-main">
                    <span className="row-top">
                      <span className="row-product">{r.repo}</span>
                      {r.stars != null && <span className="row-id">★ {n(r.stars)}</span>}
                    </span>
                    <span className="row-text">
                      {!r.found
                        ? r.error ?? "Absent de l’index SecurityContext : lancez une analyse."
                        : r.cheapestPath
                          ? `Point d’entrée le plus simple : ${fr(PATH_FR, r.cheapestPath.type).toLowerCase()} → ${fr(FIX_FR, r.cheapestPath.fix)}`
                          : "Aucun chemin d’attaque relevé."}
                    </span>
                    <span className="chips">
                      {r.severity && <span className={`tag ${SEV_CLASS[r.severity] ?? ""}`}>Risque {SEVERITY_FR[r.severity]?.toLowerCase() ?? r.severity}</span>}
                      {r.found && <span className="tag">{n(r.counts.vulnerableRuntime)} dépendance{r.counts.vulnerableRuntime > 1 ? "s" : ""} vulnérable{r.counts.vulnerableRuntime > 1 ? "s" : ""}</span>}
                      {(r.stack?.knownExploited ?? 0) > 0 && <span className="tag tag-bad">{r.stack!.knownExploited} exploitée{r.stack!.knownExploited > 1 ? "s" : ""}</span>}
                      {r.counts.publicExploit > 0 && <span className="tag tag-poc">{r.counts.publicExploit} avec exploit public</span>}
                      {(r.stack?.malicious ?? 0) > 0 && <span className="tag tag-bad">Paquet malveillant</span>}
                      {r.counts.activeSecrets > 0 && <span className="tag tag-bad">{r.counts.activeSecrets} secret{r.counts.activeSecrets > 1 ? "s" : ""} actif{r.counts.activeSecrets > 1 ? "s" : ""}</span>}
                      {r.escalations.length > 0 && <span className="tag tag-esc">{r.escalations.length} escalade{r.escalations.length > 1 ? "s" : ""} (30 j)</span>}
                      {(r.scanId || scan[r.repo]) && <span className="tag tag-stack">{scan[r.repo] ?? "analyse en cours"}</span>}
                    </span>
                  </span>
                  <Icon name="chevron" size={14} className={isOpen ? "rot90" : ""} />
                </button>
                {isOpen && (
                  <div className="repo-detail">
                    {!r.found ? (
                      <>
                        {r.candidates.length > 0 && <p className="hint">Noms proches dans l’index : {r.candidates.join(", ")}</p>}
                        {canEdit && !r.scanId && (
                          <button type="button" className="btn-secondary btn-sm" onClick={() => startScan(r.repo)}>
                            Analyser ce dépôt (quelques minutes)
                          </button>
                        )}
                      </>
                    ) : (
                      <>
                        <div className="tiles sc-tiles">
                          <div className="tile">
                            <span className="tile-k">Score de risque</span>
                            <span className="tile-v">{r.riskScore ?? "–"}/100</span>
                            <span className="tile-n">{r.percentile != null ? `plus risqué que ${r.percentile} % des dépôts` : ""}</span>
                          </div>
                          <div className="tile">
                            <span className="tile-k">Paquets concernés</span>
                            <span className="tile-v">{r.stack ? n(r.stack.affected) : "–"}</span>
                            <span className="tile-n">{r.stack ? `sur ${n(r.stack.packages)} analysés` : ""}</span>
                          </div>
                          <div className="tile">
                            <span className="tile-k">Critiques / hautes</span>
                            <span className="tile-v">{r.stack ? `${r.stack.bySeverity.critical ?? 0} / ${r.stack.bySeverity.high ?? 0}` : "–"}</span>
                            <span className="tile-n">dépendances concernées</span>
                          </div>
                          <div className="tile">
                            <span className="tile-k">Contributeurs exposés</span>
                            <span className="tile-v">{n(r.counts.contributorsWithLeak)}</span>
                            <span className="tile-n">identifiants dans une fuite</span>
                          </div>
                        </div>

                        {r.entryPoints.length > 0 && (
                          <>
                            <h3 className="sec-title">Points d’entrée</h3>
                            <ul className="repo-list">
                              {r.entryPoints.map((e) => (
                                <li key={e.type}>
                                  <strong>{fr(PATH_FR, e.type)}</strong> ({n(e.count)}) : {fr(FIX_FR, e.fix)}
                                </li>
                              ))}
                            </ul>
                          </>
                        )}

                        {r.upgrades.length > 0 && (
                          <>
                            <h3 className="sec-title">Mises à jour à faire d’abord</h3>
                            <ul className="repo-list">
                              {r.upgrades.map((u) => (
                                <li key={u.manifest + u.direct}>
                                  <span className={`tag ${SEV_CLASS[u.worst ?? ""] ?? ""}`}>{SEVERITY_FR[u.worst ?? ""] ?? "—"}</span> <code>{u.direct ?? u.manifest}</code>
                                  <span className="hint"> · {u.manifest} · {u.affected} paquet{u.affected > 1 ? "s" : ""}</span>
                                  {u.packages.length > 0 && (
                                    <div className="hint repo-pk">
                                      {u.packages.map((p) => (
                                        <span key={p.input}>
                                          {p.input}
                                          {p.fixed ? ` → ${p.fixed}` : ""}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </li>
                              ))}
                            </ul>
                          </>
                        )}

                        {r.escalations.length > 0 && (
                          <>
                            <h3 className="sec-title">Escalades récentes sur ses dépendances</h3>
                            <ul className="repo-list">
                              {r.escalations.slice(0, 10).map((e) => (
                                <li key={e.cve + e.kind}>
                                  <a href={`/cve/${e.cve}`}>{e.cve}</a> · {ESCALATION_FR[e.kind]} · <span className="hint">{e.date}</span>
                                </li>
                              ))}
                            </ul>
                          </>
                        )}
                      </>
                    )}
                    <div className="repo-actions">
                      <a className="btn-secondary btn-sm" href={`https://securitycontext.com/repo/${r.repo}`} target="_blank" rel="noreferrer">
                        Rapport complet <Icon name="external" size={13} />
                      </a>
                      {canEdit && (
                        <button type="button" className="btn-secondary btn-sm" onClick={() => remove(r.repo)}>
                          Ne plus suivre
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <p className="hint">
        Données :{" "}
        <a href="https://securitycontext.com" target="_blank" rel="noreferrer">
          SecurityContext par ProjectDiscovery
        </a>{" "}
        (dépendances déclarées, sans vision du déploiement : « listé » signifie exposé, pas compromis).
      </p>
    </div>
  );
}
