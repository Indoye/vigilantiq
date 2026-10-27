"use client";

import { useEffect, useState } from "react";
import { hostOf, relTime } from "@/lib/format";
import type { ExploitRef, Remediation, RemediationKind, TicketRef } from "@/lib/types";
import { Icon } from "./ui";

// ---------- État des connecteurs (chargé une fois par page) ----------

export interface ConnectorState {
  id: "jira" | "servicenow" | "xsoar" | "siem";
  name: string;
  kind: "ticket" | "event";
  configured: boolean;
  missing: string[];
  auto: boolean;
}

export interface ConnectorsInfo {
  connectors: ConnectorState[];
  autoMinPriority: string;
  apiTokens: boolean;
  canTest: boolean;
  pocMonitor: { githubToken: boolean };
}

let cache: Promise<ConnectorsInfo | null> | null = null;

export function useConnectors(): ConnectorsInfo | null {
  const [info, setInfo] = useState<ConnectorsInfo | null>(null);
  useEffect(() => {
    let alive = true;
    cache ??= fetch("/api/connectors", { cache: "no-store" })
      .then((r) => (r.ok ? (r.json() as Promise<ConnectorsInfo>) : null))
      .catch(() => null);
    cache.then((v) => {
      if (!v) cache = null;
      if (alive) setInfo(v);
    });
    return () => {
      alive = false;
    };
  }, []);
  return info;
}

// ---------- Remédiation ----------

const KIND_LABEL: Record<RemediationKind, string> = {
  correctif: "Corriger",
  contournement: "En attendant",
  detection: "Détecter",
  verification: "Vérifier",
};
const KIND_ORDER: RemediationKind[] = ["correctif", "contournement", "detection", "verification"];

export function RemediationSection({ r, id }: { r: Remediation; id: string }) {
  return (
    <section aria-labelledby={`rem-${id}`}>
      <h3 className="sec-title" id={`rem-${id}`}>
        Remédiation
      </h3>
      <div className={`rem-head ${r.patchAvailable ? "rem-ok" : "rem-wait"}`}>
        <Icon name="wrench" size={18} />
        <div>
          <p className="rem-summary">{r.summary}</p>
          <p className="rem-deadline">Délai recommandé : {r.deadline}</p>
        </div>
      </div>
      <div className="rem-groups">
        {KIND_ORDER.map((k) => {
          const steps = r.steps.filter((s) => s.kind === k);
          if (!steps.length) return null;
          return (
            <div key={k} className="rem-group">
              <p className={`rem-kind rk-${k}`}>{KIND_LABEL[k]}</p>
              <ol className="rem-steps">
                {steps.map((s, i) => (
                  <li key={i}>
                    <p>
                      {s.text} <span className="rem-src">{s.source}</span>
                    </p>
                    {s.originalFr && <p className="rem-fr">{s.originalFr}</p>}
                    {s.original && (
                      <details className="rem-orig">
                        <summary>{s.originalFr ? "Texte d’origine" : "Texte de la source (anglais)"}</summary>
                        <p lang="en">{s.original}</p>
                      </details>
                    )}
                    {s.url && (
                      <a href={s.url} target="_blank" rel="noreferrer" className="rem-link">
                        {hostOf(s.url)} <Icon name="external" size={12} />
                      </a>
                    )}
                  </li>
                ))}
              </ol>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ---------- Exploits et PoC ----------

const SOURCE_NAME: Record<string, string> = { github: "GitHub", exploitdb: "Exploit-DB" };

export function ExploitsSection({ list, id, loading }: { list: ExploitRef[]; id: string; loading?: boolean }) {
  const [all, setAll] = useState(false);
  if (!list.length) {
    return loading ? null : (
      <section aria-labelledby={`poc-${id}`}>
        <h3 className="sec-title" id={`poc-${id}`}>
          Exploits et PoC publics
        </h3>
        <p className="muted-box">Aucun code d’exploitation public repéré sur GitHub ni sur Exploit-DB.</p>
      </section>
    );
  }
  const shown = all ? list : list.slice(0, 5);
  return (
    <section aria-labelledby={`poc-${id}`}>
      <h3 className="sec-title" id={`poc-${id}`}>
        Exploits et PoC publics ({list.length})
      </h3>
      <ul className="group linklist">
        {shown.map((e) => (
          <li key={e.url}>
            <a href={e.url} target="_blank" rel="noreferrer" className="linkrow">
              <span className="linkrow-main">
                <span className="linkrow-title">{e.title}</span>
                {e.description && <span className="linkrow-sub poc-desc">{e.description}</span>}
                <span className="linkrow-sub">
                  {SOURCE_NAME[e.source] ?? e.source}
                  {e.stars > 0 && (
                    <>
                      {" · "}
                      <Icon name="star" size={11} /> {e.stars}
                    </>
                  )}
                  {e.publishedAt ? ` · publié ${relTime(e.publishedAt)}` : ""}
                </span>
              </span>
              <Icon name="external" size={15} className="linkrow-icon" />
            </a>
          </li>
        ))}
      </ul>
      {list.length > 5 && (
        <button type="button" className="btn-plain more" onClick={() => setAll(!all)}>
          {all ? "Afficher moins" : `Afficher les ${list.length - 5} autres`}
        </button>
      )}
      <p className="hint poc-warn">
        Code non vérifié, publié par des tiers : certains dépôts sont faux ou piégés. À n’exécuter que dans un environnement isolé.
      </p>
    </section>
  );
}

// ---------- Envoi vers les outils ----------

export function SendToTools({ cveId, initial }: { cveId: string; initial: TicketRef[] }) {
  const info = useConnectors();
  const [tickets, setTickets] = useState<TicketRef[]>(initial);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Le tableau reçu change d'identité à chaque rendu : on ne resynchronise que si son contenu change.
  const sig = initial.map((t) => `${t.connector}:${t.externalId}`).join("|");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => setTickets(initial), [sig]);

  const configured = info?.connectors.filter((c) => c.configured) ?? [];
  if (!info || configured.length === 0) return null;

  const send = async (c: ConnectorState) => {
    setBusy(c.id);
    setMsg(null);
    try {
      const res = await fetch(`/api/v1/vulns/${cveId}/tickets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ connector: c.id }),
      });
      const j = await res.json();
      if (j.ticket) setTickets((t) => [...t.filter((x) => x.connector !== c.id), j.ticket]);
      if (res.ok) setMsg({ ok: true, text: c.kind === "event" ? `Envoyé au ${c.name}.` : `Ticket ${j.ticket?.externalId ?? ""} créé dans ${c.name}.` });
      else setMsg({ ok: res.status === 409 && Boolean(j.ticket), text: j.error ?? `Erreur ${res.status}` });
    } catch {
      setMsg({ ok: false, text: "Réseau indisponible. Réessayez." });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="send-tools" role="group" aria-label="Envoyer vers les outils de l'équipe">
      <span className="status-label">Envoyer vers</span>
      <div className="send-row">
        {configured.map((c) => {
          const t = tickets.find((x) => x.connector === c.id);
          if (t) {
            return t.url ? (
              <a key={c.id} href={t.url} target="_blank" rel="noreferrer" className="btn-secondary btn-sent">
                <Icon name="check" size={14} /> {c.name} {t.externalId && t.externalId !== "envoyé" ? t.externalId : ""}
              </a>
            ) : (
              <span key={c.id} className="btn-secondary btn-sent" aria-disabled="true">
                <Icon name="check" size={14} /> {c.kind === "event" ? `${c.name} : envoyé` : `${c.name} ${t.externalId}`}
              </span>
            );
          }
          return (
            <button key={c.id} type="button" className="btn-secondary" disabled={busy !== null} onClick={() => send(c)}>
              <Icon name="send" size={14} />
              {busy === c.id ? "Envoi…" : c.name}
            </button>
          );
        })}
      </div>
      {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
    </div>
  );
}

// ---------- Panneau d'administration (Mon compte) ----------

const AUTO_SCOPE: Record<string, string> = {
  urgente: "urgentes",
  haute: "urgentes et hautes",
  moyenne: "de priorité moyenne ou plus",
  basse: "de toutes priorités",
};

export function IntegrationsPanel() {
  const info = useConnectors();
  const [testing, setTesting] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { ok: boolean; message: string }>>({});

  if (!info) return <p className="hint">Chargement des intégrations…</p>;

  const test = async (id: string) => {
    setTesting(id);
    try {
      const res = await fetch("/api/connectors/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ connector: id }) });
      const j = await res.json();
      setResults((r) => ({ ...r, [id]: { ok: Boolean(j.ok), message: j.message ?? j.error ?? `Erreur ${res.status}` } }));
    } catch {
      setResults((r) => ({ ...r, [id]: { ok: false, message: "Réseau indisponible." } }));
    } finally {
      setTesting(null);
    }
  };

  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return (
    <>
      <div className="cells">
        {info.connectors.map((c) => (
          <div key={c.id} className="cell cell-col" style={{ gap: 6 }}>
            <div className="cell" style={{ padding: 0, minHeight: 0 }}>
              <div className="cell-main">
                <span className="cell-title">{c.name}</span>
                <span className="cell-sub">
                  {c.configured
                    ? `${c.kind === "event" ? "Événements" : "Tickets"} : manuel depuis chaque fiche${c.auto ? `, et automatique pour les CVE ${AUTO_SCOPE[info.autoMinPriority] ?? "prioritaires"}` : ""}`
                    : `Non configuré. Variables à ajouter : ${c.missing.join(", ")}`}
                </span>
              </div>
              {c.configured ? (
                info.canTest ? (
                  <button type="button" className="btn-link" onClick={() => test(c.id)} disabled={testing !== null}>
                    {testing === c.id ? "Test…" : "Tester"}
                  </button>
                ) : (
                  <span className="tag tag-good">Actif</span>
                )
              ) : (
                <span className="tag">Inactif</span>
              )}
            </div>
            {results[c.id] && <p className={`form-msg ${results[c.id].ok ? "form-ok" : "form-err"}`}>{results[c.id].message}</p>}
          </div>
        ))}
        <div className="cell cell-col" style={{ gap: 4 }}>
          <span className="cell-title">API REST</span>
          <span className="cell-sub">
            {info.apiTokens ? "Jetons configurés." : "Aucun jeton : ajoutez VIGILANTIQ_API_TOKENS pour brancher SIEM, SOAR et scripts."} Point d’entrée :{" "}
            <code>{origin}/api/v1</code>
          </span>
        </div>
        <div className="cell cell-col" style={{ gap: 4 }}>
          <span className="cell-title">Moniteur de PoC</span>
          <span className="cell-sub">
            Chaque matin : recherche GitHub, PoC-in-GitHub et Exploit-DB. {info.pocMonitor.githubToken ? "Jeton GitHub configuré." : "Ajoutez GITHUB_TOKEN pour élargir la recherche."}
          </span>
        </div>
      </div>
      <p className="hint">La configuration se fait par l’administrateur dans les variables d’environnement du projet Vercel ; les secrets ne sont jamais affichés ici.</p>
    </>
  );
}

// ---------- Autres vulnérabilités avec PoC (vue « PoC publics ») ----------

interface PocGroup {
  cveId: string;
  count: number;
  latest: string;
  top: ExploitRef;
}

/** Regroupe les PoC par vulnérabilité, les plus récemment détectées d'abord. */
function groupByCve(items: ExploitRef[], exclude: Map<string, unknown>): PocGroup[] {
  const map = new Map<string, ExploitRef[]>();
  for (const e of items) {
    if (exclude.has(e.cveId)) continue;
    map.set(e.cveId, [...(map.get(e.cveId) ?? []), e]);
  }
  return [...map.entries()]
    .map(([cveId, list]) => {
      const sorted = [...list].sort((a, b) => b.stars - a.stars);
      const latest = list.map((e) => e.firstSeen ?? e.publishedAt ?? "").sort().pop() ?? "";
      return { cveId, count: list.length, latest, top: sorted[0] };
    })
    .sort((a, b) => b.latest.localeCompare(a.latest));
}

/**
 * Vulnérabilités hors du flux du jour pour lesquelles le moniteur a détecté un PoC (30 derniers jours).
 * Chaque ligne est une vulnérabilité : on la touche pour ouvrir sa fiche et voir ses PoC.
 */
export function OtherPocCves({
  exclude,
  selected,
  onSelect,
  onLoaded,
}: {
  exclude: Map<string, unknown>;
  selected: string | null;
  onSelect: (id: string) => void;
  /** Transmet les PoC chargés : la fiche peut les afficher même si NVD et CVE.org ne répondent pas. */
  onLoaded?: (items: ExploitRef[]) => void;
}) {
  const [items, setItems] = useState<ExploitRef[] | null>(null);
  useEffect(() => {
    let alive = true;
    fetch("/api/v1/exploits?days=30&limit=600", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : { items: [] }))
      .then((j) => {
        if (!alive) return;
        setItems(j.items ?? []);
        onLoaded?.(j.items ?? []);
      })
      .catch(() => alive && setItems([]));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  if (!items) return null;
  const groups = groupByCve(items, exclude);
  if (!groups.length) return null;
  return (
    <section className="other-pocs" aria-labelledby="h-other-pocs">
      <h2 id="h-other-pocs" className="sec-title other-title">
        Autres vulnérabilités avec PoC <span>· détectés ces 30 derniers jours</span>
      </h2>
      <ul className="list card">
        {groups.slice(0, 60).map((g) => (
          <li key={g.cveId}>
            <button type="button" className={`row poc-row${selected === g.cveId ? " is-sel" : ""}`} aria-pressed={selected === g.cveId} onClick={() => onSelect(g.cveId)}>
              <span className="poc-count" aria-hidden="true">
                <Icon name="code" size={16} />
              </span>
              <span className="row-main">
                <span className="row-top">
                  <span className="row-product">{g.cveId}</span>
                </span>
                <span className="chips">
                  <span className="tag tag-poc">
                    {g.count} PoC
                  </span>
                  <span className="tag">{SOURCE_NAME[g.top.source] ?? g.top.source}</span>
                  {g.top.stars > 0 && <span className="tag">★ {g.top.stars}</span>}
                </span>
              </span>
              <span className="row-meta">
                <span>{g.latest ? `détecté ${relTime(g.latest)}` : ""}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
