"use client";

import { useState, type ReactNode } from "react";
import type { AssetRow, FindingRow, SiemView } from "@/lib/hunt/store";
import { relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Kpi, Skeleton, useJson } from "../cti/common";

interface Run {
  id: number;
  kind: string;
  trigger: string;
  stats: Record<string, unknown>;
  report: string | null;
  model: string | null;
  error: string | null;
  startedAt: string;
  finishedAt: string | null;
}
interface Overview {
  assets: AssetRow[];
  findings: FindingRow[];
  siem: SiemView | null;
  leaks: {
    darkweb: { title: string; status: string; score: number; mode: string; count: number; source: string; postedAt: string | null }[];
    accounts: Record<string, number>;
    infostealers: number;
    exfiltration: number;
  };
  observations: number;
  iocs: { total: number; sources: { name: string; ok: boolean; count: number }[]; generatedAt: string } | null;
  runs: Run[];
  ai: { configured: boolean; provider: string | null; model: string | null };
}
interface Kit {
  id: number;
  key: string;
  scripts: { windows: string; unix: string };
  install: { windows: string[]; unix: string[] };
}

const SEV_LABEL: Record<string, string> = { critique: "Critique", haute: "Haute", moyenne: "Moyenne", info: "Info" };
const KIND_LABEL: Record<string, string> = { ioc: "IOC connu", exfiltration: "Exfiltration possible", tunnel_dns: "Tunnel DNS", tor: "Réseau Tor", ressemblant: "Domaine ressemblant" };
const STATUS_LABEL: Record<string, string> = { nouveau: "Nouveau", en_cours: "En cours", resolu: "Résolu", faux_positif: "Faux positif" };
const TYPE_LABEL: Record<string, string> = { ip: "Adresse IP", domain: "Domaine", url: "URL", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" };
const ASSET_KINDS: [string, string][] = [
  ["poste", "Poste de travail"],
  ["serveur", "Serveur"],
  ["reseau", "Équipement réseau"],
  ["cloud", "Instance cloud"],
  ["autre", "Autre"],
];

async function send(url: string, method: string, body?: unknown) {
  const r = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
  return j;
}

function verdict(a: AssetRow, now: number): { label: string; cls: string } {
  if (!a.lastSeenAt) return { label: "En attente de données", cls: "tag" };
  if (a.worst === "critique") return { label: "Compromis probable", cls: "tag tag-bad" };
  if (a.worst === "haute" || a.worst === "moyenne") return { label: "Suspect", cls: "tag tag-prio p-haute" };
  if (a.source === "agent" && now - Date.parse(a.lastSeenAt) > 2 * 3600_000) return { label: "Agent silencieux", cls: "tag" };
  return { label: "Aucune trace", cls: "tag tag-good" };
}

/** Threat Hunting : équipements, agent collecteur, connecteur SIEM/EDR, détections et enquête de l'agent IA. */
export default function HuntView({ now, guest }: { now: number; guest: boolean }) {
  const { data, error, loading, reload } = useJson<Overview>(guest ? null : "/api/hunt", 120_000);
  const [busy, setBusy] = useState<"" | "hunt" | "ai">("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [report, setReport] = useState<Run | null>(null);

  if (guest) {
    return (
      <div className="empty card">
        <p className="empty-title">Threat Hunting réservé aux comptes</p>
        <p>
          Installez l’agent collecteur sur vos postes et serveurs ou branchez votre SIEM : VigilantIQ y recherche en continu les indicateurs de
          compromission connus et les signes de fuite de données, et son agent IA rédige l’enquête. <a href="/connexion">Connectez-vous avec un compte</a>.
        </p>
      </div>
    );
  }
  if (loading && !data) return <Skeleton />;
  if (error && !data) return <p className="callout callout-err">{error}</p>;
  if (!data) return null;

  const open = data.findings.filter((f) => f.status === "nouveau" || f.status === "en_cours");
  const crit = open.filter((f) => f.severity === "critique").length;
  const online = data.assets.filter((a) => a.lastSeenAt && now - Date.parse(a.lastSeenAt) < 2 * 3600_000).length;
  const lastAi = report ?? data.runs.find((r) => r.kind === "enquete" && r.report) ?? null;
  const lastHunt = data.runs.find((r) => r.kind === "chasse");

  const run = async (what: "hunt" | "ai") => {
    setBusy(what);
    setMsg(null);
    try {
      if (what === "hunt") {
        const j = await send("/api/hunt/run", "POST");
        setMsg({ ok: true, text: `Chasse terminée : ${fmtInt(j.observations)} observables comparés à ${fmtInt(j.iocs)} IOC, ${j.findings} nouvelle(s) détection(s).` });
      } else {
        const j = await send("/api/hunt/investigate", "POST");
        setReport({ id: j.id, kind: "enquete", trigger: "manuel", stats: { steps: j.steps }, report: j.report, model: j.model, error: null, startedAt: new Date().toISOString(), finishedAt: new Date().toISOString() });
      }
      await reload();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Opération impossible" });
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="cti hunt">
      <section className="tiles">
        <Kpi k="Équipements" v={fmtInt(data.assets.length)} n={`${online} actif${online > 1 ? "s" : ""} ces 2 dernières heures`} />
        <Kpi k="Détections ouvertes" v={fmtInt(open.length)} n={crit ? `dont ${crit} critique${crit > 1 ? "s" : ""}` : "aucune critique"} />
        <Kpi k="Observables" v={fmtInt(data.observations)} n="connexions, DNS, exécutables (30 j)" />
        <Kpi k="IOC comparés" v={data.iocs ? fmtInt(data.iocs.total) : "–"} n={lastHunt ? `chasse ${relTime(lastHunt.startedAt, now)}` : "flux d’IOC du jour"} />
      </section>

      <section className="card tm-panel">
        <div className="hunt-head">
          <div>
            <h2>
              <Icon name="shield" size={16} /> Agent IA d’enquête
            </h2>
            <p className="hint">
              {data.ai.configured
                ? `Moteur : ${data.ai.model} (${data.ai.provider}). L’agent interroge vos détections, observables, IOC et fuites, puis rédige l’enquête.`
                : "Aucun fournisseur IA configuré : le rapport est produit par règles. Ajoutez AI_API_KEY, AI_MODEL et AI_BASE_URL pour activer l’agent IA."}
            </p>
          </div>
          <div className="watch-actions">
            <button type="button" className="btn-secondary" onClick={() => run("hunt")} disabled={Boolean(busy)}>
              <Icon name="refresh" size={15} className={busy === "hunt" ? "spin" : ""} /> {busy === "hunt" ? "Chasse…" : "Relancer la chasse"}
            </button>
            <button type="button" className="btn-primary watch-add" onClick={() => run("ai")} disabled={Boolean(busy)}>
              {busy === "ai" ? "Enquête en cours…" : "Lancer l’enquête"}
            </button>
          </div>
        </div>
        {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
        {busy === "ai" && <p className="hint">L’agent examine vos équipements ; cela peut prendre jusqu’à une minute.</p>}
        {lastAi?.report ? (
          <article className="hunt-report">
            <p className="hint">
              Enquête {relTime(lastAi.startedAt, now)}
              {lastAi.model ? ` · ${lastAi.model}` : " · rapport par règles"}
            </p>
            <Markdown text={lastAi.report} />
          </article>
        ) : (
          <p className="hint">Aucune enquête pour le moment.</p>
        )}
      </section>

      <Findings findings={data.findings} now={now} onChange={reload} />
      <Assets assets={data.assets} now={now} onChange={reload} />
      <Siem siem={data.siem} now={now} onChange={reload} />
      <Leaks leaks={data.leaks} />
    </div>
  );
}

// ---------- Détections ----------

function Findings({ findings, now, onChange }: { findings: FindingRow[]; now: number; onChange: () => void }) {
  const [all, setAll] = useState(false);
  const list = findings.filter((f) => all || f.status === "nouveau" || f.status === "en_cours");
  const setStatus = async (id: number, status: string) => {
    try {
      await send("/api/hunt/findings", "PATCH", { id, status });
      onChange();
    } catch {
      /* l'état sera rechargé au prochain rafraîchissement */
    }
  };
  return (
    <section className="card tm-panel">
      <div className="hunt-head">
        <h2>Détections</h2>
        <div className="segmented" role="group" aria-label="Filtre des détections">
          <button type="button" aria-pressed={!all} className={!all ? "is-on" : ""} onClick={() => setAll(false)}>
            Ouvertes
          </button>
          <button type="button" aria-pressed={all} className={all ? "is-on" : ""} onClick={() => setAll(true)}>
            Toutes
          </button>
        </div>
      </div>
      {list.length === 0 ? (
        <p className="hint">Aucune trace de compromission détectée{all ? "" : " en cours"}.</p>
      ) : (
        <ul className="acc-list">
          {list.map((f) => (
            <li key={f.id} className={`acc-item sev-${f.severity}`}>
              <details>
                <summary>
                  <span className="sev-dot" aria-hidden="true" />
                  <span className="acc-main">
                    <span className="acc-email">{f.threat || KIND_LABEL[f.kind]}</span>
                    <span className="chips">
                      <span className="tag">{SEV_LABEL[f.severity]}</span>
                      <span className="tag">{KIND_LABEL[f.kind] ?? f.kind}</span>
                      {f.asset && <span className="tag tag-stack">{f.asset}</span>}
                      {f.status !== "nouveau" && <span className="tag">{STATUS_LABEL[f.status]}</span>}
                    </span>
                    <span className="cti-desc">
                      {TYPE_LABEL[f.indicatorType] ?? f.indicatorType} <code>{f.indicator}</code> · {f.source}
                      {f.malware ? ` · ${f.malware}` : ""}
                    </span>
                  </span>
                  <span className="cti-side">
                    <span className="hint">{relTime(f.lastSeen, now)}</span>
                  </span>
                </summary>
                <div className="acc-detail">
                  <dl className="dw-facts">
                    <dt>Première fois</dt>
                    <dd>{relTime(f.firstSeen, now)}</dd>
                    {Object.entries(f.evidence)
                      .filter(([k]) => !["ref"].includes(k))
                      .slice(0, 8)
                      .map(([k, v]) => (
                        <Fact key={k} k={k} v={v} />
                      ))}
                    {typeof f.evidence.ref === "string" && f.evidence.ref && (
                      <>
                        <dt>Référence</dt>
                        <dd>
                          <a href={f.evidence.ref} target="_blank" rel="noreferrer">
                            {f.source}
                          </a>
                        </dd>
                      </>
                    )}
                  </dl>
                  <div className="segmented" role="group" aria-label="Statut de la détection">
                    {Object.entries(STATUS_LABEL).map(([k, l]) => (
                      <button key={k} type="button" aria-pressed={f.status === k} className={f.status === k ? "is-on" : ""} onClick={() => setStatus(f.id, k)}>
                        {l}
                      </button>
                    ))}
                  </div>
                </div>
              </details>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const FACT_FR: Record<string, string> = { process: "Processus", port: "Port", path: "Chemin", hits: "Occurrences", bytesOut: "Octets envoyés", ioc: "IOC", note: "Remarque", ressemble: "Ressemble à", exemples: "Exemples" };
function Fact({ k, v }: { k: string; v: unknown }) {
  const val = Array.isArray(v) ? v.join(", ") : typeof v === "number" && k === "bytesOut" ? `${fmtInt(Math.round(v / 1048576))} Mo` : String(v);
  if (!val) return null;
  return (
    <>
      <dt>{FACT_FR[k] ?? k}</dt>
      <dd>
        <code>{val}</code>
      </dd>
    </>
  );
}

// ---------- Équipements et agent collecteur ----------

function Assets({ assets, now, onChange }: { assets: AssetRow[]; now: number; onChange: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState("poste");
  const [kit, setKit] = useState<(Kit & { name: string }) | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      const j = (await send("/api/hunt/assets", "POST", { name, kind })) as Kit;
      setKit({ ...j, name });
      setName("");
      onChange();
    } catch (x) {
      setErr(x instanceof Error ? x.message : "Création impossible");
    }
  };
  const rotate = async (a: AssetRow) => {
    try {
      const j = (await send("/api/hunt/assets", "PATCH", { id: a.id, rotate: true })) as Kit;
      setKit({ ...j, name: a.name });
      onChange();
    } catch (x) {
      setErr(x instanceof Error ? x.message : "Opération impossible");
    }
  };
  const remove = async (a: AssetRow) => {
    if (!window.confirm(`Supprimer « ${a.name} » et ses données collectées ?`)) return;
    await send(`/api/hunt/assets?id=${a.id}`, "DELETE").catch(() => null);
    onChange();
  };
  return (
    <section className="card tm-panel">
      <h2>Équipements</h2>
      <p className="cti-desc">
        L’agent collecteur, en lecture seule, remonte toutes les 15 minutes les connexions établies, le cache DNS (Windows) et l’empreinte des
        exécutables en cours. Les équipements vus par votre SIEM/EDR s’ajoutent automatiquement.
      </p>
      {kit && <AgentKit kit={kit} onClose={() => setKit(null)} />}
      {assets.length > 0 ? (
        <ul className="dw-sources">
          {assets.map((a) => {
            const v = verdict(a, now);
            return (
              <li key={a.id}>
                <span className="acc-main">
                  <span className="acc-email">
                    {a.name} <span className={v.cls}>{v.label}</span>
                  </span>
                  <span className="cti-desc">
                    {a.source === "siem" ? "SIEM/EDR" : "Agent"}
                    {a.os ? ` · ${a.os}` : ""}
                    {a.lastIp ? ` · ${a.lastIp}` : ""} · {a.lastSeenAt ? `vu ${relTime(a.lastSeenAt, now)}` : "jamais vu"} · {fmtInt(a.observations)} observables
                    {a.open ? ` · ${a.open} détection${a.open > 1 ? "s" : ""}` : ""}
                  </span>
                </span>
                {a.source === "agent" && (
                  <button type="button" className="btn-plain" onClick={() => rotate(a)}>
                    {a.lastSeenAt ? "Nouvelle clé" : "Réinstaller"}
                  </button>
                )}
                <button type="button" className="btn-plain" onClick={() => remove(a)}>
                  Supprimer
                </button>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="hint">Aucun équipement pour le moment.</p>
      )}
      <form className="dw-form" onSubmit={create}>
        <div className="dw-grid">
          <label className="field">
            <span>Nom de l’équipement</span>
            <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="PC-COMPTA-01, srv-web…" />
          </label>
          <label className="field">
            <span>Type</span>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              {ASSET_KINDS.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="watch-actions">
          <button type="submit" className="btn-primary watch-add" disabled={!name.trim()}>
            Ajouter et obtenir l’agent
          </button>
        </div>
        {err && <p className="form-msg form-err">{err}</p>}
      </form>
    </section>
  );
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function AgentKit({ kit, onClose }: { kit: Kit & { name: string }; onClose: () => void }) {
  const [os, setOs] = useState<"windows" | "unix">("windows");
  return (
    <div className="verify-box">
      <p className="cti-title">
        <Icon name="key" size={14} /> Agent de « {kit.name} »
      </p>
      <p className="cti-desc">
        Le script contient la clé de cet équipement : téléchargez-le maintenant, il ne sera plus affiché. Il n’envoie que des métadonnées
        (adresses contactées, domaines, empreintes), jamais le contenu de vos fichiers.
      </p>
      <div className="segmented" role="group" aria-label="Système">
        <button type="button" aria-pressed={os === "windows"} className={os === "windows" ? "is-on" : ""} onClick={() => setOs("windows")}>
          Windows
        </button>
        <button type="button" aria-pressed={os === "unix"} className={os === "unix" ? "is-on" : ""} onClick={() => setOs("unix")}>
          Linux et macOS
        </button>
      </div>
      <div className="watch-actions">
        <button type="button" className="btn-primary watch-add" onClick={() => download(os === "windows" ? "agent.ps1" : "vigilantiq-agent.sh", kit.scripts[os])}>
          <Icon name="file" size={14} /> Télécharger {os === "windows" ? "agent.ps1" : "vigilantiq-agent.sh"}
        </button>
      </div>
      <ol className="hunt-steps">
        {kit.install[os].map((s) => (
          <li key={s}>
            <code>{s}</code>
          </li>
        ))}
      </ol>
      <div className="watch-actions">
        <button type="button" className="btn-secondary" onClick={onClose}>
          J’ai téléchargé l’agent
        </button>
      </div>
    </div>
  );
}

// ---------- Connecteur SIEM/EDR ----------

function Siem({ siem, now, onChange }: { siem: SiemView | null; now: number; onChange: () => void }) {
  const [edit, setEdit] = useState(!siem);
  const [f, setF] = useState({ type: siem?.type ?? "elastic", url: siem?.url ?? "", index: siem?.index ?? "wazuh-alerts-*", authKind: siem?.authKind === "basic" || siem?.authKind === "bearer" ? siem.authKind : siem ? "apikey" : "basic", user: "", password: "", token: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const done = (p: { error?: string; events?: number; hosts?: number; findings?: number } | undefined) =>
    p?.error ? { ok: false, text: p.error } : p ? { ok: true, text: `${fmtInt(p.events ?? 0)} événements lus, ${p.hosts ?? 0} équipement(s), ${p.findings ?? 0} nouvelle(s) détection(s).` } : null;
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const j = await send("/api/hunt/siem", "PUT", {
        type: f.type,
        url: f.url,
        index: f.index,
        auth: f.authKind === "basic" ? { kind: "basic", user: f.user, password: f.password } : { kind: f.authKind, token: f.token },
      });
      setMsg(done(j.pull));
      setF({ ...f, password: "", token: "" });
      setEdit(false);
      onChange();
    } catch (x) {
      setMsg({ ok: false, text: x instanceof Error ? x.message : "Enregistrement impossible" });
    } finally {
      setBusy(false);
    }
  };
  const pull = async () => {
    setBusy(true);
    setMsg(null);
    try {
      setMsg(done((await send("/api/hunt/siem", "POST")).pull));
      onChange();
    } catch (x) {
      setMsg({ ok: false, text: x instanceof Error ? x.message : "Collecte impossible" });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    await send("/api/hunt/siem", "DELETE").catch(() => null);
    setEdit(true);
    onChange();
  };
  return (
    <section className="card tm-panel">
      <h2>Connecteur SIEM/EDR</h2>
      <p className="cti-desc">
        Elastic Security, OpenSearch, Wazuh (indexeur) ou Splunk : VigilantIQ lit les événements des dernières 24 heures (adresses, DNS, URL,
        empreintes de fichiers) et y cherche les IOC. Les identifiants sont chiffrés ; un compte en lecture seule suffit. Le SIEM doit être
        joignable en HTTPS depuis Internet.
      </p>
      {siem && !edit && (
        <div className="hunt-siem">
          <span className="acc-main">
            <span className="acc-email">
              {siem.type === "splunk" ? "Splunk" : "Elastic / OpenSearch / Wazuh"} <span className={siem.lastError ? "tag tag-bad" : "tag tag-good"}>{siem.lastError ? "En erreur" : "Connecté"}</span>
            </span>
            <span className="cti-desc">
              {siem.url}
              {siem.index ? ` · ${siem.index}` : ""} · {siem.lastPullAt ? `dernière collecte ${relTime(siem.lastPullAt, now)}` : "jamais collecté"}
            </span>
            {siem.lastError && <span className="cti-desc">{siem.lastError}</span>}
          </span>
          <div className="watch-actions">
            <button type="button" className="btn-secondary" onClick={pull} disabled={busy}>
              <Icon name="refresh" size={15} className={busy ? "spin" : ""} /> Collecter maintenant
            </button>
            <button type="button" className="btn-plain" onClick={() => setEdit(true)}>
              Modifier
            </button>
            <button type="button" className="btn-plain" onClick={remove}>
              Supprimer
            </button>
          </div>
        </div>
      )}
      {edit && (
        <form className="dw-form" onSubmit={save}>
          <div className="dw-grid">
            <label className="field">
              <span>Type</span>
              <select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value as SiemView["type"], index: e.target.value === "splunk" ? "" : f.index })}>
                <option value="elastic">Elastic, OpenSearch, Wazuh</option>
                <option value="splunk">Splunk</option>
              </select>
            </label>
            <label className="field">
              <span>{f.type === "splunk" ? "Adresse de l’API (port 8089)" : "Adresse de l’API"}</span>
              <input required value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder={f.type === "splunk" ? "https://splunk.entreprise.sn:8089" : "https://siem.entreprise.sn:9200"} />
            </label>
            <label className="field">
              <span>{f.type === "splunk" ? "Index (facultatif)" : "Index ou motif"}</span>
              <input value={f.index} onChange={(e) => setF({ ...f, index: e.target.value })} placeholder={f.type === "splunk" ? "main" : "wazuh-alerts-*, logs-*"} />
            </label>
            <label className="field">
              <span>Authentification</span>
              <select value={f.authKind} onChange={(e) => setF({ ...f, authKind: e.target.value })}>
                <option value="basic">Utilisateur et mot de passe</option>
                {f.type === "elastic" && <option value="apikey">Clé d’API Elastic</option>}
                <option value="bearer">Jeton (Bearer)</option>
              </select>
            </label>
            {f.authKind === "basic" ? (
              <>
                <label className="field">
                  <span>Utilisateur</span>
                  <input required autoComplete="off" value={f.user} onChange={(e) => setF({ ...f, user: e.target.value })} />
                </label>
                <label className="field">
                  <span>Mot de passe</span>
                  <input required type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
                </label>
              </>
            ) : (
              <label className="field">
                <span>{f.authKind === "apikey" ? "Clé d’API (encodée)" : "Jeton"}</span>
                <input required type="password" autoComplete="new-password" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} />
              </label>
            )}
          </div>
          <div className="watch-actions">
            <button type="submit" className="btn-primary watch-add" disabled={busy}>
              {busy ? "Connexion…" : "Enregistrer et collecter"}
            </button>
            {siem && (
              <button type="button" className="btn-plain" onClick={() => setEdit(false)}>
                Annuler
              </button>
            )}
          </div>
        </form>
      )}
      {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
    </section>
  );
}

// ---------- Fuites de données ----------

function Leaks({ leaks }: { leaks: Overview["leaks"] }) {
  return (
    <section className="card tm-panel">
      <h2>Fuites de données</h2>
      <div className="tiles">
        <Kpi k="Annonces darkweb" v={fmtInt(leaks.darkweb.length)} n="rapprochées de vos domaines" />
        <Kpi k="Comptes exposés" v={fmtInt(leaks.accounts.exposed ?? 0)} n={`${fmtInt(leaks.infostealers)} infection(s) par infostealer`} />
        <Kpi k="Signes d’exfiltration" v={fmtInt(leaks.exfiltration)} n="partage, tunnel, Tor, gros envois" />
      </div>
      {leaks.darkweb.length > 0 && (
        <ul className="tm-list tm-list-compact">
          {leaks.darkweb.slice(0, 5).map((d, i) => (
            <li key={`${d.title}-${i}`}>
              <span className="cf-victim">{d.title}</span>
              <span className="tm-mw">{d.source}</span>
              <span className="tm-val">score {d.score}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="hint">Le détail est dans « Ma surveillance ». L’agent IA tient compte de ces fuites dans son enquête.</p>
    </section>
  );
}

// ---------- Rendu Markdown minimal (sans HTML) ----------

function inline(text: string): ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|_[^_]+_)/g);
  return parts.map((p, i) =>
    p.startsWith("**") && p.endsWith("**") ? (
      <strong key={i}>{p.slice(2, -2)}</strong>
    ) : p.startsWith("`") && p.endsWith("`") ? (
      <code key={i}>{p.slice(1, -1)}</code>
    ) : p.startsWith("_") && p.endsWith("_") && p.length > 2 ? (
      <em key={i}>{p.slice(1, -1)}</em>
    ) : (
      p
    ),
  );
}

export function Markdown({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  const flush = () => {
    if (!list) return;
    const items = list.items.map((it, i) => <li key={i}>{inline(it)}</li>);
    blocks.push(list.ordered ? <ol key={blocks.length}>{items}</ol> : <ul key={blocks.length}>{items}</ul>);
    list = null;
  };
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    const ul = /^\s*[-*•]\s+(.*)$/.exec(line);
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (h) {
      flush();
      blocks.push(<h3 key={blocks.length}>{inline(h[2])}</h3>);
    } else if (ul || ol) {
      const ordered = Boolean(ol);
      if (!list || list.ordered !== ordered) {
        flush();
        list = { ordered, items: [] };
      }
      list.items.push((ul ?? ol)![1]);
    } else if (!line.trim()) flush();
    else {
      flush();
      blocks.push(<p key={blocks.length}>{inline(line)}</p>);
    }
  }
  flush();
  return <div className="md">{blocks}</div>;
}
