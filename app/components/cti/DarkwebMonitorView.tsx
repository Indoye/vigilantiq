"use client";

import { useState } from "react";
import { dateFr, relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Kpi, Skeleton, useJson } from "./common";

type Kind = "keyword" | "phrase" | "regex" | "domain" | "email" | "wallet";
const KIND_FR: Record<Kind, string> = {
  keyword: "Mots-clés",
  phrase: "Expression exacte",
  regex: "Expression régulière",
  domain: "Domaine",
  email: "Adresse e-mail",
  wallet: "Portefeuille crypto",
};
const KIND_HELP: Record<Kind, string> = {
  keyword: "Tous les mots doivent figurer dans la page, dans n’importe quel ordre.",
  phrase: "Les mots dans cet ordre (ex. nom de produit, de projet, de dirigeant).",
  regex: "Appliquée mot par mot, sans espace (ex. vigil[a-z]*iq, ref-[0-9]{6}).",
  domain: "Adresses e-mail de ce domaine, mentions du domaine ou site qui le porte.",
  email: "Correspondance exacte par empreinte : l’adresse n’est jamais stockée en clair.",
  wallet: "Adresse publique Bitcoin, Ethereum, Monero, Tron…",
};
const PLACEHOLDER: Record<Kind, string> = {
  keyword: "entreprise base clients",
  phrase: "Projet Atlas",
  regex: "entrepr[i1]se",
  domain: "entreprise.sn",
  email: "dg@entreprise.sn",
  wallet: "bc1q…",
};
const SEV_FR: Record<string, string> = { critique: "Critique", haute: "Haute", moyenne: "Moyenne", info: "Info" };
const MATCH_FR: Record<string, string> = { nouvelle: "Nouvelle", traitee: "Traitée", faux_positif: "Faux positif" };

interface Status {
  apify: boolean;
  search: boolean;
  stats: { pages: number; hosts: number; last: string | null } | { error: string } | null;
  canEdit: boolean;
  platformAnalyst: boolean;
}
interface Pattern {
  id: number;
  name: string;
  kind: Kind;
  value: string;
  display: string;
  severity: string;
  active: boolean;
  createdAt: string;
  lastMatchAt: string | null;
  matchCount: number;
}
interface Match {
  id: number;
  patternId: number;
  pattern: string;
  kind: Kind;
  severity: string;
  url: string;
  host: string;
  snippet: string;
  status: string;
  collectedAt: string | null;
  createdAt: string;
}
interface Hit {
  id: string;
  url: string;
  host: string;
  collectedAt: string;
  snippet: string;
  counts: Record<string, number>;
}

async function send(url: string, method: string, body?: unknown) {
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
  return j;
}

/** Surligne les passages entre « » renvoyés par le cluster (texte déjà masqué, rendu sans HTML). */
function Snippet({ text }: { text: string }) {
  const parts = text.split(/(«[^»]*»)/g);
  return (
    <p className="dw-snippet">
      {parts.map((p, i) => (p.startsWith("«") && p.endsWith("»") ? <mark key={i}>{p.slice(1, -1)}</mark> : <span key={i}>{p}</span>))}
    </p>
  );
}

export default function DarkwebMonitorView({ now }: { now: number }) {
  const { data: st } = useJson<Status>("/api/darkweb");
  const [tab, setTab] = useState<"motifs" | "resultats" | "recherche" | "collecte">("motifs");
  const stats = st?.stats && "pages" in st.stats ? st.stats : null;
  const ready = Boolean(st?.apify && st?.search);

  return (
    <div className="cti">
      <section className="tiles">
        <Kpi k="Pages indexées" v={stats ? fmtInt(stats.pages) : "—"} n="texte masqué à l’ingestion" />
        <Kpi k="Sites .onion" v={stats ? fmtInt(stats.hosts) : "—"} n={stats?.last ? `dernière collecte ${relTime(stats.last)}` : "aucune collecte"} />
      </section>

      {st && !ready && (
        <p className="form-msg form-err">
          Collecte inactive :{" "}
          {[!st.apify && "jeton Apify (APIFY_TOKEN)", !st.search && "cluster OpenSearch / Elastic (DARKWEB_SEARCH_URL et ses identifiants)"].filter(Boolean).join(" et ")} à
          ajouter dans les variables d’environnement du projet. Vos motifs peuvent déjà être préparés.
        </p>
      )}
      {st?.stats && "error" in st.stats && <p className="form-msg form-err">{st.stats.error}</p>}

      <div className="segmented cti-seg" role="tablist" aria-label="Dark web">
        {(
          [
            ["motifs", "Motifs surveillés"],
            ["resultats", "Correspondances"],
            ...(st?.canEdit ? [["recherche", "Recherche"]] : []),
            ...(st?.platformAnalyst ? [["collecte", "Collecte"]] : []),
          ] as [typeof tab, string][]
        ).map(([k, l]) => (
          <button key={k} type="button" role="tab" aria-selected={tab === k} className={tab === k ? "is-on" : ""} onClick={() => setTab(k)}>
            {l}
          </button>
        ))}
      </div>

      {tab === "motifs" && <Patterns canEdit={Boolean(st?.canEdit)} now={now} />}
      {tab === "resultats" && <Matches canEdit={Boolean(st?.canEdit)} />}
      {tab === "recherche" && <Search />}
      {tab === "collecte" && <Collection now={now} />}
    </div>
  );
}

// ---------- Motifs ----------

function Patterns({ canEdit, now }: { canEdit: boolean; now: number }) {
  const { data, error, loading, reload } = useJson<{ patterns: Pattern[] }>("/api/darkweb/patterns");
  const [f, setF] = useState<{ name: string; kind: Kind; value: string; severity: string }>({ name: "", kind: "keyword", value: "", severity: "haute" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  void now;

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const j = await send("/api/darkweb/patterns", "POST", f);
      setMsg({ ok: true, text: j.retro ? `Motif ajouté : ${j.retro} page(s) déjà présente(s) dans le corpus.` : "Motif ajouté. Il sera appliqué à chaque nouvelle page collectée." });
      setF({ ...f, name: "", value: "" });
      reload();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Échec." });
    } finally {
      setBusy(false);
    }
  };
  const patch = async (body: Record<string, unknown>) => {
    try {
      await send("/api/darkweb/patterns", "PATCH", body);
      reload();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Échec." });
    }
  };
  const remove = async (p: Pattern) => {
    if (!window.confirm(`Supprimer le motif « ${p.name} » et ses correspondances ?`)) return;
    try {
      await send(`/api/darkweb/patterns?id=${p.id}`, "DELETE");
      reload();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Échec." });
    }
  };
  const list = data?.patterns ?? [];

  return (
    <section className="card tm-panel">
      <h2>Motifs surveillés</h2>
      <p className="cti-desc">
        Chaque page collectée sur les forums du dark web est confrontée à tous vos motifs dès son indexation. Une correspondance crée une alerte dans « Ma
        surveillance » et dans l’e-mail quotidien. Les motifs et leurs résultats ne sont visibles que de votre organisation.
      </p>
      {canEdit && (
        <form className="dw-form" onSubmit={create}>
          <div className="dw-grid">
            <label className="field">
              <span>Type</span>
              <select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as Kind })}>
                {(Object.keys(KIND_FR) as Kind[]).map((k) => (
                  <option key={k} value={k}>
                    {KIND_FR[k]}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Valeur</span>
              <input type={f.kind === "email" ? "email" : "text"} required maxLength={200} value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} placeholder={PLACEHOLDER[f.kind]} spellCheck={false} />
            </label>
            <label className="field">
              <span>Nom (facultatif)</span>
              <input type="text" maxLength={80} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Marque, VIP, projet…" />
            </label>
            <label className="field">
              <span>Gravité</span>
              <select value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>
                {Object.entries(SEV_FR).map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p className="hint">{KIND_HELP[f.kind]}</p>
          <div className="org-actions">
            <button type="submit" className="btn-secondary" disabled={busy}>
              {busy ? "Ajout et recherche…" : "Ajouter le motif"}
            </button>
          </div>
        </form>
      )}
      {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="form-msg form-err">{error}</p>
      ) : !list.length ? (
        <p className="hint">Aucun motif. Commencez par vos domaines, vos marques et les adresses de vos dirigeants.</p>
      ) : (
        <ul className="acc-list">
          {list.map((p) => (
            <li key={p.id} className="cti-item dw-row">
              <div className="cti-main">
                <p className="cti-title">
                  {p.name} {!p.active && <span className="tag">En pause</span>}
                </p>
                <p className="cti-alert-k">
                  {KIND_FR[p.kind]} · <code>{p.display}</code> · gravité {SEV_FR[p.severity]?.toLowerCase() ?? p.severity}
                </p>
                <p className="hint">
                  {p.matchCount ? `${fmtInt(p.matchCount)} correspondance(s), la dernière ${p.lastMatchAt ? relTime(p.lastMatchAt) : ""}` : "Aucune correspondance"} · créé le{" "}
                  {dateFr(p.createdAt)}
                </p>
              </div>
              {canEdit && (
                <div className="cti-side">
                  <button type="button" className="btn-link" onClick={() => patch({ id: p.id, active: !p.active })}>
                    {p.active ? "Mettre en pause" : "Réactiver"}
                  </button>
                  <button type="button" className="btn-link btn-link-danger" onClick={() => remove(p)}>
                    Supprimer
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ---------- Correspondances ----------

function Matches({ canEdit }: { canEdit: boolean }) {
  const [status, setStatus] = useState("nouvelle");
  const { data, error, loading, reload } = useJson<{ matches: Match[] }>(`/api/darkweb/matches${status ? `?statut=${status}` : ""}`);
  const set = async (id: number, s: string) => {
    await send("/api/darkweb/matches", "PATCH", { id, status: s }).catch(() => undefined);
    reload();
  };
  const list = data?.matches ?? [];
  return (
    <section className="card tm-panel">
      <h2>Correspondances</h2>
      <div className="segmented" role="group" aria-label="Statut">
        {["nouvelle", "traitee", "faux_positif", ""].map((s) => (
          <button key={s || "tous"} type="button" aria-pressed={status === s} className={status === s ? "is-on" : ""} onClick={() => setStatus(s)}>
            {s ? MATCH_FR[s] : "Toutes"}
          </button>
        ))}
      </div>
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="form-msg form-err">{error}</p>
      ) : !list.length ? (
        <p className="hint">Aucune correspondance dans cette catégorie.</p>
      ) : (
        <ul className="acc-list">
          {list.map((m) => (
            <li key={m.id} className="cti-item dw-row">
              <div className="cti-main">
                <p className="cti-alert-k">
                  <span className={`tag sev-${m.severity}`}>{SEV_FR[m.severity] ?? m.severity}</span> {m.pattern} · {KIND_FR[m.kind]}
                </p>
                <p className="cti-title dw-host">{m.host || "site .onion"}</p>
                <Snippet text={m.snippet} />
                <p className="hint">
                  <code className="dw-url">{m.url}</code> · collectée {m.collectedAt ? relTime(m.collectedAt) : ""}
                </p>
              </div>
              {canEdit && (
                <div className="cti-side">
                  {m.status !== "traitee" && (
                    <button type="button" className="btn-link" onClick={() => set(m.id, "traitee")}>
                      Traitée
                    </button>
                  )}
                  {m.status !== "faux_positif" && (
                    <button type="button" className="btn-link" onClick={() => set(m.id, "faux_positif")}>
                      Faux positif
                    </button>
                  )}
                  {m.status !== "nouvelle" && (
                    <button type="button" className="btn-link" onClick={() => set(m.id, "nouvelle")}>
                      Rouvrir
                    </button>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className="hint">Les adresses .onion s’ouvrent uniquement avec le navigateur Tor. Les e-mails, mots de passe, clés et numéros ont été masqués avant stockage.</p>
    </section>
  );
}

// ---------- Recherche ad hoc ----------

function Search() {
  const [kind, setKind] = useState<Kind>("keyword");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ total: number; hits: Hit[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      setRes(await send("/api/darkweb/search", "POST", { kind, value }));
    } catch (x) {
      setErr(x instanceof Error ? x.message : "Échec.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card tm-panel">
      <h2>Recherche dans le corpus</h2>
      <p className="cti-desc">Interrogez tout le corpus collecté (texte masqué) avec les mêmes types de motifs, avant d’en faire une surveillance permanente.</p>
      <form className="dw-form" onSubmit={run}>
        <div className="dw-grid">
          <label className="field">
            <span>Type</span>
            <select value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
              {(Object.keys(KIND_FR) as Kind[]).map((k) => (
                <option key={k} value={k}>
                  {KIND_FR[k]}
                </option>
              ))}
            </select>
          </label>
          <label className="field dw-wide">
            <span>Recherche</span>
            <input type="search" required value={value} onChange={(e) => setValue(e.target.value)} placeholder={PLACEHOLDER[kind]} spellCheck={false} />
          </label>
        </div>
        <div className="org-actions">
          <button type="submit" className="btn-secondary" disabled={busy}>
            <Icon name="search" size={14} /> {busy ? "Recherche…" : "Rechercher"}
          </button>
        </div>
      </form>
      {err && <p className="form-msg form-err">{err}</p>}
      {res && (
        <>
          <p className="hint">{res.total ? `${fmtInt(res.total)} page(s) — les ${res.hits.length} plus récentes :` : "Aucune page ne correspond."}</p>
          <ul className="acc-list">
            {res.hits.map((h) => (
              <li key={h.id} className="cti-item">
                <div className="cti-main">
                  <p className="cti-title dw-host">{h.host}</p>
                  <Snippet text={h.snippet} />
                  <p className="hint">
                    <code className="dw-url">{h.url}</code> · {relTime(h.collectedAt)}
                    {h.counts?.credentials ? ` · ${h.counts.credentials} identifiant(s) masqué(s)` : ""}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

// ---------- Collecte (analystes de la plateforme) ----------

interface Source {
  id: number;
  label: string;
  url: string;
  keyword: string;
  maxDepth: number;
  maxPages: number;
  active: boolean;
  lastRunAt: string | null;
}
interface Run {
  id: number;
  label: string | null;
  status: string;
  trigger: string;
  pages: number;
  ingested: number;
  matches: number;
  error: string | null;
  startedAt: string;
}

const RUN_FR: Record<string, string> = {
  READY: "En file",
  RUNNING: "En cours",
  SUCCEEDED: "Terminée, à ingérer",
  FAILED: "Échec",
  ABORTED: "Interrompue",
  "TIMED-OUT": "Délai dépassé",
  INGESTED: "Ingérée",
};

function Collection({ now }: { now: number }) {
  const sources = useJson<{ sources: Source[] }>("/api/darkweb/sources");
  const runs = useJson<{ runs: Run[] }>("/api/darkweb/runs", 30_000);
  const [f, setF] = useState({ label: "", url: "", keyword: "", maxDepth: 2, maxPages: 200 });
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  void now;
  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    setMsg(null);
    try {
      await fn();
      setMsg({ ok: true, text: ok });
      sources.reload();
      runs.reload();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Échec." });
    } finally {
      setBusy(null);
    }
  };
  return (
    <>
      <section className="card tm-panel">
        <h2>Sources de collecte</h2>
        <p className="cti-desc">
          Forums et places de marché .onion explorés par l’Actor Apify « Dark Web Scraper » (via Tor, sur l’infrastructure d’Apify). Chaque source active est
          collectée une fois par jour ; le corpus est commun à la plateforme, les motifs restent propres à chaque organisation. Coût : environ 0,003 $ par page.
        </p>
        <form
          className="dw-form"
          onSubmit={(e) => {
            e.preventDefault();
            void act("add", () => send("/api/darkweb/sources", "POST", f), "Source ajoutée.").then(() => setF({ ...f, label: "", url: "", keyword: "" }));
          }}
        >
          <div className="dw-grid">
            <label className="field dw-wide">
              <span>Adresse .onion de départ</span>
              <input type="url" required value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="http://…56 caractères….onion/" spellCheck={false} />
            </label>
            <label className="field">
              <span>Nom</span>
              <input type="text" maxLength={80} value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} />
            </label>
            <label className="field">
              <span>Mot-clé (facultatif)</span>
              <input type="text" maxLength={100} value={f.keyword} onChange={(e) => setF({ ...f, keyword: e.target.value })} />
            </label>
            <label className="field">
              <span>Profondeur</span>
              <input type="number" min={0} max={5} value={f.maxDepth} onChange={(e) => setF({ ...f, maxDepth: Number(e.target.value) })} />
            </label>
            <label className="field">
              <span>Pages au plus</span>
              <input type="number" min={1} max={500} value={f.maxPages} onChange={(e) => setF({ ...f, maxPages: Number(e.target.value) })} />
            </label>
          </div>
          <div className="org-actions">
            <button type="submit" className="btn-secondary" disabled={busy !== null}>
              Ajouter la source
            </button>
          </div>
        </form>
        {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
        {sources.error && <p className="form-msg form-err">{sources.error}</p>}
        <ul className="acc-list">
          {(sources.data?.sources ?? []).map((s) => (
            <li key={s.id} className="cti-item dw-row">
              <div className="cti-main">
                <p className="cti-title">
                  {s.label} {!s.active && <span className="tag">En pause</span>}
                </p>
                <p className="hint">
                  <code className="dw-url">{s.url}</code>
                  {s.keyword ? ` · mot-clé « ${s.keyword} »` : ""} · profondeur {s.maxDepth} · {s.maxPages} pages · {s.lastRunAt ? `collectée ${relTime(s.lastRunAt)}` : "jamais collectée"}
                </p>
              </div>
              <div className="cti-side">
                <button type="button" className="btn-link" disabled={busy !== null} onClick={() => act(`run${s.id}`, () => send("/api/darkweb/runs", "POST", { sourceId: s.id }), "Collecte lancée sur Apify.")}>
                  {busy === `run${s.id}` ? "Lancement…" : "Collecter maintenant"}
                </button>
                <button type="button" className="btn-link" disabled={busy !== null} onClick={() => act(`t${s.id}`, () => send("/api/darkweb/sources", "PATCH", { id: s.id, active: !s.active }), s.active ? "Source en pause." : "Source réactivée.")}>
                  {s.active ? "Mettre en pause" : "Réactiver"}
                </button>
                <button
                  type="button"
                  className="btn-link btn-link-danger"
                  disabled={busy !== null}
                  onClick={() => window.confirm(`Supprimer la source « ${s.label} » ?`) && act(`d${s.id}`, () => send(`/api/darkweb/sources?id=${s.id}`, "DELETE"), "Source supprimée.")}
                >
                  Supprimer
                </button>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="card tm-panel">
        <h2>Collectes récentes</h2>
        {runs.loading && !runs.data ? (
          <Skeleton />
        ) : !(runs.data?.runs ?? []).length ? (
          <p className="hint">Aucune collecte pour l’instant.</p>
        ) : (
          <ul className="acc-list">
            {(runs.data?.runs ?? []).map((r) => (
              <li key={r.id} className="cti-item dw-row">
                <div className="cti-main">
                  <p className="cti-title">
                    {r.label ?? "Source supprimée"} <span className={`tag${r.status === "INGESTED" && !r.error ? " tag-good" : ""}`}>{RUN_FR[r.status] ?? r.status}</span>
                  </p>
                  <p className="hint">
                    {relTime(r.startedAt)} · {r.trigger === "manuel" ? "manuelle" : "planifiée"} · {fmtInt(r.ingested)} page(s) ingérée(s) · {fmtInt(r.matches)} correspondance(s)
                  </p>
                  {r.error && <p className="form-msg form-err">{r.error}</p>}
                </div>
                {r.status !== "INGESTED" && (
                  <div className="cti-side">
                    <button type="button" className="btn-link" disabled={busy !== null} onClick={() => act(`i${r.id}`, () => send("/api/darkweb/runs", "POST", { runId: r.id }), "Résultats récupérés et ingérés.")}>
                      {busy === `i${r.id}` ? "Ingestion…" : "Récupérer les résultats"}
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
