"use client";

import { useState } from "react";
import type { AnalystLeak, SourceRow } from "@/lib/cti/leakstore";
import {
  CLASS_FR,
  DATA_CLASSES,
  RELIABILITY,
  RELIABILITY_FR,
  SOURCE_KIND_FR,
  SOURCE_KINDS,
  STATUS_FR,
  STATUSES,
  type DataClass,
  type LeakStatus,
  type Reliability,
  type SourceKind,
} from "@/lib/cti/leaklabels";
import { dateFr, relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Kpi, Skeleton, useJson } from "./common";

type Filter = LeakStatus | "";
const STATUS_CLS: Record<string, string> = { claimed: "tag", sample_verified: "tag tag-prio p-haute", confirmed: "tag tag-bad", false_positive: "tag tag-good" };

async function send(url: string, method: string, body: unknown) {
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
  return j;
}

/** Espace analyste : qualification des fuites, saisie manuelle, sources et clés d'ingestion. */
export default function LeakQualifyView({ now }: { now: number }) {
  const [filter, setFilter] = useState<Filter>("claimed");
  const [q, setQ] = useState("");
  const url = `/api/cti/leaks/admin?${new URLSearchParams({ ...(filter ? { statut: filter } : {}), ...(q.trim() ? { q: q.trim() } : {}) })}`;
  const { data, error, loading, reload } = useJson<{ events: AnalystLeak[]; queue: Record<string, number>; counts: Record<string, number> }>(url);
  const events = data?.events ?? [];
  const queue = data?.queue ?? {};
  const counts = data?.counts ?? {};

  return (
    <div className="cti">
      <section className="tiles">
        <Kpi k="À qualifier" v={fmtInt(counts.claimed ?? 0)} n="annonces revendiquées" />
        <Kpi k="Confirmées" v={fmtInt(counts.confirmed ?? 0)} n={`${fmtInt(counts.sample_verified ?? 0)} vérifiées sur échantillon`} />
        <Kpi k="File d’ingestion" v={fmtInt((queue.queued ?? 0) + (queue.processing ?? 0))} n={queue.error ? `${fmtInt(queue.error)} en erreur, nouvel essai auto` : "envois en attente"} />
        <Kpi k="Envois traités" v={fmtInt(queue.done ?? 0)} n="7 derniers jours" />
      </section>

      <section className="card tm-panel">
        <h2>Qualification des fuites</h2>
        <p className="cti-desc">
          Chaque annonce arrive « revendiquée ». Vérifiez-la (échantillon, cohérence, historique du vendeur), puis confirmez-la ou classez-la comme
          fausse : le score et les alertes des utilisateurs concernés sont recalculés aussitôt.
        </p>
        <div className="cti-filters">
          <div className="segmented" role="group" aria-label="Statut">
            {(["claimed", "sample_verified", "confirmed", "false_positive", ""] as Filter[]).map((s) => (
              <button key={s || "tous"} type="button" aria-pressed={filter === s} className={filter === s ? "is-on" : ""} onClick={() => setFilter(s)}>
                {s ? STATUS_FR[s] : "Toutes"}
                {s && counts[s] ? <span className="seg-n">{counts[s]}</span> : null}
              </button>
            ))}
          </div>
          <label className="search cti-search">
            <Icon name="search" size={15} />
            <span className="sr-only">Rechercher</span>
            <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Titre, victime, vendeur" />
          </label>
        </div>
        {loading && !data ? (
          <Skeleton />
        ) : error ? (
          <p className="form-msg form-err">{error}</p>
        ) : events.length === 0 ? (
          <p className="hint">Aucun événement dans cette catégorie.</p>
        ) : (
          <ul className="acc-list">
            {events.map((e) => (
              <QualifyItem key={e.id} e={e} now={now} onSaved={reload} />
            ))}
          </ul>
        )}
      </section>

      <ManualEntry onDone={reload} />
      <Sources now={now} />
    </div>
  );
}

function QualifyItem({ e, now, onSaved }: { e: AnalystLeak; now: number; onSaved: () => void }) {
  const [status, setStatus] = useState(e.status);
  const [rel, setRel] = useState(e.reliability ?? "");
  const [note, setNote] = useState(e.analystNote);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const dirty = status !== e.status || rel !== (e.reliability ?? "") || note !== e.analystNote;
  const save = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const j = await send("/api/cti/leaks/admin", "PATCH", { id: e.id, status, reliability: rel, note });
      setMsg({ ok: true, text: j.alerts ? `Enregistré : ${j.alerts} nouvelle(s) alerte(s) envoyée(s).` : "Enregistré." });
      onSaved();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Enregistrement impossible" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <li className={`acc-item sev-${e.status === "confirmed" ? "critique" : e.status === "false_positive" ? "info" : "moyenne"}`}>
      <details>
        <summary>
          <span className="sev-dot" aria-hidden="true" />
          <span className="acc-main">
            <span className="acc-email">{e.title}</span>
            <span className="chips">
              <span className={STATUS_CLS[e.status] ?? "tag"}>{STATUS_FR[e.status as LeakStatus]}</span>
              <span className="tag">{fmtInt(e.indicators)} identifiant{e.indicators > 1 ? "s" : ""}</span>
              {e.withSecrets > 0 && <span className="tag tag-bad">{fmtInt(e.withSecrets)} avec secret</span>}
              {e.matches > 0 && <span className="tag tag-prio p-haute">{e.matches} utilisateur(s) concerné(s)</span>}
            </span>
            <span className="cti-desc">
              {SOURCE_KIND_FR[e.sourceKind as SourceKind] ?? e.sourceKind} « {e.source} » · fiabilité {e.reliability ?? e.sourceReliability}
              {e.actor ? ` · ${e.actor}` : ""}
            </span>
          </span>
          <span className="cti-side">
            <span className="hint">{relTime(e.observedAt, now)}</span>
          </span>
        </summary>
        <div className="acc-detail">
          <dl className="dw-facts">
            <dt>Victime</dt>
            <dd>
              {e.victim || "—"}
              {e.victimDomain ? ` (${e.victimDomain})` : ""}
            </dd>
            <dt>Publiée</dt>
            <dd>{e.postedAt ? dateFr(e.postedAt) : "inconnue"}</dd>
            {e.volume !== null && (
              <>
                <dt>Volume</dt>
                <dd>{fmtInt(e.volume)}</dd>
              </>
            )}
            <dt>Données</dt>
            <dd>{e.dataClasses.map((c) => CLASS_FR[c as DataClass] ?? c).join(", ") || "—"}</dd>
            {e.price && (
              <>
                <dt>Prix</dt>
                <dd>{e.price}</dd>
              </>
            )}
            {e.reference && (
              <>
                <dt>Référence</dt>
                <dd>
                  <code className="ioc-val">{e.reference}</code>
                </dd>
              </>
            )}
            {e.qualifiedBy && (
              <>
                <dt>Qualifiée</dt>
                <dd>
                  par {e.qualifiedBy} {e.qualifiedAt ? relTime(e.qualifiedAt, now) : ""}
                </dd>
              </>
            )}
          </dl>
          <div className="dw-form">
            <div className="segmented" role="group" aria-label="Statut de l’événement">
              {STATUSES.map((s) => (
                <button key={s} type="button" aria-pressed={status === s} className={status === s ? "is-on" : ""} onClick={() => setStatus(s)}>
                  {STATUS_FR[s]}
                </button>
              ))}
            </div>
            <label className="field">
              <span>Fiabilité retenue</span>
              <select value={rel} onChange={(ev) => setRel(ev.target.value)}>
                <option value="">Celle de la source ({e.sourceReliability})</option>
                {RELIABILITY.map((r) => (
                  <option key={r} value={r}>
                    {RELIABILITY_FR[r]}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Note d’analyse (visible des seuls analystes)</span>
              <textarea rows={3} value={note} onChange={(ev) => setNote(ev.target.value)} placeholder="Échantillon contrôlé, recoupement, historique du vendeur…" />
            </label>
            <div className="watch-actions">
              <button type="button" className="btn-primary watch-add" disabled={busy || !dirty} onClick={save}>
                {busy ? "Enregistrement…" : "Enregistrer"}
              </button>
            </div>
            {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
          </div>
        </div>
      </details>
    </li>
  );
}

function ManualEntry({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({ title: "", victim: "", victim_domain: "", posted_at: "", actor: "", volume: "", price: "", reference: "", ids: "" });
  const [classes, setClasses] = useState<DataClass[]>([]);
  const [withPw, setWithPw] = useState(false);
  const [withCookie, setWithCookie] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const indicators = f.ids
        .split(/[\s,;]+/)
        .map((v) => v.trim())
        .filter(Boolean)
        .map((value) => ({ value, ...(withPw ? { password: true } : {}), ...(withCookie ? { cookie: true } : {}) }));
      const j = await send("/api/cti/leaks/admin", "POST", {
        title: f.title,
        victim: f.victim,
        victim_domain: f.victim_domain,
        posted_at: f.posted_at || undefined,
        actor: f.actor,
        volume: f.volume ? Number(f.volume) : undefined,
        price: f.price,
        reference: f.reference,
        data_classes: classes,
        indicators,
      });
      setMsg({ ok: true, text: `Fuite enregistrée${j.alerts ? `, ${j.alerts} alerte(s) envoyée(s)` : ""}.${j.rejected?.length ? ` ${j.rejected.join(" ; ")}` : ""}` });
      setF({ title: "", victim: "", victim_domain: "", posted_at: "", actor: "", volume: "", price: "", reference: "", ids: "" });
      setClasses([]);
      onDone();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Enregistrement impossible" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card tm-panel">
      <details>
        <summary className="dw-summary">
          <h2>Saisir une fuite</h2>
          <span className="hint">Annonce repérée à la main, rapport d’un partenaire…</span>
        </summary>
        <form className="dw-form" onSubmit={submit}>
          <div className="dw-grid">
            <label className="field">
              <span>Titre de l’annonce *</span>
              <input required value={f.title} onChange={set("title")} placeholder="Base clients Entreprise SN à vendre" />
            </label>
            <label className="field">
              <span>Victime annoncée</span>
              <input value={f.victim} onChange={set("victim")} />
            </label>
            <label className="field">
              <span>Domaine de la victime</span>
              <input value={f.victim_domain} onChange={set("victim_domain")} placeholder="entreprise.sn" />
            </label>
            <label className="field">
              <span>Date de publication</span>
              <input type="date" value={f.posted_at} onChange={set("posted_at")} />
            </label>
            <label className="field">
              <span>Vendeur ou auteur (pseudonyme)</span>
              <input value={f.actor} onChange={set("actor")} />
            </label>
            <label className="field">
              <span>Volume annoncé</span>
              <input type="number" min={0} value={f.volume} onChange={set("volume")} />
            </label>
            <label className="field">
              <span>Prix demandé</span>
              <input value={f.price} onChange={set("price")} />
            </label>
            <label className="field">
              <span>Référence (lien, identifiant de message)</span>
              <input value={f.reference} onChange={set("reference")} />
            </label>
          </div>
          <fieldset className="dw-classes">
            <legend>Données concernées</legend>
            {DATA_CLASSES.map((c) => (
              <label key={c} className="mfa-trust">
                <input type="checkbox" checked={classes.includes(c)} onChange={(e) => setClasses(e.target.checked ? [...classes, c] : classes.filter((x) => x !== c))} />
                {CLASS_FR[c]}
              </label>
            ))}
          </fieldset>
          <label className="field">
            <span>Identifiants de l’échantillon (e-mails, domaines, une valeur par ligne) : ils sont hachés et masqués à l’enregistrement</span>
            <textarea rows={4} value={f.ids} onChange={set("ids")} placeholder={"prenom.nom@entreprise.sn\nvpn.entreprise.sn"} />
          </label>
          <div className="dw-classes">
            <label className="mfa-trust">
              <input type="checkbox" checked={withPw} onChange={(e) => setWithPw(e.target.checked)} /> L’échantillon contient des mots de passe
            </label>
            <label className="mfa-trust">
              <input type="checkbox" checked={withCookie} onChange={(e) => setWithCookie(e.target.checked)} /> L’échantillon contient des cookies de session
            </label>
          </div>
          <p className="hint">Ne collez jamais les mots de passe eux-mêmes : cochez seulement leur présence.</p>
          <div className="watch-actions">
            <button type="submit" className="btn-primary watch-add" disabled={busy || !f.title.trim()}>
              {busy ? "Enregistrement…" : "Enregistrer et rapprocher"}
            </button>
          </div>
          {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
        </form>
      </details>
    </section>
  );
}

function Sources({ now }: { now: number }) {
  const { data, error, loading, reload } = useJson<{ sources: SourceRow[]; connectors: { misp: boolean; taxii: boolean } }>("/api/cti/leaks/sources");
  const [f, setF] = useState<{ name: string; kind: SourceKind; reliability: Reliability; language: string }>({ name: "", kind: "provider", reliability: "C", language: "" });
  const [key, setKey] = useState<{ name: string; key: string } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const j = await send("/api/cti/leaks/sources", "POST", f);
      if (j.key) setKey({ name: f.name, key: j.key });
      setF({ ...f, name: "" });
      reload();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : "Création impossible");
    } finally {
      setBusy(false);
    }
  };
  const patch = async (body: Record<string, unknown>, name: string) => {
    setMsg(null);
    try {
      const j = await send("/api/cti/leaks/sources", "PATCH", body);
      if (j.key) setKey({ name, key: j.key });
      reload();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : "Modification impossible");
    }
  };
  const sources = data?.sources ?? [];
  return (
    <section className="card tm-panel">
      <h2>Sources et clés d’ingestion</h2>
      <p className="cti-desc">
        Chaque collecteur, fournisseur ou partenaire reçoit sa propre clé. Il envoie ses événements à <code>POST /api/v1/fuites</code>, signés en
        HMAC-SHA256. La clé n’est affichée qu’une fois : VigilantIQ ne la conserve pas et ne peut que la remplacer.
      </p>
      {data && (
        <p className="hint">
          Connecteurs : MISP {data.connectors.misp ? "configuré" : "non configuré (MISP_URL, MISP_API_KEY)"} · TAXII 2.1{" "}
          {data.connectors.taxii ? "configuré" : "non configuré (TAXII_URL, TAXII_COLLECTION)"}. Collecte chaque jour.
        </p>
      )}
      {key && <KeyReveal name={key.name} k={key.key} onClose={() => setKey(null)} />}
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="form-msg form-err">{error}</p>
      ) : sources.length > 0 ? (
        <ul className="dw-sources">
          {sources.map((s) => (
            <li key={s.id} className={s.active ? "" : "is-off"}>
              <span className="acc-main">
                <span className="acc-email">{s.name}</span>
                <span className="cti-desc">
                  {SOURCE_KIND_FR[s.kind as SourceKind] ?? s.kind} · {fmtInt(s.events)} événement{s.events > 1 ? "s" : ""} ·{" "}
                  {s.lastIngestAt ? `dernier envoi ${relTime(s.lastIngestAt, now)}` : "aucun envoi"}
                  {s.active ? "" : " · désactivée"}
                </span>
              </span>
              <select aria-label={`Fiabilité de ${s.name}`} value={s.reliability} onChange={(e) => patch({ id: s.id, reliability: e.target.value }, s.name)}>
                {RELIABILITY.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              {s.hasKey && (
                <button type="button" className="btn-plain" onClick={() => patch({ id: s.id, rotate: true }, s.name)}>
                  Nouvelle clé
                </button>
              )}
              <button type="button" className="btn-plain" onClick={() => patch({ id: s.id, active: !s.active }, s.name)}>
                {s.active ? "Désactiver" : "Réactiver"}
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="hint">Aucune source pour le moment.</p>
      )}
      <form className="dw-form" onSubmit={create}>
        <div className="dw-grid">
          <label className="field">
            <span>Nom de la source</span>
            <input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Fournisseur X, CERT partenaire…" />
          </label>
          <label className="field">
            <span>Type</span>
            <select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as SourceKind })}>
              {SOURCE_KINDS.filter((k) => !["misp", "taxii", "manual"].includes(k)).map((k) => (
                <option key={k} value={k}>
                  {SOURCE_KIND_FR[k]}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Fiabilité</span>
            <select value={f.reliability} onChange={(e) => setF({ ...f, reliability: e.target.value as Reliability })}>
              {RELIABILITY.map((r) => (
                <option key={r} value={r}>
                  {RELIABILITY_FR[r]}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Langue principale</span>
            <input value={f.language} onChange={(e) => setF({ ...f, language: e.target.value })} placeholder="fr, en, ru…" />
          </label>
        </div>
        <div className="watch-actions">
          <button type="submit" className="btn-primary watch-add" disabled={busy || !f.name.trim()}>
            Créer la source et sa clé
          </button>
        </div>
        {msg && <p className="form-msg form-err">{msg}</p>}
      </form>
    </section>
  );
}

function KeyReveal({ name, k, onClose }: { name: string; k: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const sample = `KEY='${k}'
BODY='{"events":[{"title":"Base clients à vendre","victim_domain":"entreprise.sn","data_classes":["credentials"],"indicators":[{"type":"email","value":"x@entreprise.sn","password":true}]}]}'
TS=$(date +%s)
SIG="sha256=$(printf '%s' "$TS.$BODY" | openssl dgst -sha256 -hmac "$KEY" | sed 's/^.* //')"
curl -X POST ${origin}/api/v1/fuites \\
  -H "Authorization: Bearer $KEY" -H "X-VQ-Timestamp: $TS" -H "X-VQ-Signature: $SIG" \\
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" --data "$BODY"`;
  return (
    <div className="verify-box">
      <p className="cti-title">
        <Icon name="key" size={14} /> Clé d’ingestion de « {name} »
      </p>
      <p className="cti-desc">Copiez-la maintenant et transmettez-la par un canal sûr : elle ne sera plus affichée.</p>
      <div className="share-field">
        <code className="ioc-val verify-record">{k}</code>
        <button
          type="button"
          className={`share-copy${copied ? " is-done" : ""}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(k);
              setCopied(true);
            } catch {
              /* presse-papiers indisponible */
            }
          }}
        >
          {copied ? "Copiée" : "Copier"}
        </button>
      </div>
      <details>
        <summary className="hint">Exemple d’envoi signé (shell)</summary>
        <pre className="dw-code">{sample}</pre>
      </details>
      <div className="watch-actions">
        <button type="button" className="btn-secondary" onClick={onClose}>
          J’ai copié la clé
        </button>
      </div>
    </div>
  );
}
