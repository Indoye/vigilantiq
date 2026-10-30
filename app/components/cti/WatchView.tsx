"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { AlertRow, ScanResult, WatchRow } from "@/lib/cti/store";
import { dataFr } from "@/lib/cti/labels";
import { SOURCE_LABEL } from "@/lib/cti/notify";
import { dateFr, relTime } from "@/lib/format";
import { Icon } from "../ui";
import AccountsPanel from "./AccountsPanel";
import { fmtInt, Kpi, Skeleton, useJson } from "./common";

interface Resp {
  items: WatchRow[];
  alerts: AlertRow[];
  max: number;
  email: string | null;
}

const SEV_LABEL: Record<string, string> = { critique: "Critique", haute: "Haute", moyenne: "Moyenne", info: "Info" };
const SEV_ORDER = ["critique", "haute", "moyenne", "info"];
type SourceSel = "" | keyof typeof SOURCE_LABEL;

/** Liste de surveillance de l'utilisateur, analyses et alertes (fuites, dark web, hameçonnage…). */
export default function WatchView({ now, guest, onUnread }: { now: number; guest: boolean; onUnread?: (n: number) => void }) {
  const { data, error, loading, reload, setData } = useJson<Resp>(guest ? null : "/api/cti/watch");
  const [kind, setKind] = useState<"domain" | "brand">("domain");
  const [value, setValue] = useState("");
  const [formErr, setFormErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanErr, setScanErr] = useState<string | null>(null);
  const [source, setSource] = useState<SourceSel>("");
  const autoScanned = useRef(false);

  const unread = data?.alerts.filter((a) => !a.seen).length ?? 0;
  useEffect(() => onUnread?.(unread), [unread, onUnread]);

  const runScan = async () => {
    setScanning(true);
    setScanErr(null);
    try {
      const r = await fetch("/api/cti/scan", { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setScan(j as ScanResult);
      await reload();
    } catch (e) {
      setScanErr(e instanceof Error ? e.message : "Analyse impossible");
    } finally {
      setScanning(false);
    }
  };

  // Première visite avec une liste jamais analysée : on lance l'analyse automatiquement.
  useEffect(() => {
    if (!data || autoScanned.current) return;
    if (data.items.length > 0 && data.items.every((i) => !i.lastScanAt)) {
      autoScanned.current = true;
      void runScan();
    }
  }, [data]); // eslint-disable-line react-hooks/exhaustive-deps

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFormErr(null);
    try {
      const r = await fetch("/api/cti/watch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind, value }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setValue("");
      autoScanned.current = false;
      await reload();
    } catch (err) {
      setFormErr(err instanceof Error ? err.message : "Ajout impossible");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: number) => {
    await fetch(`/api/cti/watch?id=${id}`, { method: "DELETE" });
    await reload();
  };

  const markAll = async () => {
    await fetch("/api/cti/alerts", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids: "all" }) });
    setData((d) => (d ? { ...d, alerts: d.alerts.map((a) => ({ ...a, seen: true })) } : d));
  };

  const alerts = useMemo(
    () =>
      (data?.alerts ?? [])
        .filter((a) => !source || a.source === source)
        .sort((a, b) => Number(a.seen) - Number(b.seen) || SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.createdAt.localeCompare(a.createdAt)),
    [data, source],
  );
  const bySource = (s: string) => data?.alerts.filter((a) => a.source === s).length ?? 0;
  const lastScan = data?.items.map((i) => i.lastScanAt).filter(Boolean).sort().pop() ?? null;

  if (guest) {
    return (
      <div className="empty card">
        <p className="empty-title">Surveillance réservée aux comptes</p>
        <p>
          Déclarez vos domaines et marques pour être alerté quand ils apparaissent sur les sites de fuite des rançongiciels, dans des identifiants
          volés par des infostealers, des fuites de données ou des sites d’hameçonnage. <a href="/connexion">Connectez-vous avec un compte</a>.
        </p>
      </div>
    );
  }

  return (
    <div className="cti">
      {error && <p className="callout callout-err">{error}</p>}

      <section className="card tm-panel">
        <div className="cti-head">
          <h2>Éléments surveillés</h2>
          <span className="hint">
            {data ? `${data.items.length} / ${data.max}` : ""}
            {lastScan ? ` · analysé ${relTime(lastScan, now)}` : ""}
          </span>
        </div>
        <form className="watch-form" onSubmit={add}>
          <div className="segmented" role="group" aria-label="Type d’élément">
            <button type="button" aria-pressed={kind === "domain"} className={kind === "domain" ? "is-on" : ""} onClick={() => setKind("domain")}>
              Domaine
            </button>
            <button type="button" aria-pressed={kind === "brand"} className={kind === "brand" ? "is-on" : ""} onClick={() => setKind("brand")}>
              Marque
            </button>
          </div>
          <label className="search watch-input">
            <span className="sr-only">{kind === "domain" ? "Nom de domaine" : "Nom de marque"}</span>
            <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === "domain" ? "entreprise.sn" : "Nom de votre marque"} required />
          </label>
          <button type="submit" className="btn-primary watch-add" disabled={busy || !value.trim() || (data ? data.items.length >= data.max : false)}>
            Ajouter
          </button>
        </form>
        {formErr && <p className="form-msg form-err">{formErr}</p>}
        {loading && !data ? (
          <Skeleton />
        ) : data && data.items.length > 0 ? (
          <div className="chips watch-chips">
            {data.items.map((i) => (
              <span key={i.id} className="watch-chip">
                <span className="watch-kind">{i.kind === "domain" ? "Domaine" : "Marque"}</span>
                {i.value}
                {i.kind === "domain" && (
                  <span className={`watch-ver${i.verified ? " is-ok" : ""}`} title={i.verified ? "Propriété vérifiée" : "Propriété non vérifiée"}>
                    <Icon name={i.verified ? "check" : "lock"} size={10} />
                    {i.verified ? "vérifié" : "à vérifier"}
                  </span>
                )}
                <button type="button" onClick={() => remove(i.id)} aria-label={`Ne plus surveiller ${i.value}`}>
                  <Icon name="close" size={11} />
                </button>
              </span>
            ))}
          </div>
        ) : (
          <p className="hint">Ajoutez le domaine de votre organisation (ex. entreprise.sn) et vos marques. Seul vous voyez votre liste.</p>
        )}
        <div className="watch-actions">
          <button type="button" className="btn-secondary" onClick={runScan} disabled={scanning || !data?.items.length}>
            <Icon name="refresh" size={15} className={scanning ? "spin" : ""} />
            {scanning ? "Analyse en cours… (jusqu’à 1 min)" : "Analyser maintenant"}
          </button>
        </div>
        {scanErr && <p className="callout callout-err">{scanErr}</p>}
        {scan && (
          <p className="hint">
            Analyse terminée : {scan.created} nouvelle{scan.created > 1 ? "s" : ""} alerte{scan.created > 1 ? "s" : ""}.
            {scan.errors.length > 0 && ` Sources partielles : ${scan.errors.join(" ; ")}.`}
          </p>
        )}
        <p className="hint">
          Vérifiés : sites de fuite des rançongiciels, identifiants volés par des infostealers (revendus sur les marchés, forums et canaux Telegram),
          fuites de données publiques, domaines ressemblants et sites d’hameçonnage
          {data?.email ? `, ainsi que votre adresse ${data.email}` : ""}. Analyse automatique chaque jour, avec e-mail des nouvelles alertes.
        </p>
      </section>

      {data && <AccountsPanel items={data.items} now={now} onVerified={reload} />}

      {scan?.domains.map((d) => (
        <DomainCard key={d.domain} report={d} now={now} />
      ))}
      {scan?.email && (
        <section className="card tm-panel">
          <h2>Votre adresse e-mail</h2>
          {scan.email.breaches === null ? (
            <p className="hint">Vérification indisponible pour le moment.</p>
          ) : scan.email.breaches.length === 0 ? (
            <p className="hint">{scan.email.address} n’apparaît dans aucune fuite connue.</p>
          ) : (
            <>
              <p>
                {scan.email.address} apparaît dans <strong>{scan.email.breaches.length}</strong> fuite{scan.email.breaches.length > 1 ? "s" : ""}. Changez
                les mots de passe concernés et activez la double authentification.
              </p>
              <div className="chips">
                {scan.email.breaches.slice(0, 30).map((b) => (
                  <span key={b} className="tag">
                    {b}
                  </span>
                ))}
              </div>
            </>
          )}
        </section>
      )}

      <section className="card tm-panel">
        <div className="cti-head">
          <h2>Alertes {unread > 0 && <span className="nav-badge cti-badge">{unread}</span>}</h2>
          {unread > 0 && (
            <button type="button" className="btn-plain" onClick={markAll}>
              Tout marquer comme lu
            </button>
          )}
        </div>
        {data && data.alerts.length > 0 && (
          <div className="segmented cti-seg" role="group" aria-label="Type d’alerte">
            <button type="button" aria-pressed={source === ""} className={source === "" ? "is-on" : ""} onClick={() => setSource("")}>
              Toutes <span className="seg-n">{data.alerts.length}</span>
            </button>
            {Object.keys(SOURCE_LABEL)
              .filter((s) => bySource(s) > 0)
              .map((s) => (
                <button key={s} type="button" aria-pressed={source === s} className={source === s ? "is-on" : ""} onClick={() => setSource(s as SourceSel)}>
                  {SOURCE_LABEL[s]} <span className="seg-n">{bySource(s)}</span>
                </button>
              ))}
          </div>
        )}
        {!data ? (
          <Skeleton />
        ) : alerts.length === 0 ? (
          <p className="hint">{data.items.length ? "Aucune alerte pour le moment : rien n’a été détecté pour vos éléments surveillés." : "Ajoutez un domaine ou une marque pour recevoir des alertes."}</p>
        ) : (
          <ul className="cti-alerts">
            {alerts.map((a) => (
              <li key={a.id} className={`cti-alert sev-${a.severity}${a.seen ? "" : " is-new"}`}>
                <span className="sev-dot" aria-hidden="true" />
                <div className="cti-main">
                  <p className="cti-alert-k">
                    {SEV_LABEL[a.severity] ?? a.severity} · {SOURCE_LABEL[a.source] ?? a.source} · {a.watchValue}
                    {!a.seen && <span className="cti-new">Nouveau</span>}
                  </p>
                  <p className="cti-title">{a.title}</p>
                  <AlertDetail a={a} />
                </div>
                <div className="cti-side">
                  <span className="hint">{relTime(a.createdAt, now)}</span>
                  {a.url && (
                    <a href={a.url} target="_blank" rel="noreferrer" className="cti-link">
                      Source <Icon name="external" size={12} />
                    </a>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
      <p className="foot-note">
        Couverture gratuite : ransomware.live, Hudson Rock (infostealers), Have I Been Pwned, XposedOrNot, OpenPhish, abuse.ch et DNS public. Les
        forums privés, Discord et les canaux Telegram ne sont couverts qu’indirectement (identifiants d’infostealers, annonces des groupes) : une
        surveillance directe demande un fournisseur spécialisé payant.
      </p>
    </div>
  );
}

function AlertDetail({ a }: { a: AlertRow }) {
  const d = a.detail as Record<string, unknown>;
  if (a.source === "infostealer") {
    const fam = (d.families as { name: string; count: number }[] | undefined) ?? [];
    return (
      <p className="cti-desc">
        {fmtInt(Number(d.employees) || 0)} employé(s), {fmtInt(Number(d.users) || 0)} utilisateur(s)
        {d.lastEmployee ? ` · dernier poste d’employé infecté le ${dateFr(String(d.lastEmployee))}` : ""}
        {fam.length ? ` · ${fam.slice(0, 3).map((f) => f.name).join(", ")}` : ""}
      </p>
    );
  }
  if (a.source === "ransomware") return <p className="cti-desc">{[d.sector, d.country, d.domain].filter(Boolean).join(" · ")}</p>;
  if (a.source === "breach") return <p className="cti-desc">{((d.dataClasses as string[]) ?? []).slice(0, 6).map(dataFr).join(", ")}</p>;
  if (a.source === "typosquat")
    return (
      <p className="cti-desc">
        {((d.ips as string[]) ?? []).join(", ") || "sans adresse IP"}
        {d.mx ? " · serveur de messagerie configuré" : ""}
      </p>
    );
  if (a.source === "account") {
    if (d.kind === "stealer") return <p className="cti-desc">Ordinateur {String(d.computer || "non identifié")} · {String(d.os || "")}</p>;
    return <p className="cti-desc">{((d.dataTypes as string[]) ?? []).slice(0, 8).map(dataFr).join(", ")}</p>;
  }
  if (a.source === "phishing") return <p className="cti-desc ioc-val">{String(d.url ?? "")}</p>;
  return null;
}

function DomainCard({ report, now }: { report: ScanResult["domains"][number]; now: number }) {
  const s = report.infostealer;
  return (
    <section className="card tm-panel">
      <div className="cti-head">
        <h2>{report.domain}</h2>
        {report.errors.length > 0 && <span className="hint">{report.errors.join(" ; ")}</span>}
      </div>
      <div className="tm-kpis">
        <Kpi k="Employés compromis" v={s ? fmtInt(s.employees) : "–"} n={s?.lastEmployee ? `dernier : ${relTime(s.lastEmployee, now)}` : "infostealers"} />
        <Kpi k="Utilisateurs compromis" v={s ? fmtInt(s.users) : "–"} n={s?.lastUser ? `dernier : ${relTime(s.lastUser, now)}` : "clients, visiteurs"} />
        <Kpi k="Domaines ressemblants" v={report.lookalikes ? report.lookalikes.length : "–"} n="actifs (DNS)" />
        <Kpi k="Fuites du domaine" v={report.breaches.length} n="Have I Been Pwned" />
      </div>
      {s && s.employees + s.users > 0 && (
        <div className="tm-two">
          <div>
            <h3>Accès internes exposés</h3>
            {s.employeeHosts.length ? (
              <div className="chips">
                {s.employeeHosts.map((h) => (
                  <span key={h.host} className="tag">
                    {h.host} ×{h.count}
                  </span>
                ))}
              </div>
            ) : (
              <p className="hint">Aucun accès d’employé identifié.</p>
            )}
            {s.weakPasswordsPct != null && <p className="hint">{s.weakPasswordsPct} % des mots de passe d’employés exposés sont faibles.</p>}
          </div>
          <div>
            <h3>Familles d’infostealers</h3>
            <div className="chips">
              {s.families.map((f) => (
                <span key={f.name} className="tag tag-bad">
                  {f.name} {fmtInt(f.count)}
                </span>
              ))}
            </div>
            <p className="hint">Réinitialisez les mots de passe et sessions des comptes exposés, et vérifiez les postes concernés.</p>
          </div>
        </div>
      )}
      {report.lookalikes && report.lookalikes.length > 0 && (
        <div>
          <h3>Domaines ressemblants actifs</h3>
          <div className="chips">
            {report.lookalikes.map((l) => (
              <span key={l.domain} className={`tag${l.mx ? " tag-bad" : ""}`} title={l.ips.join(", ")}>
                {l.domain}
                {l.mx ? " · e-mail" : ""}
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
