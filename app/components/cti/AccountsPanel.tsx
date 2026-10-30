"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AccountBreach, AccountStealer, PasswordRisk } from "@/lib/cti/accounts";
import type { AccountRow } from "@/lib/cti/accountstore";
import { dataFr } from "@/lib/cti/labels";
import type { WatchRow } from "@/lib/cti/store";
import { dateFr, relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Kpi, Skeleton, useJson } from "./common";

const RISK: Record<PasswordRisk, { label: string; cls: string }> = {
  plaintext: { label: "Mot de passe en clair", cls: "tag-bad" },
  easytocrack: { label: "Mot de passe facile à casser", cls: "tag-bad" },
  hardtocrack: { label: "Mot de passe chiffré solidement", cls: "" },
  unknown: { label: "Protection du mot de passe inconnue", cls: "" },
};
const RISK_ORDER: PasswordRisk[] = ["plaintext", "easytocrack", "unknown", "hardtocrack"];
type Filter = "tous" | "exposes" | "infostealer" | "sains" | "attente";

const hasPassword = (b: AccountBreach) => b.dataTypes.some((d) => /password/i.test(d));
const worstRisk = (a: AccountRow): PasswordRisk | null => {
  const r = a.breaches.filter(hasPassword).map((b) => b.passwordRisk);
  return RISK_ORDER.find((x) => r.includes(x)) ?? null;
};
const allTypes = (a: AccountRow) => [...new Set(a.breaches.flatMap((b) => b.dataTypes))];
const lastExposure = (a: AccountRow) => [...a.stealers.map((s) => s.date ?? ""), ...a.breaches.map((b) => b.added ?? b.date)].sort().pop() ?? "";

/** Vérification de propriété des domaines + comptes exposés (fuites et infostealers), avec le détail de ce qui a fuité. */
export default function AccountsPanel({ items, now, onVerified }: { items: WatchRow[]; now: number; onVerified: () => void }) {
  const domains = items.filter((i) => i.kind === "domain");
  const verified = domains.filter((d) => d.verified);
  const { data, loading, reload } = useJson<{ max: number; items: AccountRow[] }>(verified.length ? "/api/cti/accounts" : null);
  const [text, setText] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState<{ remaining: number } | null>(null);
  const [filter, setFilter] = useState<Filter>("exposes");
  const [q, setQ] = useState("");
  const stop = useRef(false);

  const runChecks = useCallback(async () => {
    stop.current = false;
    setChecking({ remaining: -1 });
    try {
      for (let i = 0; i < 60 && !stop.current; i++) {
        const r = await fetch("/api/cti/accounts/check", { method: "POST" });
        const j = (await r.json().catch(() => ({}))) as { checked?: number; remaining?: number; error?: string };
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        setChecking({ remaining: j.remaining ?? 0 });
        await reload();
        if (!j.checked || !j.remaining) break;
      }
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Contrôle interrompu" });
    } finally {
      setChecking(null);
    }
  }, [reload]);

  // Des adresses jamais contrôlées : on lance le contrôle automatiquement.
  const pending = data?.items.filter((a) => a.status === "pending").length ?? 0;
  useEffect(() => {
    if (pending > 0 && !checking) void runChecks();
    return () => {
      stop.current = true;
    };
  }, [pending > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const r = await fetch("/api/cti/accounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setText("");
      setMsg({
        ok: true,
        text: `${j.added} adresse${j.added > 1 ? "s" : ""} ajoutée${j.added > 1 ? "s" : ""}${j.duplicates ? `, ${j.duplicates} déjà présente(s)` : ""}${j.rejected?.length ? `. Refusées (hors domaine vérifié) : ${j.rejected.slice(0, 5).join(", ")}${j.rejected.length > 5 ? "…" : ""}` : ""}.`,
      });
      await reload();
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Ajout impossible" });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (ids: number[] | "all") => {
    await fetch("/api/cti/accounts", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids }) });
    await reload();
  };

  const accounts = data?.items ?? [];
  const exposed = accounts.filter((a) => a.status === "exposed");
  const stealerCount = accounts.filter((a) => a.stealers.length > 0).length;
  const weakPw = accounts.filter((a) => {
    const r = worstRisk(a);
    return r === "plaintext" || r === "easytocrack";
  }).length;

  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return accounts
      .filter((a) => {
        if (filter === "exposes" && a.status !== "exposed") return false;
        if (filter === "infostealer" && !a.stealers.length) return false;
        if (filter === "sains" && a.status !== "clean") return false;
        if (filter === "attente" && a.status !== "pending" && a.status !== "error") return false;
        return !s || a.email.includes(s);
      })
      .sort((a, b) => b.stealers.length - a.stealers.length || b.breaches.length - a.breaches.length || a.email.localeCompare(b.email));
  }, [accounts, filter, q]);

  const exportCsv = () => {
    const esc = (v: string) => (/[",\n;]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
    const rows = [["adresse", "statut", "infections_infostealer", "derniere_infection", "fuites", "donnees_exposees", "risque_mot_de_passe", "fuites_detail"].join(",")];
    for (const a of accounts) {
      rows.push(
        [
          a.email,
          a.status,
          String(a.stealers.length),
          a.stealers[0]?.date?.slice(0, 10) ?? "",
          String(a.breaches.length),
          allTypes(a).map(dataFr).join(" | "),
          worstRisk(a) ? RISK[worstRisk(a)!].label : "",
          a.breaches.map((b) => `${b.name} (${b.date})`).join(" | "),
        ]
          .map(esc)
          .join(","),
      );
    }
    const url = URL.createObjectURL(new Blob([rows.join("\n") + "\n"], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `vigilantiq-comptes-exposes-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (!domains.length) return null;

  return (
    <section className="card tm-panel" aria-labelledby="h-accounts">
      <div className="cti-head">
        <h2 id="h-accounts">Comptes exposés</h2>
        {accounts.length > 0 && (
          <button type="button" className="btn-plain" onClick={exportCsv}>
            <Icon name="file" size={14} /> Exporter (CSV)
          </button>
        )}
      </div>

      {domains
        .filter((d) => !d.verified)
        .map((d) => (
          <VerifyDomain key={d.id} item={d} onVerified={onVerified} />
        ))}

      {verified.length > 0 && (
        <>
          <div className="tm-kpis">
            <Kpi k="Comptes surveillés" v={data ? fmtInt(accounts.length) : "–"} n={data ? `sur ${fmtInt(data.max)} possibles` : ""} />
            <Kpi k="Comptes exposés" v={data ? fmtInt(exposed.length) : "–"} n="fuites ou infostealers" />
            <Kpi k="Postes infectés" v={data ? fmtInt(stealerCount) : "–"} n="infostealers (critique)" />
            <Kpi k="Mots de passe à risque" v={data ? fmtInt(weakPw) : "–"} n="en clair ou faciles à casser" />
          </div>

          <form className="acc-import" onSubmit={add}>
            <label htmlFor="acc-emails" className="share-k">
              Adresses à surveiller ({verified.map((d) => `@${d.value}`).join(", ")})
            </label>
            <textarea
              id="acc-emails"
              className="stack-input"
              rows={3}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={`prenom.nom@${verified[0].value}, contact@${verified[0].value}…  (une par ligne, ou collez un export CSV de l’annuaire)`}
            />
            <div className="watch-actions">
              <button type="submit" className="btn-primary watch-add" disabled={busy || !text.trim()}>
                Ajouter et contrôler
              </button>
              <button type="button" className="btn-secondary" onClick={runChecks} disabled={Boolean(checking) || !accounts.length}>
                <Icon name="refresh" size={15} className={checking ? "spin" : ""} />
                {checking ? (checking.remaining >= 0 ? `Contrôle… ${checking.remaining} restante(s)` : "Contrôle…") : "Recontrôler"}
              </button>
            </div>
          </form>
          {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}

          {loading && !data ? (
            <Skeleton />
          ) : accounts.length > 0 ? (
            <>
              <div className="cti-filters">
                <div className="segmented" role="group" aria-label="Filtre des comptes">
                  {(
                    [
                      ["exposes", `Exposés ${exposed.length}`],
                      ["infostealer", `Infostealers ${stealerCount}`],
                      ["sains", "Sans exposition"],
                      ["attente", "En attente"],
                      ["tous", `Tous ${accounts.length}`],
                    ] as [Filter, string][]
                  ).map(([k, l]) => (
                    <button key={k} type="button" aria-pressed={filter === k} className={filter === k ? "is-on" : ""} onClick={() => setFilter(k)}>
                      {l}
                    </button>
                  ))}
                </div>
                <label className="search cti-search">
                  <Icon name="search" size={15} />
                  <span className="sr-only">Rechercher une adresse</span>
                  <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Rechercher une adresse" />
                </label>
              </div>
              {list.length === 0 ? (
                <p className="hint">Aucun compte dans cette catégorie.</p>
              ) : (
                <ul className="acc-list">
                  {list.map((a) => (
                    <AccountItem key={a.id} a={a} now={now} onRemove={() => remove([a.id])} />
                  ))}
                </ul>
              )}
            </>
          ) : (
            <p className="hint">Ajoutez les adresses de vos collaborateurs pour savoir lesquelles ont fuité et quelles données sont exposées.</p>
          )}
        </>
      )}
      <p className="hint">
        Sources : XposedOrNot (fuites de données) et Hudson Rock (postes infectés par des infostealers). Pour chaque compte, VigilantIQ indique
        les fuites, leurs dates, les types de données exposées et le niveau de protection du mot de passe. Les mots de passe, identifiants et
        adresses IP eux-mêmes ne sont jamais récupérés ni affichés.
      </p>
    </section>
  );
}

function VerifyDomain({ item, onVerified }: { item: WatchRow; onVerified: () => void }) {
  const [state, setState] = useState<"idle" | "busy" | "fail">("idle");
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const record = `vigilantiq-verification=${item.verifyToken ?? "…"}`;
  const check = async () => {
    setState("busy");
    setErr(null);
    try {
      const r = await fetch("/api/cti/watch/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: item.id }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      if (j.verified) onVerified();
      else setState("fail");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Vérification impossible");
      setState("idle");
    }
  };
  return (
    <div className="verify-box">
      <p className="cti-title">
        <Icon name="lock" size={14} /> Prouvez que {item.value} vous appartient
      </p>
      <p className="cti-desc">
        La liste des comptes exposés d’un domaine n’est montrée qu’à son propriétaire. Ajoutez cet enregistrement <strong>TXT</strong> à la zone DNS
        de <strong>{item.value}</strong>, puis cliquez sur « Vérifier » (la propagation peut prendre quelques minutes).
      </p>
      <div className="share-field">
        <code className="ioc-val verify-record">{record}</code>
        <button
          type="button"
          className={`share-copy${copied ? " is-done" : ""}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(record);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            } catch {
              /* presse-papiers indisponible */
            }
          }}
        >
          {copied ? "Copié" : "Copier"}
        </button>
      </div>
      <div className="watch-actions">
        <button type="button" className="btn-secondary" onClick={check} disabled={state === "busy"}>
          {state === "busy" ? "Vérification…" : "Vérifier"}
        </button>
      </div>
      {state === "fail" && <p className="form-msg form-err">Enregistrement introuvable pour le moment. Vérifiez la zone DNS et réessayez dans quelques minutes.</p>}
      {err && <p className="form-msg form-err">{err}</p>}
    </div>
  );
}

function AccountItem({ a, now, onRemove }: { a: AccountRow; now: number; onRemove: () => void }) {
  const risk = worstRisk(a);
  const types = allTypes(a);
  const last = lastExposure(a);
  const sev = a.stealers.length ? "critique" : risk === "plaintext" || risk === "easytocrack" ? "haute" : a.status === "exposed" ? "moyenne" : "info";
  return (
    <li className={`acc-item sev-${sev}`}>
      <details>
        <summary>
          <span className="sev-dot" aria-hidden="true" />
          <span className="acc-main">
            <span className="acc-email">{a.email}</span>
            <span className="chips">
              {a.status === "pending" && <span className="tag">En attente de contrôle</span>}
              {a.status === "error" && <span className="tag" title={a.error ?? ""}>Contrôle en échec, nouvel essai prévu</span>}
              {a.status === "clean" && <span className="tag tag-good">Aucune exposition connue</span>}
              {a.stealers.length > 0 && <span className="tag tag-bad">Poste infecté (infostealer) ×{a.stealers.length}</span>}
              {a.breaches.length > 0 && (
                <span className="tag tag-prio p-haute">
                  {a.breaches.length} fuite{a.breaches.length > 1 ? "s" : ""}
                </span>
              )}
              {risk && <span className={`tag ${RISK[risk].cls}`}>{RISK[risk].label}</span>}
            </span>
            {types.length > 0 && <span className="cti-desc">Données exposées : {types.slice(0, 10).map(dataFr).join(", ")}{types.length > 10 ? "…" : ""}</span>}
          </span>
          <span className="cti-side">
            <span className="hint">{last ? `exposé ${relTime(last.length === 4 ? `${last}-12-31` : last, now) || last}` : a.checkedAt ? `contrôlé ${relTime(a.checkedAt, now)}` : ""}</span>
            {a.status === "exposed" && <span className="cti-link">Détails</span>}
          </span>
        </summary>
        <div className="acc-detail">
          {a.stealers.length > 0 && (
            <div>
              <h3>Infections par infostealer</h3>
              <ul className="acc-sub">
                {a.stealers.map((s, i) => (
                  <li key={i}>
                    <span>
                      <strong>{s.date ? dateFr(s.date) : "Date inconnue"}</strong> · ordinateur {s.computer || "non identifié"} · {s.os || "système inconnu"}
                    </span>
                    <span className="hint">
                      Identifiants enregistrés dans le navigateur : {fmtInt(s.corporateServices)} service(s) professionnel(s), {fmtInt(s.userServices)} service(s)
                      personnel(s) · antivirus : {s.antiviruses.length ? s.antiviruses.join(", ") : "aucun détecté"}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="hint acc-todo">
                À faire : isoler et nettoyer le poste, réinitialiser tous les mots de passe enregistrés dans le navigateur, révoquer les sessions et
                jetons actifs, imposer la double authentification.
              </p>
            </div>
          )}
          {a.breaches.length > 0 && (
            <div>
              <h3>Fuites de données</h3>
              <ul className="acc-sub">
                {a.breaches.map((b) => (
                  <li key={b.name}>
                    <span>
                      <strong>{b.name}</strong>
                      {b.domain ? ` (${b.domain})` : ""} · {b.date || "date inconnue"}
                      {b.records ? ` · ${fmtInt(b.records)} comptes touchés` : ""}
                      {b.industry ? ` · ${b.industry}` : ""}
                    </span>
                    <div className="chips">
                      {b.dataTypes.map((d) => (
                        <span key={d} className={`tag${/password|credit|bank|security/i.test(d) ? " tag-bad" : ""}`}>
                          {dataFr(d)}
                        </span>
                      ))}
                      {hasPassword(b) && <span className={`tag ${RISK[b.passwordRisk].cls}`}>{RISK[b.passwordRisk].label}</span>}
                    </div>
                    {b.details && <p className="cti-desc">{b.details}</p>}
                  </li>
                ))}
              </ul>
              <p className="hint acc-todo">
                À faire : changer le mot de passe de ce compte et de tout service où il était réutilisé, activer la double authentification, prévenir
                la personne du risque d’hameçonnage ciblé.
              </p>
            </div>
          )}
          <div className="watch-actions">
            <button type="button" className="btn-plain" onClick={onRemove}>
              Ne plus surveiller cette adresse
            </button>
          </div>
        </div>
      </details>
    </li>
  );
}
