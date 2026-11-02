"use client";

import { useState } from "react";
import type { UserLeak } from "@/lib/cti/leakstore";
import { CLASS_FR, severityOf, SOURCE_KIND_FR, STATUS_FR, type DataClass, type LeakStatus, type SourceKind } from "@/lib/cti/leaklabels";
import { dateFr, relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Skeleton, useJson } from "./common";

const MODE_FR: Record<string, string> = {
  account: "Comptes déclarés",
  domain: "Votre domaine",
  subdomain: "Un de vos sous-domaines",
  typosquat: "Domaine ressemblant",
  brand: "Votre marque",
};
const STATUS_CLS: Record<string, string> = { claimed: "tag", sample_verified: "tag tag-prio p-haute", confirmed: "tag tag-bad", false_positive: "tag tag-good" };

/** Fuites repérées sur des forums du darkweb, des canaux Telegram ou des sites de dépôt, rapprochées de votre liste. */
export default function DarkwebPanel({ now }: { now: number }) {
  const { data, error, loading } = useJson<{ leaks: UserLeak[] }>("/api/cti/leaks");
  const leaks = data?.leaks ?? [];
  return (
    <section className="card tm-panel" aria-labelledby="dw-title">
      <h2 id="dw-title">Fuites repérées sur le darkweb</h2>
      <p className="cti-desc">
        Annonces de vente ou de publication de données (forums, places de marché, canaux Telegram, sites de dépôt) transmises par les sources
        partenaires et qualifiées par les analystes, puis rapprochées de vos domaines vérifiés, de vos comptes déclarés et de vos marques.
      </p>
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="form-msg form-err">{error}</p>
      ) : leaks.length === 0 ? (
        <p className="hint">Aucune fuite ne concerne votre liste de surveillance pour le moment.</p>
      ) : (
        <ul className="acc-list">
          {leaks.map((l) => (
            <LeakItem key={l.eventId} l={l} now={now} />
          ))}
        </ul>
      )}
      <p className="hint">
        Les mots de passe, cookies et données personnelles ne sont jamais conservés : VigilantIQ indique seulement leur présence. Les adresses
        sont masquées, sauf celles que vous avez déclarées dans « Comptes exposés ».
      </p>
    </section>
  );
}

function LeakItem({ l, now }: { l: UserLeak; now: number }) {
  const [all, setAll] = useState(false);
  const sev = severityOf(l.score);
  const best = [...l.matches].sort((a, b) => b.score - a.score)[0];
  const shown = all ? l.accounts : l.accounts.slice(0, 12);
  const secrets = l.accounts.filter((a) => a.password || a.cookie).length;
  return (
    <li className={`acc-item sev-${sev}`} id={`fuite-${l.eventId}`}>
      <details>
        <summary>
          <span className="sev-dot" aria-hidden="true" />
          <span className="acc-main">
            <span className="acc-email">{l.title}</span>
            <span className="chips">
              <span className={STATUS_CLS[l.status] ?? "tag"}>{STATUS_FR[l.status as LeakStatus] ?? l.status}</span>
              {best && (
                <span className="tag">
                  {MODE_FR[best.mode] ?? best.mode} · {best.watchValue}
                </span>
              )}
              {l.accountsTotal > 0 && (
                <span className="tag tag-prio p-haute">
                  {fmtInt(l.accountsTotal)} identifiant{l.accountsTotal > 1 ? "s" : ""}
                </span>
              )}
              {secrets > 0 && <span className="tag tag-bad">{fmtInt(secrets)} avec mot de passe ou cookie</span>}
            </span>
            <span className="cti-desc">
              {SOURCE_KIND_FR[l.sourceKind as SourceKind] ?? l.sourceKind} « {l.source} » · fiabilité {l.reliability}
              {l.actor ? ` · vendeur ou auteur : ${l.actor}` : ""}
            </span>
          </span>
          <span className="cti-side">
            <span className="dw-score" title="Score de gravité sur 100">
              {l.score}
            </span>
            <span className="hint">{relTime(l.postedAt ?? l.observedAt, now) || dateFr(l.postedAt ?? l.observedAt)}</span>
          </span>
        </summary>
        <div className="acc-detail">
          <dl className="dw-facts">
            {l.victim && (
              <>
                <dt>Victime annoncée</dt>
                <dd>{l.victim}</dd>
              </>
            )}
            <dt>Publiée</dt>
            <dd>{l.postedAt ? dateFr(l.postedAt) : "date inconnue"} (repérée {relTime(l.observedAt, now)})</dd>
            {l.volume !== null && (
              <>
                <dt>Volume annoncé</dt>
                <dd>{fmtInt(l.volume)} enregistrements</dd>
              </>
            )}
            {l.dataClasses.length > 0 && (
              <>
                <dt>Données concernées</dt>
                <dd>{l.dataClasses.map((c) => CLASS_FR[c as DataClass] ?? c).join(", ")}</dd>
              </>
            )}
            {l.price && (
              <>
                <dt>Prix demandé</dt>
                <dd>{l.price}</dd>
              </>
            )}
            <dt>Rapprochement</dt>
            <dd>{l.matches.map((m) => `${MODE_FR[m.mode] ?? m.mode} (${m.watchValue}, score ${m.score})`).join(" ; ")}</dd>
          </dl>
          {l.accounts.length > 0 && (
            <>
              <p className="cti-title">
                <Icon name="key" size={14} /> Identifiants de vos domaines
              </p>
              <ul className="dw-accounts">
                {shown.map((a, i) => (
                  <li key={`${a.label}-${i}`}>
                    <code className={a.declared ? "dw-declared" : ""}>{a.label}</code>
                    <span className="chips">
                      {a.password && <span className="tag tag-bad">Mot de passe</span>}
                      {a.cookie && <span className="tag tag-bad">Cookie de session</span>}
                      {a.pii && <span className="tag">Données personnelles</span>}
                      {a.declared && <span className="tag tag-good">Compte déclaré</span>}
                    </span>
                  </li>
                ))}
              </ul>
              {l.accounts.length > 12 && (
                <button type="button" className="btn-plain" onClick={() => setAll(!all)}>
                  {all ? "Réduire" : `Voir les ${l.accounts.length} identifiants`}
                </button>
              )}
              {l.accountsTotal > l.accounts.length && <p className="hint">Les 200 premiers identifiants sont affichés sur {fmtInt(l.accountsTotal)}.</p>}
            </>
          )}
          <p className="hint">
            À faire : réinitialiser les mots de passe concernés, révoquer les sessions actives (cookies), vérifier la MFA des comptes et surveiller les
            connexions inhabituelles.
          </p>
        </div>
      </details>
    </li>
  );
}
