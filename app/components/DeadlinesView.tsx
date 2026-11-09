"use client";

import { countdown, refLabel, type Deadline, type DeadlineLevel } from "@/lib/deadlines";
import { dateFr } from "@/lib/format";
import { PRIORITY_LABEL } from "@/lib/score";
import type { Priority } from "@/lib/types";
import { Icon } from "./ui";
import { STATUS_LABEL, type CveStatusValue } from "./useMe";

export interface DueItem {
  id: string;
  product: string;
  deadline: Deadline;
  priority: Priority | null;
  exploited: boolean;
  ransomware: boolean;
  status: CveStatusValue;
  inFeed: boolean;
  /** Suivie, assignée ou détectée sur le parc : seule une faille prise en charge peut être « en retard ». */
  engaged: boolean;
}

export const LEVEL_LABEL: Record<DeadlineLevel, string> = {
  retard: "Échéance dépassée",
  urgent: "Aujourd’hui à 2 jours",
  proche: "Cette semaine",
  bientot: "Dans les 2 semaines",
  "plus-tard": "Plus tard",
};
const LEVELS: DeadlineLevel[] = ["retard", "urgent", "proche", "bientot", "plus-tard"];

export function DueChip({ d, compact = false, engaged = true }: { d: Deadline; compact?: boolean; engaged?: boolean }) {
  if (d.daysLeft < 0 && !engaged)
    return (
      <span className="due due-ref" title="Échéance passée : un repère, pas un retard (faille ni suivie, ni assignée, ni détectée sur le parc)">
        <Icon name="clock" size={12} />
        {refLabel(d)}
      </span>
    );
  return (
    <span className={`due due-${d.level}`} title={`Échéance ${d.source === "cisa" ? "CISA" : "recommandée"} : ${dateFr(d.date)}`}>
      <Icon name="clock" size={12} />
      {countdown(d)}
      {!compact && <span className="due-src">{d.source === "cisa" ? "CISA" : "recommandée"}</span>}
    </span>
  );
}

function DueRow({ it, onOpen }: { it: DueItem; onOpen: (id: string) => void }) {
  return (
    <li>
      <button type="button" className={`due-row due-row-${it.deadline.level === "retard" && !it.engaged ? "ref" : it.deadline.level}${it.status === "traitee" || it.status === "non_concernee" ? " is-done" : ""}`} onClick={() => onOpen(it.id)}>
        <span className="due-date">
          <span className="due-day">{new Date(it.deadline.date).getUTCDate()}</span>
          <span className="due-month">{new Date(it.deadline.date).toLocaleDateString("fr-FR", { month: "short", timeZone: "UTC" })}</span>
        </span>
        <span className="row-main">
          <span className="row-top">
            <span className="row-product">{it.product}</span>
            <span className="row-id">{it.id}</span>
          </span>
          <span className="chips">
            <DueChip d={it.deadline} engaged={it.engaged} />
            {it.priority && <span className={`tag tag-prio p-${it.priority}`}>{PRIORITY_LABEL[it.priority]}</span>}
            {it.exploited && <span className="tag tag-kev">Exploitée</span>}
            {it.ransomware && <span className="tag tag-bad">Rançongiciels</span>}
            {it.status !== "a_traiter" && <span className={`tag tag-st-${it.status}`}>{STATUS_LABEL[it.status]}</span>}
          </span>
        </span>
        <Icon name="chevron" size={14} className="due-chev" />
      </button>
    </li>
  );
}

/** Calendrier des échéances de correction, des plus urgentes aux plus lointaines. */
export default function DeadlinesView({ items, onOpen, kevError, showDone, setShowDone }: { items: DueItem[]; onOpen: (id: string) => void; kevError: string | null; showDone: boolean; setShowDone: (v: boolean) => void }) {
  const shown = items.filter((i) => showDone || (i.status !== "traitee" && i.status !== "non_concernee"));
  // Échéance passée sans prise en charge : simple repère, regroupé à part et sans alarme.
  const inLevel = (i: DueItem, l: DeadlineLevel) => i.deadline.level === l && (l !== "retard" || i.engaged);
  const reference = shown.filter((i) => i.deadline.level === "retard" && !i.engaged);
  return (
    <div className="cti">
      <p className="lede">
        Dates limites de correction : échéances fixées par la CISA pour les failles exploitées (catalogue KEV), et délais recommandés selon la
        priorité pour les autres (48 h, 7 j, 30 j après publication). Une échéance n’est comptée « dépassée » que pour les failles prises en
        charge par votre organisation (suivies, assignées ou détectées sur votre parc) ; pour les autres, la date reste un simple repère.
      </p>
      <div className="tm-kpis">
        {(["retard", "urgent", "proche", "bientot"] as DeadlineLevel[]).map((l) => (
          <div key={l} className={`tile due-tile due-tile-${l}`}>
            <span className="tile-k">{LEVEL_LABEL[l]}</span>
            <span className="tile-v">{shown.filter((i) => inLevel(i, l)).length}</span>
          </div>
        ))}
      </div>
      <label className="switch-row due-toggle">
        <span>Afficher les vulnérabilités traitées</span>
        <span className="switch">
          <input type="checkbox" role="switch" checked={showDone} onChange={(e) => setShowDone(e.target.checked)} />
          <span />
        </span>
      </label>
      {kevError && <p className="callout callout-err">{kevError}</p>}
      {LEVELS.map((l) => {
        const group = shown.filter((i) => inLevel(i, l));
        if (!group.length) return null;
        return (
          <section key={l} className="due-group" aria-label={LEVEL_LABEL[l]}>
            <h2 className={`due-h due-h-${l}`}>
              {LEVEL_LABEL[l]} <span className="seg-n">{group.length}</span>
            </h2>
            <ul className="list card">
              {group.map((it) => (
                <DueRow key={it.id} it={it} onOpen={onOpen} />
              ))}
            </ul>
          </section>
        );
      })}
      {reference.length > 0 && (
        <section className="due-group" aria-label="Échéances de référence passées">
          <h2 className="due-h">
            Échéance de référence passée <span className="seg-n">{reference.length}</span>
          </h2>
          <p className="hint">Failles ni suivies, ni assignées, ni détectées sur votre parc. Passez-les « en cours » si elles vous concernent, ou « non concernée ».</p>
          <ul className="list card">
            {reference.map((it) => (
              <DueRow key={it.id} it={it} onOpen={onOpen} />
            ))}
          </ul>
        </section>
      )}
      {shown.length === 0 && (
        <div className="empty card">
          <p className="empty-title">Aucune échéance</p>
          <p>Aucune correction à prévoir dans les 45 prochains jours.</p>
        </div>
      )}
    </div>
  );
}
