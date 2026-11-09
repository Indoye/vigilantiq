"use client";

import { useCallback, useEffect, useState } from "react";
import { countdown, deadlineOf, refLabel } from "@/lib/deadlines";
import { relTime } from "@/lib/format";
import type { Vuln } from "@/lib/types";
import { Icon } from "./ui";
import type { CveStatusValue } from "./useMe";

interface Team {
  assignee: { userId: string; name: string; email: string; assignedAt: string } | null;
  comments: { id: number; userId: string | null; name: string; body: string; createdAt: string; mine: boolean }[];
  members: { userId: string; name: string; email: string }[];
  parc: { devices: number; open: number };
  me: string;
  canEdit: boolean;
}

/** Une phrase : que faire et pour quand, d'après la priorité, l'exploitation et l'échéance. */
function verdict(v: Vuln, status: CveStatusValue, engaged: boolean): { tone: "ok" | "info" | "warn" | "urgent"; text: string } {
  if (status === "traitee") return { tone: "ok", text: "Traitée par votre équipe : rien d’autre à faire." };
  if (status === "non_concernee") return { tone: "ok", text: "Marquée « non concernée » : votre organisation n’utilise pas ce produit." };
  const d = deadlineOf(v);
  const exploited = Boolean(v.kev || v.ssvc?.exploitation === "active");
  // Sans prise en charge par l'organisation, une échéance passée n'est qu'un repère : pas de « retard ».
  const when = d ? (d.daysLeft < 0 ? (engaged || status === "en_cours" ? `échéance dépassée depuis ${-d.daysLeft} j` : refLabel(d).toLowerCase()) : `à corriger ${countdown(d).toLowerCase()}`) : "";
  if (v.priority === "urgente" || (exploited && d && d.daysLeft <= 7))
    return { tone: "urgent", text: `Urgent : ${exploited ? "faille exploitée activement" : "faille critique"}${when ? `, ${when}` : ""}. Corrigez ou isolez les systèmes concernés en priorité.` };
  if (v.priority === "haute") return { tone: "warn", text: `À traiter rapidement${when ? ` (${when})` : ""} : vérifiez si vous utilisez ce produit, puis appliquez le correctif.` };
  return { tone: "info", text: `À planifier${when ? ` (${when})` : ""} : vérifiez si vous êtes concerné et intégrez le correctif au prochain cycle de mises à jour.` };
}

export default function CvePlan({ v, status, engaged = false, onStatus, ticketAnchor }: { v: Vuln; status: CveStatusValue; engaged?: boolean; onStatus: (s: CveStatusValue) => void; ticketAnchor: string }) {
  const [team, setTeam] = useState<Team | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const url = `/api/cve/${v.id}/equipe`;

  const call = useCallback(
    async (init?: RequestInit, q = "") => {
      setErr(null);
      try {
        const r = await fetch(url + q, { cache: "no-store", ...init, headers: { "Content-Type": "application/json" } });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        setTeam(j);
        return true;
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Réseau indisponible.");
        return false;
      }
    },
    [url],
  );
  useEffect(() => {
    void call();
  }, [call]);

  const vd = verdict(v, status, engaged);
  const closed = status === "traitee" || status === "non_concernee";
  const assignTo = (id: string | null) => void call({ method: "PUT", body: JSON.stringify({ assigneeId: id }) });
  const takeIt = async () => {
    if (!team) return;
    assignTo(team.me);
    if (status === "a_traiter") onStatus("en_cours");
  };
  const post = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.trim()) return;
    setBusy(true);
    if (await call({ method: "POST", body: JSON.stringify({ body: draft }) })) setDraft("");
    setBusy(false);
  };

  return (
    <section className={`plan plan-${vd.tone}`} aria-labelledby={`plan-${v.id}`}>
      <h3 id={`plan-${v.id}`}>Que dois-je faire ?</h3>
      <p className="plan-verdict">{vd.text}</p>
      {v.ai?.action && !closed && <p className="plan-reco">{v.ai.action}</p>}

      <div className="plan-owner">
        <Icon name="user" size={15} />
        {team?.assignee ? (
          <span>
            Responsable : <strong>{team.assignee.userId === team.me ? "vous" : team.assignee.name}</strong>
            <span className="hint"> · depuis {relTime(team.assignee.assignedAt)}</span>
          </span>
        ) : (
          <span className="hint">Aucun responsable</span>
        )}
        {team?.canEdit && (
          <select className="plan-select" aria-label="Choisir le responsable" value={team.assignee?.userId ?? ""} onChange={(e) => assignTo(e.target.value || null)}>
            <option value="">— Personne —</option>
            {team.members.map((m) => (
              <option key={m.userId} value={m.userId}>
                {m.userId === team.me ? `${m.name} (moi)` : m.name}
              </option>
            ))}
          </select>
        )}
      </div>

      {team?.canEdit && !closed && (
        <div className="plan-actions">
          {team.assignee?.userId !== team.me && (
            <button type="button" className="btn-primary btn-sm" onClick={takeIt}>
              <Icon name="user" size={14} /> Je m’en occupe
            </button>
          )}
          <a className="btn-secondary btn-sm" href={`#${ticketAnchor}`}>
            <Icon name="send" size={14} /> Créer un ticket
          </a>
          {team.parc.open > 0 && (
            <a className="btn-secondary btn-sm" href="/?vue=parc">
              <Icon name="wrench" size={14} /> Corriger {team.parc.open} équipement{team.parc.open > 1 ? "s" : ""}
            </a>
          )}
          <button type="button" className="btn-secondary btn-sm" onClick={() => onStatus("traitee")}>
            <Icon name="check" size={14} /> C’est corrigé
          </button>
          <button type="button" className="btn-link" onClick={() => onStatus("non_concernee")}>
            Non concerné
          </button>
        </div>
      )}
      {team && team.parc.devices > 0 && (
        <p className="hint plan-parc">
          Parc : {team.parc.open ? `${team.parc.open} équipement${team.parc.open > 1 ? "s" : ""} encore vulnérable${team.parc.open > 1 ? "s" : ""}` : "tous les équipements touchés sont corrigés"} sur{" "}
          {team.parc.devices} concerné{team.parc.devices > 1 ? "s" : ""}.
        </p>
      )}

      <details className="plan-thread" open={(team?.comments.length ?? 0) > 0}>
        <summary>
          <Icon name="message" size={14} /> Discussion de l’équipe{team?.comments.length ? ` (${team.comments.length})` : ""}
        </summary>
        <ul className="plan-comments">
          {team?.comments.map((c) => (
            <li key={c.id}>
              <p className="plan-c-head">
                <strong>{c.mine ? "Vous" : c.name}</strong> <span className="hint">{relTime(c.createdAt)}</span>
                {c.mine && (
                  <button type="button" className="btn-link plan-c-del" onClick={() => call({ method: "DELETE" }, `?commentaire=${c.id}`)}>
                    Supprimer
                  </button>
                )}
              </p>
              <p className="plan-c-body">{c.body}</p>
            </li>
          ))}
          {team && !team.comments.length && <li className="hint">Aucun échange pour l’instant.</li>}
        </ul>
        {team?.canEdit && (
          <form className="plan-form" onSubmit={post}>
            <textarea rows={2} maxLength={4000} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Ajouter une note pour l’équipe (contexte, contournement, avancement…)" />
            <button type="submit" className="btn-secondary btn-sm" disabled={busy || !draft.trim()}>
              {busy ? "Envoi…" : "Publier"}
            </button>
          </form>
        )}
      </details>
      {err && <p className="form-msg form-err">{err}</p>}
    </section>
  );
}
