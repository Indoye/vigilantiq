"use client";

import { useCallback, useEffect, useState } from "react";
import { relTime } from "@/lib/format";
import { ROLE_LABEL, roleAtLeast, type OrgRole } from "./useMe";

interface Member {
  userId: string;
  name: string;
  email: string;
  role: OrgRole;
  since: string;
  mfa: boolean | null;
}
interface Invite {
  id: string;
  email: string;
  role: OrgRole;
  expiresAt: string;
}
interface ApiKey {
  id: number;
  name: string;
  prefix: string;
  scope: "lecture" | "ecriture";
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
}
interface Org {
  id: string;
  name: string;
  role: OrgRole;
  me: string;
  members: Member[];
  invites: Invite[];
  apiKeys: ApiKey[];
  mail: boolean;
}

const ROLE_HELP: Record<OrgRole, string> = {
  owner: "tous les droits, y compris la gestion des propriétaires",
  admin: "membres, connecteurs, clés d’API, agents",
  analyst: "traite les CVE, alertes, chasses et déploiements",
  viewer: "consultation seule",
};

type Msg = { ok: boolean; text: string } | null;

async function api(url: string, init?: RequestInit): Promise<{ ok: boolean; j: Record<string, unknown> }> {
  try {
    const r = await fetch(url, { ...init, headers: { "Content-Type": "application/json" } });
    return { ok: r.ok, j: (await r.json().catch(() => ({}))) as Record<string, unknown> };
  } catch {
    return { ok: false, j: { error: "Réseau indisponible." } };
  }
}

/** Organisation (locataire) : nom, membres et rôles, invitations, clés d'API. */
export default function OrgPanel({ onRenamed }: { onRenamed?: (name: string) => void }) {
  const [org, setOrg] = useState<Org | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<Msg>(null);
  const [inv, setInv] = useState({ email: "", role: "analyst" as OrgRole });
  const [invLink, setInvLink] = useState<{ link: string; mailed: boolean } | null>(null);
  const [key, setKey] = useState({ name: "", scope: "lecture" });
  const [newKey, setNewKey] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    const { ok, j } = await api("/api/org");
    if (!ok) return setErr(String(j.error ?? "Impossible de charger l’organisation."));
    setOrg(j as unknown as Org);
    setName(String(j.name));
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  if (err) return <p className="form-msg form-err">{err}</p>;
  if (!org) return <p className="hint">Chargement de l’organisation…</p>;
  const admin = roleAtLeast(org.role, "admin");
  const owner = org.role === "owner";

  const run = async (what: string, url: string, init: RequestInit, ok?: string) => {
    setBusy(what);
    setMsg(null);
    const r = await api(url, init);
    setBusy(null);
    if (!r.ok) setMsg({ ok: false, text: String(r.j.error ?? "Échec.") });
    else if (ok) setMsg({ ok: true, text: ok });
    if (r.ok) await load();
    return r;
  };

  const rename = async () => {
    const n = name.trim();
    if (!n || n === org.name) return;
    const r = await run("name", "/api/org", { method: "PATCH", body: JSON.stringify({ name: n }) }, "Nom enregistré.");
    if (r.ok) onRenamed?.(n);
  };
  const invite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInvLink(null);
    const r = await run("invite", "/api/org/invites", { method: "POST", body: JSON.stringify(inv) });
    if (r.ok) {
      setInvLink({ link: String(r.j.link), mailed: Boolean(r.j.mailed) });
      setInv({ ...inv, email: "" });
    }
  };
  const createKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setNewKey(null);
    const r = await run("key", "/api/org/apikeys", { method: "POST", body: JSON.stringify(key) });
    if (r.ok) {
      setNewKey(String(r.j.key));
      setKey({ ...key, name: "" });
    }
  };
  const leave = async () => {
    if (!window.confirm(`Quitter « ${org.name} » ? Vous perdrez l’accès à ses données et repartirez dans une organisation personnelle vide.`)) return;
    const r = await run("leave", "/api/org", { method: "DELETE" });
    if (r.ok) window.location.reload();
  };
  const assignable: OrgRole[] = owner ? ["owner", "admin", "analyst", "viewer"] : ["admin", "analyst", "viewer"];
  const copy = (t: string) => navigator.clipboard?.writeText(t).catch(() => undefined);

  return (
    <>
      <div className="cells">
        <div className="cell">
          <label className="cell-title" htmlFor="org-name">
            Nom
          </label>
          <input id="org-name" type="text" value={name} disabled={!admin} onChange={(e) => setName(e.target.value)} onBlur={rename} maxLength={80} />
        </div>
        <div className="cell">
          <div className="cell-main">
            <span className="cell-title">Votre rôle</span>
            <span className="cell-sub">
              {ROLE_LABEL[org.role]} — {ROLE_HELP[org.role]}
            </span>
          </div>
        </div>
      </div>
      <p className="hint">Les données de l’organisation (stack, suivi des CVE, surveillance, fuites, parc, chasse, connecteurs) sont strictement isolées des autres organisations.</p>
      {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}

      <h3 className="org-sub">Membres ({org.members.length})</h3>
      <div className="cells">
        {org.members.map((m) => {
          const self = m.userId === org.me;
          const editable = admin && !self && (owner || m.role !== "owner");
          return (
            <div key={m.userId} className="cell org-member">
              <div className="cell-main">
                <span className="cell-title">
                  {m.name || m.email}
                  {self ? " (vous)" : ""}
                </span>
                <span className="cell-sub">
                  {m.email}
                  {m.mfa ? "" : " · double authentification non activée"}
                </span>
              </div>
              {editable ? (
                <>
                  <select
                    className="parc-select"
                    aria-label={`Rôle de ${m.email}`}
                    value={m.role}
                    disabled={busy !== null}
                    onChange={(e) => run("role", "/api/org/members", { method: "PATCH", body: JSON.stringify({ userId: m.userId, role: e.target.value }) }, "Rôle mis à jour.")}
                  >
                    {assignable.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="btn-link btn-link-danger"
                    disabled={busy !== null}
                    onClick={() => window.confirm(`Retirer ${m.email} de l’organisation ?`) && run("rm", `/api/org/members?userId=${encodeURIComponent(m.userId)}`, { method: "DELETE" }, "Membre retiré.")}
                  >
                    Retirer
                  </button>
                </>
              ) : (
                <span className="tag">{ROLE_LABEL[m.role]}</span>
              )}
            </div>
          );
        })}
        {org.members.length > 1 && (
          <div className="cell">
            <button type="button" className="btn-link btn-link-danger" onClick={leave} disabled={busy !== null}>
              Quitter l’organisation
            </button>
          </div>
        )}
      </div>

      {admin && (
        <>
          <h3 className="org-sub">Inviter un membre</h3>
          <div className="cells">
            <form className="cell cell-col org-form" onSubmit={invite}>
              <label className="field">
                <span>Adresse e-mail professionnelle</span>
                <input type="email" required value={inv.email} onChange={(e) => setInv({ ...inv, email: e.target.value })} placeholder="prenom.nom@entreprise.com" />
              </label>
              <label className="field">
                <span>Rôle</span>
                <select value={inv.role} onChange={(e) => setInv({ ...inv, role: e.target.value as OrgRole })}>
                  {assignable.map((r) => (
                    <option key={r} value={r}>
                      {ROLE_LABEL[r]} — {ROLE_HELP[r]}
                    </option>
                  ))}
                </select>
              </label>
              <div className="org-actions">
                <button type="submit" className="btn-secondary" disabled={busy !== null}>
                  {busy === "invite" ? "Création…" : "Créer l’invitation"}
                </button>
              </div>
              {invLink && (
                <div className="org-secret">
                  <p className="cell-sub" style={{ margin: 0 }}>
                    {invLink.mailed ? "Invitation envoyée par e-mail. Lien (valable 7 jours) :" : "Transmettez ce lien à la personne invitée (valable 7 jours, affiché une seule fois) :"}
                  </p>
                  <code className="mfa-key">{invLink.link}</code>
                  <button type="button" className="btn-link" onClick={() => copy(invLink.link)}>
                    Copier le lien
                  </button>
                </div>
              )}
            </form>
            {org.invites.map((i) => (
              <div key={i.id} className="cell">
                <div className="cell-main">
                  <span className="cell-title">{i.email}</span>
                  <span className="cell-sub">
                    Invitation en attente · {ROLE_LABEL[i.role]} · expire {relTime(i.expiresAt)}
                  </span>
                </div>
                <button type="button" className="btn-link btn-link-danger" disabled={busy !== null} onClick={() => run("rev", `/api/org/invites?id=${encodeURIComponent(i.id)}`, { method: "DELETE" }, "Invitation révoquée.")}>
                  Révoquer
                </button>
              </div>
            ))}
          </div>
          <p className="hint">La personne invitée rejoint l’organisation en créant son compte avec cette adresse, ou en ouvrant le lien si elle a déjà un compte.</p>

          <h3 className="org-sub">Clés d’API</h3>
          <div className="cells">
            <form className="cell cell-col org-form" onSubmit={createKey}>
              <label className="field">
                <span>Nom de la clé</span>
                <input type="text" required maxLength={60} value={key.name} onChange={(e) => setKey({ ...key, name: e.target.value })} placeholder="SOAR, script d’export…" />
              </label>
              <label className="field">
                <span>Portée</span>
                <select value={key.scope} onChange={(e) => setKey({ ...key, scope: e.target.value })}>
                  <option value="lecture">Lecture — consulter les vulnérabilités et les rapports</option>
                  <option value="ecriture">Écriture — créer aussi des tickets via les connecteurs</option>
                </select>
              </label>
              <div className="org-actions">
                <button type="submit" className="btn-secondary" disabled={busy !== null}>
                  {busy === "key" ? "Création…" : "Créer la clé"}
                </button>
              </div>
              {newKey && (
                <div className="org-secret">
                  <p className="cell-sub" style={{ margin: 0 }}>
                    Copiez cette clé maintenant : elle ne sera plus jamais affichée.
                  </p>
                  <code className="mfa-key">{newKey}</code>
                  <button type="button" className="btn-link" onClick={() => copy(newKey)}>
                    Copier la clé
                  </button>
                </div>
              )}
            </form>
            {org.apiKeys.map((k) => (
              <div key={k.id} className="cell">
                <div className="cell-main">
                  <span className="cell-title">{k.name}</span>
                  <span className="cell-sub">
                    <code>{k.prefix}</code> · {k.scope === "ecriture" ? "écriture" : "lecture"} · {k.revoked ? "révoquée" : k.lastUsedAt ? `utilisée ${relTime(k.lastUsedAt)}` : "jamais utilisée"}
                  </span>
                </div>
                {!k.revoked && (
                  <button type="button" className="btn-link btn-link-danger" disabled={busy !== null} onClick={() => window.confirm(`Révoquer la clé « ${k.name} » ?`) && run("revk", `/api/org/apikeys?id=${k.id}`, { method: "DELETE" }, "Clé révoquée.")}>
                    Révoquer
                  </button>
                )}
              </div>
            ))}
          </div>
          <p className="hint">Une clé n’accède qu’aux données de cette organisation. Envoi : en-tête « Authorization: Bearer vqo_… ».</p>
        </>
      )}
    </>
  );
}
