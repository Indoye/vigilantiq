"use client";

import { navigate } from "@/lib/nav";
import { useState } from "react";
import { authClient, authError } from "@/lib/auth-client";
import { parseStack } from "@/lib/stack";
import { Avatar } from "./UserMenu";
import { useMe, type Me, type Settings } from "./useMe";

function Switch({ id, checked, onChange, label }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <span className="switch">
      <input id={id} type="checkbox" role="switch" aria-label={label} checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span />
    </span>
  );
}

export default function AccountView({ initial, linkError }: { initial: Me; linkError: boolean }) {
  const { me, error, saving, saveSettings, setMe } = useMe(initial);
  const m = me ?? initial;
  const s = m.settings;
  const hasPassword = m.providers.includes("credential");
  const hasGoogle = m.providers.includes("google");

  const [name, setName] = useState(m.user.name);
  const [nameMsg, setNameMsg] = useState<string | null>(null);
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);
  const [pw, setPw] = useState({ current: "", next: "" });
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmDel, setConfirmDel] = useState("");
  const [delPw, setDelPw] = useState("");
  const [delMsg, setDelMsg] = useState<string | null>(null);
  const [sessionsMsg, setSessionsMsg] = useState<string | null>(null);

  const saveName = async () => {
    const n = name.trim();
    if (!n || n === m.user.name) return;
    const res = await authClient.updateUser({ name: n });
    if (res.error) setNameMsg(authError(res.error));
    else {
      setNameMsg("Nom enregistré.");
      setMe((x) => (x ? { ...x, user: { ...x.user, name: n } } : x));
    }
  };

  const resendVerification = async () => {
    setBusy("verify");
    const res = await authClient.sendVerificationEmail({ email: m.user.email, callbackURL: "/compte" });
    setBusy(null);
    setVerifyMsg(res.error ? authError(res.error) : "E-mail envoyé. Ouvrez le lien qu’il contient.");
  };

  const changePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy("pw");
    const res = await authClient.changePassword({ currentPassword: pw.current, newPassword: pw.next, revokeOtherSessions: true });
    setBusy(null);
    if (res.error) setPwMsg({ ok: false, text: authError(res.error) });
    else {
      setPwMsg({ ok: true, text: "Mot de passe changé. Vos autres appareils ont été déconnectés." });
      setPw({ current: "", next: "" });
    }
  };

  const linkGoogle = async () => {
    setBusy("google");
    const res = await authClient.linkSocial({ provider: "google", callbackURL: "/compte", errorCallbackURL: "/compte?erreur=liaison" });
    if (res?.error) setBusy(null);
  };

  const revokeOthers = async () => {
    setBusy("sessions");
    const res = await authClient.revokeOtherSessions();
    setBusy(null);
    setSessionsMsg(res.error ? authError(res.error) : "Vos autres appareils ont été déconnectés.");
  };

  const signOut = async () => {
    setBusy("out");
    await authClient.signOut();
    navigate("/connexion");
  };

  const deleteAccount = async () => {
    setBusy("delete");
    const res = await authClient.deleteUser(hasPassword ? { password: delPw } : {});
    if (res.error) {
      setBusy(null);
      setDelMsg(
        res.error.code === "SESSION_EXPIRED"
          ? "Par sécurité, reconnectez-vous puis recommencez la suppression."
          : authError(res.error),
      );
      return;
    }
    navigate("/connexion");
  };

  const set = (patch: Partial<Settings>) => saveSettings(patch);
  const stackCount = parseStack(s.stack).length;

  return (
    <main className="account">
      <h1>Mon compte</h1>

      <section className="acc-head">
        <Avatar me={m} size={56} />
        <div className="menu-id">
          <span className="menu-name">{m.user.name || "Sans nom"}</span>
          <span className="menu-mail">{m.user.email}</span>
          {m.user.emailVerified ? (
            <span className="tag tag-good" style={{ alignSelf: "flex-start", marginTop: 6 }}>
              Adresse confirmée
            </span>
          ) : (
            <span className="hint" style={{ marginTop: 6 }}>
              Adresse non confirmée.{" "}
              {m.features.mail && (
                <button type="button" className="btn-link" onClick={resendVerification} disabled={busy === "verify"}>
                  Renvoyer l’e-mail de confirmation
                </button>
              )}
            </span>
          )}
          {verifyMsg && <span className="hint">{verifyMsg}</span>}
        </div>
      </section>

      <section className="acc-sec" aria-labelledby="h-profil">
        <h2 id="h-profil">Profil</h2>
        <div className="cells">
          <div className="cell">
            <label className="cell-title" htmlFor="acc-name">
              Nom
            </label>
            <input id="acc-name" type="text" value={name} onChange={(e) => setName(e.target.value)} onBlur={saveName} autoComplete="name" />
          </div>
        </div>
        {nameMsg && <p className="hint">{nameMsg}</p>}
      </section>

      <section className="acc-sec" aria-labelledby="h-stack">
        <h2 id="h-stack">Ma stack</h2>
        <div className="cells">
          <div className="cell cell-col">
            <label className="cell-sub" htmlFor="acc-stack">
              Logiciels, éditeurs ou équipements que vous utilisez, séparés par des virgules.
            </label>
            <textarea id="acc-stack" rows={3} value={s.stack} onChange={(e) => set({ stack: e.target.value })} placeholder="fortinet, nginx, wordpress, cisco" />
          </div>
        </div>
        <p className="hint">
          {saving ? "Enregistrement…" : `${stackCount} technologie${stackCount > 1 ? "s" : ""} suivie${stackCount > 1 ? "s" : ""}. Les CVE qui les concernent remontent dans « Ma stack ».`}
        </p>
      </section>

      <section className="acc-sec" aria-labelledby="h-digest">
        <h2 id="h-digest">Digest quotidien par e-mail</h2>
        <div className="cells">
          <div className="cell">
            <div className="cell-main">
              <label className="cell-title" htmlFor="sw-digest">
                Recevoir le digest à 7 h (UTC)
              </label>
              <span className="cell-sub">Seulement les jours où il y a quelque chose à faire.</span>
            </div>
            <Switch id="sw-digest" label="Recevoir le digest" checked={s.digestEnabled} onChange={(v) => set({ digestEnabled: v })} />
          </div>
          <div className="cell">
            <label className="cell-title" htmlFor="sel-prio">
              Inclure à partir de
            </label>
            <select id="sel-prio" value={s.digestMinPriority} onChange={(e) => set({ digestMinPriority: e.target.value as Settings["digestMinPriority"] })} disabled={!s.digestEnabled}>
              <option value="urgente">Urgente</option>
              <option value="haute">Haute</option>
              <option value="moyenne">Moyenne</option>
            </select>
          </div>
          <div className="cell">
            <div className="cell-main">
              <label className="cell-title" htmlFor="sw-stack">
                Seulement ma stack
              </label>
              <span className="cell-sub">Les failles exploitées activement restent toujours incluses.</span>
            </div>
            <Switch id="sw-stack" label="Seulement ma stack" checked={s.digestStackOnly} onChange={(v) => set({ digestStackOnly: v })} />
          </div>
        </div>
        {!m.features.mail ? (
          <p className="hint">L’envoi d’e-mails n’est pas encore configuré sur ce serveur : vos préférences seront appliquées dès qu’il le sera.</p>
        ) : !m.user.emailVerified ? (
          <p className="hint">Confirmez votre adresse pour recevoir le digest.</p>
        ) : (
          <p className="hint">Les CVE que vous avez marquées « Traitée » ou « Non concernée » n’y figurent plus.</p>
        )}
      </section>

      <section className="acc-sec" aria-labelledby="h-secu">
        <h2 id="h-secu">Connexion et sécurité</h2>
        <div className="cells">
          <div className="cell">
            <div className="cell-main">
              <span className="cell-title">Google</span>
              <span className="cell-sub">{hasGoogle ? "Associé à ce compte" : "Non associé"}</span>
            </div>
            {!hasGoogle && m.features.google && (
              <button type="button" className="btn-link" onClick={linkGoogle} disabled={busy === "google"}>
                Associer
              </button>
            )}
          </div>
          <div className="cell">
            <div className="cell-main">
              <span className="cell-title">Mot de passe</span>
              <span className="cell-sub">{hasPassword ? "Défini" : "Aucun : vous vous connectez avec Google"}</span>
            </div>
          </div>
          {hasPassword && (
            <form className="cell cell-col" onSubmit={changePassword} style={{ gap: 8 }}>
              <label className="cell-sub" htmlFor="pw-cur">
                Mot de passe actuel
              </label>
              <input id="pw-cur" type="password" autoComplete="current-password" required value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
              <label className="cell-sub" htmlFor="pw-new">
                Nouveau mot de passe (10 caractères minimum)
              </label>
              <input id="pw-new" type="password" autoComplete="new-password" minLength={10} required value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
              {pwMsg && <p className={`form-msg ${pwMsg.ok ? "form-ok" : "form-err"}`}>{pwMsg.text}</p>}
              <button type="submit" className="btn-secondary" disabled={busy === "pw"}>
                {busy === "pw" ? "Enregistrement…" : "Changer le mot de passe"}
              </button>
            </form>
          )}
          <div className="cell">
            <button type="button" className="btn-link" onClick={revokeOthers} disabled={busy === "sessions"}>
              Déconnecter mes autres appareils
            </button>
          </div>
          <div className="cell">
            <button type="button" className="btn-link" onClick={signOut} disabled={busy === "out"}>
              Se déconnecter
            </button>
          </div>
        </div>
        {sessionsMsg && <p className="hint">{sessionsMsg}</p>}
        {linkError && <p className="hint">L’association avec Google n’a pas abouti. Utilisez le même e-mail que ce compte.</p>}
      </section>

      <section className="acc-sec" aria-labelledby="h-del">
        <h2 id="h-del">Supprimer le compte</h2>
        <div className="cells">
          <div className="cell cell-col" style={{ gap: 8 }}>
            <p className="cell-sub" style={{ margin: 0 }}>
              Votre compte, votre stack, votre suivi des CVE et vos préférences seront effacés définitivement.
            </p>
            {hasPassword && (
              <>
                <label className="cell-sub" htmlFor="del-pw">
                  Mot de passe
                </label>
                <input id="del-pw" type="password" autoComplete="current-password" value={delPw} onChange={(e) => setDelPw(e.target.value)} />
              </>
            )}
            <label className="cell-sub" htmlFor="del-confirm">
              Tapez SUPPRIMER pour confirmer
            </label>
            <input id="del-confirm" type="text" autoComplete="off" value={confirmDel} onChange={(e) => setConfirmDel(e.target.value)} />
            {delMsg && <p className="form-msg form-err">{delMsg}</p>}
            <button
              type="button"
              className="btn-danger"
              disabled={confirmDel !== "SUPPRIMER" || (hasPassword && !delPw) || busy === "delete"}
              onClick={deleteAccount}
            >
              {busy === "delete" ? "Suppression…" : "Supprimer mon compte"}
            </button>
          </div>
        </div>
      </section>

      {error && (
        <p className="toast" role="alert">
          {error}
        </p>
      )}
    </main>
  );
}
