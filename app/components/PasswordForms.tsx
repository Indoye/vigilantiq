"use client";

import Link from "next/link";
import { useState } from "react";
import { authClient, authError } from "@/lib/auth-client";
import { LogoMark } from "./Logo";

function Brand({ title, text }: { title: string; text: string }) {
  return (
    <div className="auth-brand">
      <span className="brand-mark">
        <LogoMark size={44} />
      </span>
      <h1>{title}</h1>
      <p>{text}</p>
    </div>
  );
}

export function ForgotForm({ mail = true }: { mail?: boolean }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const res = await authClient.requestPasswordReset({ email, redirectTo: "/reinitialiser" });
    setBusy(false);
    if (res.error && res.error.status === 429) setErr(authError(res.error));
    // Même message que le compte existe ou non : on ne révèle pas qui est inscrit.
    else setSent(true);
  };

  return (
    <div className="auth-card">
      <Brand title="Mot de passe oublié" text="Indiquez votre e-mail : nous vous envoyons un lien pour choisir un nouveau mot de passe." />
      <div className="auth-panel">
        {!mail ? (
          <p className="form-msg form-err" role="alert">
            L’envoi d’e-mails n’est pas encore configuré sur ce serveur : la réinitialisation par e-mail est indisponible.
            Contactez l’administrateur de VigilantIQ.
          </p>
        ) : sent ? (
          <p className="form-msg form-ok" role="status">
            Si un compte existe pour {email}, un e-mail vient de partir. Le lien est valable une heure. Pensez à regarder
            dans les courriers indésirables.
          </p>
        ) : (
          <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div className="fields">
              <div className="field">
                <label htmlFor="f-email">E-mail</label>
                <input id="f-email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
            </div>
            {err && <p className="form-msg form-err" role="alert">{err}</p>}
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? "Envoi…" : "Envoyer le lien"}
            </button>
          </form>
        )}
      </div>
      <div className="auth-links">
        <Link href="/connexion">Revenir à la connexion</Link>
      </div>
    </div>
  );
}

export function ResetForm({ token, error }: { token: string | null; error: string | null }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState<string | null>(error ? "Ce lien n’est plus valable. Demandez-en un nouveau." : null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    if (password !== confirm) {
      setErr("Les deux mots de passe ne correspondent pas.");
      return;
    }
    setBusy(true);
    setErr(null);
    const res = await authClient.resetPassword({ newPassword: password, token });
    setBusy(false);
    if (res.error) setErr(authError(res.error));
    else setDone(true);
  };

  return (
    <div className="auth-card">
      <Brand title="Nouveau mot de passe" text="Choisissez un mot de passe d’au moins 10 caractères." />
      <div className="auth-panel">
        {done ? (
          <>
            <p className="form-msg form-ok" role="status">
              Mot de passe changé. Vos autres sessions ont été fermées par sécurité.
            </p>
            <Link href="/connexion" className="btn-primary">
              Se connecter
            </Link>
          </>
        ) : token ? (
          <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div className="fields">
              <div className="field">
                <label htmlFor="f-pass">Nouveau mot de passe</label>
                <input id="f-pass" type="password" autoComplete="new-password" minLength={10} required value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="f-pass2">Confirmer le mot de passe</label>
                <input id="f-pass2" type="password" autoComplete="new-password" minLength={10} required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </div>
            </div>
            {err && <p className="form-msg form-err" role="alert">{err}</p>}
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? "Enregistrement…" : "Changer le mot de passe"}
            </button>
          </form>
        ) : (
          <p className="form-msg form-err" role="alert">
            {err ?? "Lien incomplet."} <Link href="/mot-de-passe-oublie">Demander un nouveau lien</Link>
          </p>
        )}
      </div>
    </div>
  );
}
