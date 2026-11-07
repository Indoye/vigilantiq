"use client";

import { navigate } from "@/lib/nav";
import Link from "next/link";
import { useState } from "react";
import { authClient, authError } from "@/lib/auth-client";
import { LogoMark } from "./Logo";
import TwoFactorStep from "./TwoFactorStep";

function GoogleLogo() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
      <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
    </svg>
  );
}

/** Une destination interne uniquement, pour éviter les redirections vers d'autres sites. */
function safeNext(raw: string | null): string {
  return raw && raw.startsWith("/") && !raw.startsWith("//") ? raw : "/";
}

/** Messageries grand public les plus courantes, pour un retour immédiat avant l'envoi. */
const PERSONAL_RE = /@(gmail\.com|googlemail\.com|(yahoo|ymail|hotmail|outlook|live)\.[a-z]{2,3}(\.[a-z]{2})?|msn\.com|icloud\.com|me\.com|mac\.com|aol\.[a-z]{2,3}|proton\.me|protonmail\.(com|ch)|gmx\.[a-z]{2,3}|yandex\.[a-z]{2,3})$/i;

export default function AuthForm({
  google,
  mail,
  next,
  initialMode = "connexion",
  restrictedTo,
  businessOnly = false,
}: {
  google: boolean;
  mail: boolean;
  next: string | null;
  initialMode?: "connexion" | "inscription";
  restrictedTo: string[];
  businessOnly?: boolean;
}) {
  const [mode, setMode] = useState(initialMode);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [mfa, setMfa] = useState(false);
  const dest = safeNext(next);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    // Vérification immédiate des messageries grand public (la liste complète est contrôlée par le serveur)
    if (mode === "inscription" && businessOnly && !restrictedTo.length && PERSONAL_RE.test(email.trim())) {
      setErr("Utilisez votre adresse e-mail professionnelle : les adresses personnelles (Gmail, Yahoo, Outlook, iCloud…) ne permettent pas de créer un compte.");
      return;
    }
    setBusy(true);
    const res =
      mode === "connexion"
        ? await authClient.signIn.email({ email, password, rememberMe: true })
        : await authClient.signUp.email({ name: name.trim() || email.split("@")[0], email, password });
    if (res.error) {
      setErr(authError(res.error));
      setBusy(false);
      return;
    }
    // Compte protégé par la double authentification : deuxième étape (code TOTP)
    if (res.data && "twoFactorRedirect" in res.data && res.data.twoFactorRedirect) {
      setPassword("");
      setBusy(false);
      setMfa(true);
      return;
    }
    navigate(dest);
  };

  const withGoogle = async () => {
    setErr(null);
    setBusy(true);
    const res = await authClient.signIn.social({ provider: "google", callbackURL: dest, errorCallbackURL: "/connexion?erreur=google" });
    if (res?.error) {
      setErr(authError(res.error));
      setBusy(false);
    }
  };

  // Connexion par passkey (Face ID, Touch ID, Windows Hello, clé de sécurité)
  const withPasskey = async () => {
    setErr(null);
    setBusy(true);
    try {
      const res = await authClient.signIn.passkey();
      if (res?.error) {
        setErr(authError(res.error));
        setBusy(false);
        return;
      }
      navigate(dest);
    } catch {
      setErr("Connexion par passkey impossible sur cet appareil.");
      setBusy(false);
    }
  };

  return (
    <div className="auth-card">
      <div className="auth-brand">
        <span className="brand-mark">
          <LogoMark size={44} />
        </span>
        <h1>{mode === "connexion" ? "Connexion à VigilantIQ" : "Créer votre compte"}</h1>
        <p>Les vulnérabilités du jour, leurs versions impactées et les alertes des CERT, expliquées en français.</p>
      </div>

      {mfa ? (
        <div className="auth-panel">
          <TwoFactorStep onDone={() => navigate(dest)} onCancel={() => setMfa(false)} />
        </div>
      ) : (
      <>
      <div className="segmented" role="group" aria-label="Choix">
        <button type="button" aria-pressed={mode === "connexion"} className={mode === "connexion" ? "is-on" : ""} onClick={() => { setMode("connexion"); setErr(null); }}>
          Se connecter
        </button>
        <button type="button" aria-pressed={mode === "inscription"} className={mode === "inscription" ? "is-on" : ""} onClick={() => { setMode("inscription"); setErr(null); }}>
          Créer un compte
        </button>
      </div>

      <div className="auth-panel">
        {mode === "connexion" && (
          <button type="button" className="btn-passkey" onClick={withPasskey} disabled={busy}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="9" cy="8" r="4" />
              <path d="M2 21a7 7 0 0 1 11-5.7 M17 11a3 3 0 1 1 0 6 3 3 0 0 1 0-6z M19.1 16.1L22 19v2h-2v-1h-1v-1h-1" />
            </svg>
            Se connecter avec une passkey
          </button>
        )}
        {mode === "connexion" && !google && <div className="or">ou avec votre e-mail</div>}
        {google && (
          <>
            <button type="button" className="btn-google" onClick={withGoogle} disabled={busy}>
              <GoogleLogo />
              Continuer avec Google
            </button>
            <div className="or">ou avec votre e-mail</div>
          </>
        )}

        <form onSubmit={submit} noValidate={false} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="fields">
            {mode === "inscription" && (
              <div className="field">
                <label htmlFor="f-name">Nom</label>
                <input id="f-name" type="text" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Awa Ndiaye" />
              </div>
            )}
            <div className="field">
              <label htmlFor="f-email">E-mail</label>
              <input id="f-email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="vous@entreprise.sn" />
            </div>
            <div className="field">
              <label htmlFor="f-pass">Mot de passe</label>
              <input
                id="f-pass"
                type="password"
                autoComplete={mode === "connexion" ? "current-password" : "new-password"}
                required
                minLength={mode === "inscription" ? 10 : undefined}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={mode === "inscription" ? "10 caractères minimum" : ""}
              />
            </div>
          </div>
          {mode === "inscription" && restrictedTo.length > 0 && (
            <p className="hint">Inscription réservée aux adresses {restrictedTo.map((d) => "@" + d).join(", ")}.</p>
          )}
          {mode === "inscription" && !restrictedTo.length && businessOnly && (
            <p className="hint">
              Adresse e-mail professionnelle obligatoire : la surveillance, le Threat Hunting et les autres fonctions avancées sont réservés aux
              entreprises. Les tableaux de veille restent accessibles sans compte.
            </p>
          )}
          {err && (
            <p className="form-msg form-err" role="alert">
              {err}
            </p>
          )}
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? "Un instant…" : mode === "connexion" ? "Se connecter" : "Créer mon compte"}
          </button>
        </form>
      </div>
      </>
      )}

      <div className="auth-links">
        {mode === "connexion" && mail && <Link href="/mot-de-passe-oublie">Mot de passe oublié ?</Link>}
        <Link href="/">Continuer sans compte</Link>
      </div>
      <p className="auth-legal">Votre compte conserve votre stack, le suivi de vos CVE et vos préférences de digest.</p>
    </div>
  );
}
