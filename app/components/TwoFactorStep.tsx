"use client";

import { useEffect, useRef, useState } from "react";
import { authClient, authError } from "@/lib/auth-client";
import { Icon } from "./ui";

/** Deuxième étape de connexion : code TOTP à 6 chiffres (ou code de secours). */
export default function TwoFactorStep({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [backup, setBackup] = useState(false);
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => input.current?.focus(), [backup]);

  const submit = async (value = code) => {
    const clean = backup ? value.trim() : value.replace(/\D/g, "");
    if (!backup && clean.length !== 6) return;
    setBusy(true);
    setErr(null);
    const res = backup
      ? await authClient.twoFactor.verifyBackupCode({ code: clean, trustDevice: trust })
      : await authClient.twoFactor.verifyTotp({ code: clean, trustDevice: trust });
    if (res.error) {
      setErr(authError(res.error));
      setCode("");
      setBusy(false);
      input.current?.focus();
      return;
    }
    onDone();
  };

  return (
    <form
      className="mfa-step"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <span className="mfa-icon" aria-hidden="true">
        <Icon name="lock" size={22} />
      </span>
      <h2>Double authentification</h2>
      <p className="hint">
        {backup
          ? "Saisissez l’un de vos codes de secours (chaque code ne sert qu’une fois)."
          : "Ouvrez votre application d’authentification (Microsoft Authenticator, Google Authenticator, Okta Verify…) et saisissez le code à 6 chiffres affiché pour VigilantIQ."}
      </p>
      <label htmlFor="mfa-code" className="sr-only">
        {backup ? "Code de secours" : "Code à 6 chiffres"}
      </label>
      <input
        ref={input}
        id="mfa-code"
        type="text"
        className={`mfa-code${backup ? " is-backup" : ""}`}
        inputMode={backup ? "text" : "numeric"}
        autoComplete="one-time-code"
        pattern={backup ? undefined : "[0-9]{6}"}
        maxLength={backup ? 24 : 6}
        value={code}
        placeholder={backup ? "XXXXX-XXXXX" : "••••••"}
        onChange={(e) => {
          const v = backup ? e.target.value : e.target.value.replace(/\D/g, "").slice(0, 6);
          setCode(v);
          if (!backup && v.length === 6) void submit(v); // validation automatique au 6e chiffre
        }}
        disabled={busy}
      />
      <label className="mfa-trust">
        <input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} />
        Faire confiance à cet appareil pendant 30 jours
      </label>
      {err && (
        <p className="form-msg form-err" role="alert">
          {err}
        </p>
      )}
      <button type="submit" className="btn-primary" disabled={busy || (!backup && code.length !== 6) || (backup && !code.trim())}>
        {busy ? "Vérification…" : "Vérifier"}
      </button>
      <div className="auth-links">
        <button type="button" className="btn-plain" onClick={() => (setBackup(!backup), setCode(""), setErr(null))}>
          {backup ? "Utiliser l’application d’authentification" : "Utiliser un code de secours"}
        </button>
        <button type="button" className="btn-plain" onClick={onCancel}>
          Annuler
        </button>
      </div>
    </form>
  );
}
