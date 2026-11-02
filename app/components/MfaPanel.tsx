"use client";

import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { authClient, authError } from "@/lib/auth-client";
import { Icon } from "./ui";

type Step = "off" | "password" | "scan" | "codes" | "on";

/** Clé secrète lisible (groupes de 4) extraite de l'URI otpauth:// */
function secretOf(uri: string): string {
  try {
    return (new URL(uri).searchParams.get("secret") ?? "").replace(/(.{4})/g, "$1 ").trim();
  } catch {
    return "";
  }
}

/**
 * Double authentification TOTP (RFC 6238, 6 chiffres, 30 s) : activation par QR code à scanner avec
 * Microsoft Authenticator, Google Authenticator, Okta Verify, 1Password, Authy…
 * Le QR code est dessiné dans le navigateur : le secret n'est jamais envoyé à un service tiers.
 */
export default function MfaPanel({ enabled, hasPassword }: { enabled: boolean; hasPassword: boolean }) {
  const [step, setStep] = useState<Step>(enabled ? "on" : "off");
  const [password, setPassword] = useState("");
  const [uri, setUri] = useState<string | null>(null);
  const [svg, setSvg] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [action, setAction] = useState<"enable" | "disable" | "regen">("enable");

  useEffect(() => {
    if (!uri) return setSvg(null);
    QRCode.toString(uri, { type: "svg", errorCorrectionLevel: "M", margin: 1, width: 220, color: { dark: "#1c1c1e", light: "#ffffff" } })
      .then(setSvg)
      .catch(() => setErr("QR code impossible à générer : saisissez la clé manuellement."));
  }, [uri]);

  // Le secret ne reste pas en mémoire de la page une fois l'activation terminée ou abandonnée.
  const wipe = () => {
    setUri(null);
    setSvg(null);
    setShowKey(false);
    setCode("");
    setPassword("");
  };

  const withPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    if (action === "enable") {
      const res = await authClient.twoFactor.enable({ password });
      setBusy(false);
      if (res.error || !res.data || !("totpURI" in res.data)) return setErr(authError(res.error));
      setUri(res.data.totpURI);
      setCodes(res.data.backupCodes ?? []);
      setPassword("");
      setStep("scan");
    } else if (action === "disable") {
      const res = await authClient.twoFactor.disable({ password });
      setBusy(false);
      if (res.error) return setErr(authError(res.error));
      wipe();
      setStep("off");
    } else {
      const res = await authClient.twoFactor.generateBackupCodes({ password });
      setBusy(false);
      if (res.error || !res.data) return setErr(authError(res.error));
      setCodes(res.data.backupCodes);
      setPassword("");
      setStep("codes");
    }
  };

  const verify = async (value = code) => {
    if (value.length !== 6) return;
    setBusy(true);
    setErr(null);
    const res = await authClient.twoFactor.verifyTotp({ code: value });
    setBusy(false);
    if (res.error) {
      setCode("");
      return setErr(authError(res.error));
    }
    wipe();
    setStep("codes");
  };

  const download = () => {
    const text = `Codes de secours VigilantIQ – double authentification\nChaque code ne fonctionne qu’une seule fois. Conservez-les en lieu sûr.\n\n${codes.join("\n")}\n`;
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigilantiq-codes-de-secours.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!hasPassword) {
    return (
      <div className="cell cell-col">
        <span className="cell-title">Double authentification (MFA)</span>
        <span className="cell-sub">Disponible pour la connexion par mot de passe. Votre compte utilise Google, qui gère sa propre validation en deux étapes.</span>
      </div>
    );
  }

  return (
    <div className="cell cell-col mfa-panel">
      <div className="mfa-head">
        <span className={`mfa-badge${step === "on" || step === "codes" ? " is-on" : ""}`}>
          <Icon name={step === "on" || step === "codes" ? "check" : "lock"} size={12} />
          {step === "on" || step === "codes" ? "Activée" : "Désactivée"}
        </span>
        <span className="cell-title">Double authentification (MFA)</span>
      </div>

      {step === "off" && (
        <>
          <span className="cell-sub">
            Après votre mot de passe, VigilantIQ demandera un code à 6 chiffres généré par une application d’authentification : Microsoft
            Authenticator, Google Authenticator, Okta Verify, 1Password, Authy…
          </span>
          <button type="button" className="btn-primary mfa-btn" onClick={() => (setAction("enable"), setStep("password"), setErr(null))}>
            Activer la double authentification
          </button>
        </>
      )}

      {step === "on" && (
        <>
          <span className="cell-sub">Un code de votre application d’authentification est demandé à chaque connexion par mot de passe.</span>
          <div className="mfa-actions">
            <button type="button" className="btn-secondary" onClick={() => (setAction("regen"), setStep("password"), setErr(null))}>
              Nouveaux codes de secours
            </button>
            <button type="button" className="btn-secondary mfa-danger" onClick={() => (setAction("disable"), setStep("password"), setErr(null))}>
              Désactiver
            </button>
          </div>
        </>
      )}

      {step === "password" && (
        <form onSubmit={withPassword} className="mfa-form">
          <label className="cell-sub" htmlFor="mfa-pw">
            Confirmez votre mot de passe pour {action === "enable" ? "activer" : action === "disable" ? "désactiver" : "régénérer les codes de"} la double
            authentification
          </label>
          <input id="mfa-pw" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          <div className="mfa-actions">
            <button type="submit" className={`btn-primary mfa-btn${action === "disable" ? " mfa-danger-fill" : ""}`} disabled={busy || !password}>
              {busy ? "Un instant…" : "Continuer"}
            </button>
            <button type="button" className="btn-plain" onClick={() => (setStep(enabled || action !== "enable" ? "on" : "off"), setPassword(""), setErr(null))}>
              Annuler
            </button>
          </div>
        </form>
      )}

      {step === "scan" && (
        <div className="mfa-setup">
          <ol className="mfa-steps">
            <li>Ouvrez votre application d’authentification et choisissez « Ajouter un compte » puis « Scanner un QR code ».</li>
            <li>Scannez ce QR code. Il n’est affiché qu’une fois : ne le partagez pas et ne le photographiez pas.</li>
            <li>Saisissez le code à 6 chiffres affiché par l’application pour terminer.</li>
          </ol>
          <div className="mfa-qr-row">
            <div className="mfa-qr" aria-label="QR code de configuration">
              {svg ? <span dangerouslySetInnerHTML={{ __html: svg }} /> : <span className="hint">Génération…</span>}
            </div>
            <div className="mfa-manual">
              <span className="cell-sub">Impossible de scanner ? Saisissez cette clé dans l’application (type « basé sur le temps ») :</span>
              {showKey ? (
                <code className="mfa-key">{uri ? secretOf(uri) : ""}</code>
              ) : (
                <button type="button" className="btn-plain" onClick={() => setShowKey(true)}>
                  Afficher la clé
                </button>
              )}
              <span className="hint">Compte : VigilantIQ · 6 chiffres · toutes les 30 secondes</span>
            </div>
          </div>
          <form
            className="mfa-form"
            onSubmit={(e) => {
              e.preventDefault();
              void verify();
            }}
          >
            <label className="cell-sub" htmlFor="mfa-verify">
              Code à 6 chiffres
            </label>
            <input
              id="mfa-verify"
              type="text"
              className="mfa-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="••••••"
              value={code}
              onChange={(e) => {
                const v = e.target.value.replace(/\D/g, "").slice(0, 6);
                setCode(v);
                if (v.length === 6) void verify(v);
              }}
              disabled={busy}
            />
            <div className="mfa-actions">
              <button type="submit" className="btn-primary mfa-btn" disabled={busy || code.length !== 6}>
                {busy ? "Vérification…" : "Activer"}
              </button>
              <button type="button" className="btn-plain" onClick={() => (wipe(), setStep("off"), setErr(null))}>
                Annuler
              </button>
            </div>
          </form>
        </div>
      )}

      {step === "codes" && (
        <div className="mfa-setup">
          <p className="cell-sub">
            <strong>Double authentification activée.</strong> Gardez ces codes de secours en lieu sûr : chacun permet une connexion si vous perdez
            votre téléphone. Ils ne seront plus affichés.
          </p>
          <ul className="mfa-codes">
            {codes.map((c) => (
              <li key={c}>
                <code>{c}</code>
              </li>
            ))}
          </ul>
          <div className="mfa-actions">
            <button type="button" className="btn-secondary" onClick={download}>
              <Icon name="file" size={14} /> Télécharger
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(codes.join("\n"));
                } catch {
                  /* presse-papiers indisponible */
                }
              }}
            >
              <Icon name="copy" size={14} /> Copier
            </button>
            <button type="button" className="btn-primary mfa-btn" onClick={() => (setCodes([]), setStep("on"))}>
              J’ai enregistré mes codes
            </button>
          </div>
        </div>
      )}

      {err && (
        <p className="form-msg form-err" role="alert">
          {err}
        </p>
      )}
    </div>
  );
}
