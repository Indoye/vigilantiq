"use client";

import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { authClient, authError } from "@/lib/auth-client";
import { navigate } from "@/lib/nav";
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
/** Mot de passe absent (compte Google uniquement) : le serveur l'accepte (allowPasswordless). */
const pw = (password: string) => (password ? { password } : ({} as { password: string }));

/**
 * `required` : activation obligatoire (page /double-authentification), sans possibilité d'annuler ;
 * `next` : page où revenir une fois les codes de secours enregistrés.
 */
export default function MfaPanel({ enabled, hasPassword, required = false, next = "/" }: { enabled: boolean; hasPassword: boolean; required?: boolean; next?: string }) {
  const [step, setStep] = useState<Step>(enabled ? "on" : required && hasPassword ? "password" : "off");
  const [password, setPassword] = useState("");
  const [uri, setUri] = useState<string | null>(null);
  const [svg, setSvg] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [action, setAction] = useState<"enable" | "reset" | "regen">("enable");

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

  const startEnable = async () => {
    const res = await authClient.twoFactor.enable(pw(password));
    setBusy(false);
    if (res.error || !res.data || !("totpURI" in res.data)) return setErr(authError(res.error));
    setUri(res.data.totpURI);
    setCodes(res.data.backupCodes ?? []);
    setPassword("");
    setStep("scan");
  };

  const withPassword = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setErr(null);
    if (action === "enable") {
      await startEnable();
    } else if (action === "reset") {
      // Changer d'application : l'ancien secret est révoqué, un nouveau QR code est généré aussitôt.
      // La double authentification reste obligatoire : sans nouvelle activation, l'accès est bloqué.
      const res = await authClient.twoFactor.disable(pw(password));
      if (res.error) {
        setBusy(false);
        return setErr(authError(res.error));
      }
      await startEnable();
    } else {
      const res = await authClient.twoFactor.generateBackupCodes(pw(password));
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

  const ask = (a: typeof action) => {
    setAction(a);
    setErr(null);
    if (hasPassword) setStep("password");
    else void withPasswordAs(a);
  };
  // Compte Google uniquement : pas de mot de passe à confirmer.
  const withPasswordAs = async (a: typeof action) => {
    setBusy(true);
    if (a === "enable") return startEnable();
    if (a === "reset") {
      const res = await authClient.twoFactor.disable(pw(""));
      if (res.error) return setBusy(false), setErr(authError(res.error));
      return startEnable();
    }
    const res = await authClient.twoFactor.generateBackupCodes(pw(""));
    setBusy(false);
    if (res.error || !res.data) return setErr(authError(res.error));
    setCodes(res.data.backupCodes);
    setStep("codes");
  };
  const leave = async () => {
    await authClient.signOut();
    navigate("/connexion");
  };
  const isOn = step === "on" || step === "codes";

  return (
    <div className="cell cell-col mfa-panel">
      <div className="mfa-head">
        <span className={`mfa-badge${isOn ? " is-on" : ""}`}>
          <Icon name={isOn ? "check" : "lock"} size={12} />
          {isOn ? "Activée" : "Obligatoire"}
        </span>
        <span className="cell-title">Double authentification (MFA)</span>
      </div>

      {step === "off" && (
        <>
          <span className="cell-sub">
            À chaque connexion, VigilantIQ demande un code à 6 chiffres généré par une application d’authentification : Microsoft
            Authenticator, Google Authenticator, Okta Verify, 1Password, Authy…
          </span>
          <button type="button" className="btn-primary mfa-btn" disabled={busy} onClick={() => ask("enable")}>
            {busy ? "Un instant…" : "Activer la double authentification"}
          </button>
        </>
      )}

      {step === "on" && (
        <>
          <span className="cell-sub">
            Obligatoire pour tous les comptes : un code de votre application d’authentification est demandé à chaque connexion.
          </span>
          <div className="mfa-actions">
            <button type="button" className="btn-secondary" disabled={busy} onClick={() => ask("regen")}>
              Nouveaux codes de secours
            </button>
            <button type="button" className="btn-secondary" disabled={busy} onClick={() => ask("reset")}>
              Changer d’application ou de téléphone
            </button>
          </div>
        </>
      )}

      {step === "password" && (
        <form onSubmit={withPassword} className="mfa-form">
          <label className="cell-sub" htmlFor="mfa-pw">
            {action === "enable"
              ? "Confirmez votre mot de passe pour activer la double authentification"
              : action === "reset"
                ? "Confirmez votre mot de passe : l’ancienne application cessera de fonctionner et un nouveau QR code sera affiché"
                : "Confirmez votre mot de passe pour générer de nouveaux codes de secours (les anciens ne fonctionneront plus)"}
          </label>
          <input id="mfa-pw" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          <div className="mfa-actions">
            <button type="submit" className="btn-primary mfa-btn" disabled={busy || !password}>
              {busy ? "Un instant…" : "Continuer"}
            </button>
            {required ? (
              <button type="button" className="btn-plain" onClick={leave}>
                Se déconnecter
              </button>
            ) : (
              <button type="button" className="btn-plain" onClick={() => (setStep(action === "enable" ? "off" : "on"), setPassword(""), setErr(null))}>
                Annuler
              </button>
            )}
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
              {required ? (
                <button type="button" className="btn-plain" onClick={leave}>
                  Se déconnecter
                </button>
              ) : action === "enable" ? (
                <button type="button" className="btn-plain" onClick={() => (wipe(), setStep("off"), setErr(null))}>
                  Annuler
                </button>
              ) : null}
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
            <button type="button" className="btn-primary mfa-btn" onClick={() => (setCodes([]), required ? navigate(next) : setStep("on"))}>
              {required ? "J’ai enregistré mes codes, continuer" : "J’ai enregistré mes codes"}
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
