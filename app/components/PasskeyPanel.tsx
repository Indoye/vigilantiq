"use client";

import { useCallback, useEffect, useState } from "react";
import { relTime } from "@/lib/format";
import { authClient, authError } from "@/lib/auth-client";

interface Pk {
  id: string;
  name?: string | null;
  createdAt?: string | Date | null;
  deviceType?: string;
  backedUp?: boolean;
}

/** Passkeys du compte : connexion sans mot de passe par Face ID, Touch ID, Windows Hello ou clé de sécurité. */
export default function PasskeyPanel() {
  const [list, setList] = useState<Pk[] | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  // Détecté après l'affichage (évite un écart entre rendu serveur et navigateur)
  const [supported, setSupported] = useState(true);
  useEffect(() => setSupported("PublicKeyCredential" in window), []);

  const load = useCallback(async () => {
    const r = await authClient.passkey.listUserPasskeys();
    setList((r.data as Pk[] | null) ?? []);
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    setBusy(true);
    setMsg(null);
    const ua = navigator.userAgent;
    const device = /iPhone|iPad/.test(ua) ? "iPhone / iPad" : /Mac/.test(ua) ? "Mac" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : "Cet appareil";
    try {
      const r = await authClient.passkey.addPasskey({ name: `${device} – ${new Date().toLocaleDateString("fr-FR")}` });
      if (r?.error) setMsg({ ok: false, text: authError(r.error) });
      else {
        setMsg({ ok: true, text: "Passkey ajoutée : vous pouvez vous connecter sans mot de passe sur cet appareil." });
        await load();
      }
    } catch {
      setMsg({ ok: false, text: "Enregistrement annulé ou non pris en charge par cet appareil." });
    }
    setBusy(false);
  };
  const remove = async (p: Pk) => {
    if (!window.confirm(`Supprimer la passkey « ${p.name ?? "sans nom"} » ?`)) return;
    const r = await authClient.passkey.deletePasskey({ id: p.id });
    if (r?.error) setMsg({ ok: false, text: authError(r.error) });
    await load();
  };

  return (
    <>
      <div className="cell cell-col pk-panel" style={{ gap: 8 }}>
        <span className="cell-title">Passkeys</span>
        <span className="cell-sub">
          Connectez-vous en un geste avec Face ID, Touch ID, Windows Hello ou une clé de sécurité, sans mot de passe ni code. Une passkey ne peut pas être
          hameçonnée : elle ne fonctionne que sur VigilantIQ.
        </span>
        {!supported ? (
          <span className="hint">Ce navigateur ne prend pas en charge les passkeys.</span>
        ) : (
          <div className="org-actions">
            <button type="button" className="btn-secondary btn-sm" onClick={add} disabled={busy}>
              {busy ? "En attente de l’appareil…" : "Ajouter une passkey"}
            </button>
          </div>
        )}
        {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
      </div>
      {list?.map((p) => (
        <div key={p.id} className="cell">
          <div className="cell-main">
            <span className="cell-title">{p.name || "Passkey"}</span>
            <span className="cell-sub">
              {p.backedUp ? "Synchronisée (trousseau)" : "Liée à cet appareil"}
              {p.createdAt ? ` · ajoutée ${relTime(new Date(p.createdAt).toISOString())}` : ""}
            </span>
          </div>
          <button type="button" className="btn-link btn-link-danger" onClick={() => remove(p)}>
            Supprimer
          </button>
        </div>
      ))}
    </>
  );
}
