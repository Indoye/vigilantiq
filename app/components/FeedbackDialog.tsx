"use client";

import { useEffect, useRef, useState } from "react";

const MOODS = [
  { k: "content", e: "😀", l: "J’aime" },
  { k: "neutre", e: "😐", l: "Bof" },
  { k: "mecontent", e: "🙁", l: "Je n’aime pas" },
] as const;

/** Fenêtre « Donner mon avis » : humeur + message libre, enregistrés pour l'équipe produit. */
export default function FeedbackDialog({ onClose }: { onClose: () => void }) {
  const [mood, setMood] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [state, setState] = useState<"idle" | "busy" | "done" | "error">("idle");
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", esc);
    ref.current?.querySelector<HTMLElement>("button")?.focus();
    return () => document.removeEventListener("keydown", esc);
  }, [onClose]);

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mood) return;
    setState("busy");
    const r = await fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mood, message: msg, page: window.location.pathname + window.location.search }),
    }).catch(() => null);
    setState(r?.ok ? "done" : "error");
  };

  return (
    <div className="cmdk-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="fb" role="dialog" aria-modal="true" aria-labelledby="fb-title" ref={ref}>
        {state === "done" ? (
          <>
            <h2 id="fb-title">Merci !</h2>
            <p className="hint">Votre avis a bien été transmis à l’équipe VigilantIQ.</p>
            <button type="button" className="btn-primary btn-sm" onClick={onClose}>
              Fermer
            </button>
          </>
        ) : (
          <form onSubmit={send}>
            <h2 id="fb-title">Votre avis sur VigilantIQ</h2>
            <div className="fb-moods" role="radiogroup" aria-label="Votre impression">
              {MOODS.map((m) => (
                <button key={m.k} type="button" role="radio" aria-checked={mood === m.k} className={`fb-mood${mood === m.k ? " is-on" : ""}`} onClick={() => setMood(m.k)}>
                  <span aria-hidden="true">{m.e}</span>
                  {m.l}
                </button>
              ))}
            </div>
            <textarea rows={4} maxLength={2000} value={msg} onChange={(e) => setMsg(e.target.value)} placeholder="Qu’est-ce qui vous a gêné ou plu ? Une idée d’amélioration ? (facultatif)" />
            {state === "error" && <p className="form-msg form-err">Envoi impossible. Réessayez.</p>}
            <div className="org-actions">
              <button type="submit" className="btn-primary btn-sm" disabled={!mood || state === "busy"}>
                {state === "busy" ? "Envoi…" : "Envoyer"}
              </button>
              <button type="button" className="btn-link" onClick={onClose}>
                Annuler
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
