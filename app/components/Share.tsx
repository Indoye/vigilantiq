"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { productName } from "@/lib/format";
import { networkUrl, shareShortText, shareTitle, type Network, type ShareInfo } from "@/lib/sharetext";
import type { Vuln } from "@/lib/types";
import { LogoMark } from "./Logo";
import { Icon } from "./ui";

export function shareInfoOf(v: Vuln): ShareInfo {
  return {
    id: v.id,
    product: productName(v),
    priority: v.priority,
    score: v.score,
    cvss: v.cvss,
    kev: Boolean(v.kev),
    poc: v.exploits?.length ?? 0,
    summary: v.ai?.resume ?? null,
  };
}

const NETWORKS: { id: Network; label: string; glyph: React.ReactNode; className: string }[] = [
  { id: "email", label: "E-mail", glyph: <Icon name="mail" size={24} />, className: "net-mail" },
  { id: "linkedin", label: "LinkedIn", glyph: <span className="net-letter">L</span>, className: "net-linkedin" },
  { id: "x", label: "X", glyph: <span className="net-letter">X</span>, className: "net-x" },
  { id: "reddit", label: "Reddit", glyph: <span className="net-letter">R</span>, className: "net-reddit" },
];

/**
 * Bouton « Partager » + feuille de partage façon iOS : lien public à copier, e-mail, LinkedIn, X, Reddit,
 * et « Autres » (partage natif de l'appareil) quand le navigateur le propose.
 * `publicUrl` : lien déjà connu (page publique) ; sinon il est demandé au serveur à l'ouverture.
 */
export function ShareButton({ v, publicUrl, className = "btn-secondary" }: { v: Vuln; publicUrl?: string; className?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className={className} onClick={() => setOpen(true)} aria-haspopup="dialog">
        <Icon name="share" size={16} />
        Partager
      </button>
      {open && <ShareSheet v={v} publicUrl={publicUrl} onClose={() => setOpen(false)} />}
    </>
  );
}

function ShareSheet({ v, publicUrl, onClose }: { v: Vuln; publicUrl?: string; onClose: () => void }) {
  const info = shareInfoOf(v);
  const [url, setUrl] = useState<string | null>(publicUrl ?? null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [canNative, setCanNative] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setCanNative(typeof navigator !== "undefined" && typeof navigator.share === "function");
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);

  useEffect(() => {
    if (publicUrl) return;
    let alive = true;
    fetch(`/api/cve/${v.id}/share`, { cache: "no-store" })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!alive) return;
        if (r.ok && j.url) setUrl(j.url);
        else setErr(j.error ?? "Impossible de créer le lien de partage.");
      })
      .catch(() => alive && setErr("Réseau indisponible : réessayez."));
    return () => {
      alive = false;
    };
  }, [v.id, publicUrl]);

  const copy = useCallback(async () => {
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      inputRef.current?.select();
      document.execCommand?.("copy");
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }, [url]);

  const go = (n: Network) => {
    if (!url) return;
    const href = networkUrl(n, info, url);
    if (n === "email") window.location.href = href;
    else window.open(href, "_blank", "noopener,noreferrer,width=640,height=720");
  };

  const native = async () => {
    if (!url) return;
    try {
      await navigator.share({ title: shareTitle(info), text: shareShortText(info), url });
    } catch {
      /* partage annulé */
    }
  };

  return (
    <div className="share-layer" role="presentation">
      <button type="button" className="share-scrim" aria-label="Fermer" onClick={onClose} tabIndex={-1} />
      <div className="share-sheet" role="dialog" aria-modal="true" aria-labelledby="share-title">
        <span className="grabber share-grabber" aria-hidden="true" />
        <header className="share-head">
          <span className="share-icon" aria-hidden="true">
            <LogoMark size={30} />
          </span>
          <div className="share-id">
            <h2 id="share-title">{info.id}</h2>
            <p>
              {info.product} · score {info.score}/100
            </p>
          </div>
          <button ref={closeRef} type="button" className="share-close" onClick={onClose} aria-label="Fermer">
            <Icon name="close" size={14} />
          </button>
        </header>

        <div className="share-nets" role="group" aria-label="Partager via">
          {NETWORKS.map((n) => (
            <button key={n.id} type="button" className="share-net" onClick={() => go(n.id)} disabled={!url}>
              <span className={`net-tile ${n.className}`}>{n.glyph}</span>
              <span className="net-label">{n.label}</span>
            </button>
          ))}
          {canNative && (
            <button type="button" className="share-net" onClick={native} disabled={!url}>
              <span className="net-tile net-more">
                <Icon name="more" size={26} />
              </span>
              <span className="net-label">Autres</span>
            </button>
          )}
        </div>

        <div className="share-link">
          <label htmlFor="share-url" className="share-k">
            Lien de la fiche
          </label>
          <div className="share-field">
            <Icon name="link" size={16} />
            <input
              ref={inputRef}
              id="share-url"
              readOnly
              value={url ?? (err ? "" : "Création du lien…")}
              onFocus={(e) => e.currentTarget.select()}
              aria-describedby="share-note"
            />
            <button type="button" className={`share-copy${copied ? " is-done" : ""}`} onClick={copy} disabled={!url}>
              {copied ? (
                <>
                  <Icon name="check" size={14} /> Copié
                </>
              ) : (
                "Copier"
              )}
            </button>
          </div>
          {err && <p className="callout callout-err">{err}</p>}
          <p id="share-note" className="share-note">
            Le lien ouvre une fiche publique, lisible sans compte : uniquement les données publiques de la CVE (description, scores, versions, sources, PoC). Votre suivi et les tickets de l’équipe ne sont jamais partagés.
          </p>
        </div>
      </div>
      <span className="sr-only" aria-live="polite">
        {copied ? "Lien copié dans le presse-papiers" : ""}
      </span>
    </div>
  );
}
