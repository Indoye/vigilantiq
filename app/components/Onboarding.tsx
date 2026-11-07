"use client";

import { useEffect, useState } from "react";
import { Icon } from "./ui";
import { roleAtLeast, type OrgRole } from "./useMe";

interface Step {
  key: string;
  title: string;
  why: string;
  done: boolean;
  action: { label: string; href: string };
  role: "analyst" | "admin";
}

/**
 * Carte « Bien démarrer » de l'accueil : étapes de mise en route de l'organisation, cochées automatiquement
 * à partir des données réelles. Masquable ; disparaît d'elle-même quand tout est fait.
 */
export default function Onboarding({ onStack }: { onStack: () => void }) {
  const [data, setData] = useState<{ steps: Step[]; hidden: boolean; role: OrgRole } | null>(null);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    let alive = true;
    fetch("/api/onboarding", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => alive && j && setData(j))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  if (!data || data.hidden) return null;
  const done = data.steps.filter((s) => s.done).length;
  if (done === data.steps.length) return null;
  const next = data.steps.find((s) => !s.done && roleAtLeast(data.role, s.role));

  const hide = () => {
    setData({ ...data, hidden: true });
    void fetch("/api/onboarding", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hidden: true }) });
  };

  return (
    <section className="card onb" aria-labelledby="onb-title">
      <div className="onb-head">
        <div className="onb-progress" style={{ "--p": `${(done / data.steps.length) * 100}%` } as React.CSSProperties} aria-hidden="true">
          <span>
            {done}/{data.steps.length}
          </span>
        </div>
        <div className="onb-intro">
          <h2 id="onb-title">Bien démarrer avec VigilantIQ</h2>
          <p>{next ? `Prochaine étape : ${next.title.toLowerCase()}.` : "Les étapes restantes sont réservées aux administrateurs de votre organisation."}</p>
        </div>
        <div className="onb-tools">
          <button type="button" className="btn-link" aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? "Réduire" : "Afficher"}
          </button>
          <button type="button" className="icon-btn" aria-label="Masquer définitivement" title="Masquer définitivement" onClick={hide}>
            <Icon name="close" size={14} />
          </button>
        </div>
      </div>
      {open && (
        <ol className="onb-steps">
          {data.steps.map((s) => {
            const allowed = roleAtLeast(data.role, s.role);
            return (
              <li key={s.key} className={`onb-step${s.done ? " is-done" : ""}${next?.key === s.key ? " is-next" : ""}`}>
                <span className="onb-check" aria-hidden="true">
                  {s.done ? <Icon name="check" size={13} /> : null}
                </span>
                <div className="onb-text">
                  <span className="onb-title">
                    {s.title}
                    <span className="sr-only">{s.done ? " (fait)" : " (à faire)"}</span>
                  </span>
                  {!s.done && <span className="onb-why">{s.why}</span>}
                </div>
                {!s.done &&
                  (allowed ? (
                    s.key === "stack" ? (
                      <button type="button" className={next?.key === s.key ? "btn-primary btn-sm" : "btn-secondary btn-sm"} onClick={onStack}>
                        {s.action.label}
                      </button>
                    ) : (
                      <a className={next?.key === s.key ? "btn-primary btn-sm" : "btn-secondary btn-sm"} href={s.action.href}>
                        {s.action.label}
                      </a>
                    )
                  ) : (
                    <span className="hint">Réservé aux administrateurs</span>
                  ))}
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
