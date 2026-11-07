import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { isAnalyst } from "@/lib/cti/leakstore";
import { configChecks, feedHealth } from "@/lib/platformstatus";
import { currentTenant } from "@/lib/tenant";

export const metadata: Metadata = { title: "État de la plateforme – VigilantIQ", robots: { index: false } };
export const dynamic = "force-dynamic";

const Dot = ({ ok, warn }: { ok: boolean; warn?: boolean }) => <span className={`dot ${ok ? "dot-ok" : warn ? "dot-warn" : "dot-bad"}`} aria-hidden="true" />;

/** Réservé aux opérateurs de la plateforme : configuration, flux en erreur et effets visibles pour les utilisateurs. */
export default async function Etat() {
  const t = await currentTenant();
  if (!t) redirect("/connexion?suite=/etat");
  if (!isAnalyst(t.email)) notFound();
  const checks = configChecks();
  const health = await feedHealth().catch((e) => ({ error: e instanceof Error ? e.message : String(e) }));
  const groups = [...new Set(checks.map((c) => c.group))];
  const missing = checks.filter((c) => !c.ok && !c.optional).length;

  return (
    <div className="app">
      <header className="toolbar page-cve-bar">
        <Link href="/" className="back">
          <svg width="12" height="20" viewBox="0 0 12 20" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M10 2L2 10l8 8" />
          </svg>
          Tableau de veille
        </Link>
        <span className="toolbar-title">État de la plateforme</span>
        <span />
      </header>
      <main className="account etat">
        <p className="hint">
          Visible des opérateurs uniquement. Les utilisateurs ne voient plus ces détails techniques : seulement un message neutre quand une donnée manque.
        </p>
        <section className="acc-sec">
          <h2>{missing ? `${missing} réglage${missing > 1 ? "s" : ""} essentiel${missing > 1 ? "s" : ""} manquant${missing > 1 ? "s" : ""}` : "Configuration"}</h2>
          {groups.map((g) => (
            <div key={g} className="etat-group">
              <h3 className="org-sub">{g}</h3>
              <ul className="cells">
                {checks
                  .filter((c) => c.group === g)
                  .map((c) => (
                    <li key={c.label} className="cell">
                      <div className="cell-main">
                        <span className="cell-title">
                          <Dot ok={c.ok} warn={c.optional} /> {c.label}
                          {c.optional && !c.ok ? " (facultatif)" : ""}
                        </span>
                        {!c.ok && (
                          <span className="cell-sub">
                            {c.impact} À définir dans Vercel : <code>{c.vars}</code>
                          </span>
                        )}
                      </div>
                      <span className={`tag${c.ok ? " tag-good" : ""}`}>{c.ok ? "OK" : "Manquant"}</span>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </section>

        <section className="acc-sec">
          <h2>Sources de données</h2>
          {"error" in health ? (
            <p className="form-msg form-err">{health.error}</p>
          ) : (
            <>
              {health.errors.length > 0 && (
                <ul className="cells">
                  {health.errors.map((e) => (
                    <li key={e} className="cell">
                      <span className="cell-sub">
                        <Dot ok={false} /> {e}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {!health.aiEnabled && <p className="hint">Résumés IA inactifs : clé absente ou crédits épuisés sur le compte Anthropic.</p>}
              <ul className="cells">
                {[...health.sources, ...health.rss].map((s) => (
                  <li key={s.name} className="cell">
                    <div className="cell-main">
                      <span className="cell-title">
                        <Dot ok={s.ok} /> {s.name}
                      </span>
                      {!s.ok && s.detail && <span className="cell-sub">{s.detail}</span>}
                    </div>
                    <span className={`tag${s.ok ? " tag-good" : ""}`}>{s.ok ? "À jour" : "Erreur"}</span>
                  </li>
                ))}
              </ul>
              <p className="hint">Flux générés le {new Date(health.generatedAt).toLocaleString("fr-FR", { timeZone: "UTC" })} UTC.</p>
            </>
          )}
        </section>
      </main>
    </div>
  );
}
