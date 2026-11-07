/**
 * État de la plateforme, pour les opérateurs (VIGILANTIQ_ANALYSTS) : ce qui est configuré, ce qui manque,
 * et l'effet visible pour les utilisateurs. Seule la présence des variables est testée, jamais leur valeur.
 */
import { getDailyFeed } from "./feed";
import { getRssSnapshot } from "./rss";

export interface Check {
  group: string;
  label: string;
  ok: boolean;
  /** Ce que voient les utilisateurs quand l'élément manque */
  impact: string;
  /** Variables d'environnement à définir */
  vars: string;
  optional?: boolean;
}

const has = (...k: string[]) => k.every((x) => Boolean(process.env[x]));

export function configChecks(): Check[] {
  return [
    { group: "Essentiel", label: "Base de données", ok: has("DATABASE_URL"), impact: "Comptes et suivi indisponibles.", vars: "DATABASE_URL" },
    { group: "Essentiel", label: "Secret d’authentification", ok: has("BETTER_AUTH_SECRET"), impact: "Connexion impossible.", vars: "BETTER_AUTH_SECRET" },
    { group: "Essentiel", label: "Tâches planifiées", ok: has("CRON_SECRET"), impact: "Pas de veille quotidienne, d’e-mails ni de collecte automatique.", vars: "CRON_SECRET" },
    { group: "Essentiel", label: "Envoi d’e-mails", ok: has("SMTP_HOST", "SMTP_USER", "SMTP_PASS") || has("RESEND_API_KEY"), impact: "Ni résumé quotidien, ni alertes, ni invitations par e-mail.", vars: "SMTP_HOST, SMTP_USER, SMTP_PASS (ou RESEND_API_KEY)" },
    { group: "Intelligence artificielle", label: "Résumés en français", ok: has("ANTHROPIC_API_KEY"), impact: "Les CVE s’affichent avec leur description anglaise d’origine.", vars: "ANTHROPIC_API_KEY (et crédits sur le compte)" },
    { group: "Intelligence artificielle", label: "Agent de Threat Hunting", ok: has("AI_API_KEY", "AI_MODEL", "AI_BASE_URL"), impact: "Pas d’investigation assistée par IA.", vars: "AI_API_KEY, AI_MODEL, AI_BASE_URL", optional: true },
    { group: "Renseignement", label: "Cloudflare Radar", ok: has("CLOUDFLARE_API_TOKEN"), impact: "ThreatMap sans flux pays → pays ni origines des attaques.", vars: "CLOUDFLARE_API_TOKEN" },
    { group: "Renseignement", label: "Flux abuse.ch", ok: has("ABUSECH_AUTH_KEY"), impact: "Moins d’indicateurs (domaines, empreintes).", vars: "ABUSECH_AUTH_KEY", optional: true },
    { group: "Renseignement", label: "NVD (limite élevée)", ok: has("NVD_API_KEY"), impact: "Rafraîchissement des CVE plus lent.", vars: "NVD_API_KEY", optional: true },
    { group: "Renseignement", label: "PoC GitHub", ok: has("GITHUB_TOKEN"), impact: "Détection des preuves de concept limitée.", vars: "GITHUB_TOKEN", optional: true },
    { group: "Dark web", label: "Collecte Apify", ok: has("APIFY_TOKEN"), impact: "Aucune page collectée sur les forums.", vars: "APIFY_TOKEN", optional: true },
    { group: "Dark web", label: "Cluster OpenSearch / Elastic", ok: has("DARKWEB_SEARCH_URL") && (has("DARKWEB_SEARCH_API_KEY") || has("DARKWEB_SEARCH_USER")), impact: "Motifs dark web sans corpus à interroger.", vars: "DARKWEB_SEARCH_URL, DARKWEB_SEARCH_API_KEY", optional: true },
    { group: "Dark web", label: "Ingestion des fuites", ok: has("LEAK_INGEST_SECRET"), impact: "Clés des sources de fuites dérivées du secret d’authentification.", vars: "LEAK_INGEST_SECRET", optional: true },
    { group: "Connexion", label: "Connexion Google", ok: has("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"), impact: "Bouton « Continuer avec Google » masqué.", vars: "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET", optional: true },
  ];
}

export async function feedHealth() {
  const rss = await getRssSnapshot();
  const feed = await getDailyFeed(rss);
  return {
    generatedAt: feed.generatedAt,
    errors: feed.errors,
    aiEnabled: feed.aiEnabled,
    sources: feed.sources,
    rss: rss.sources.map((s) => ({ name: s.name, ok: s.ok, detail: s.detail ?? null })),
  };
}
