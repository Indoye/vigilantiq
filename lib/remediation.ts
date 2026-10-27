/**
 * Recommandations de correctifs et de contournements, générées automatiquement pour chaque CVE.
 *
 * Tout ce qui est affirmé vient d'une source : versions corrigées (éditeur via CVE.org, NVD, OSV),
 * textes « solutions » et « workarounds » de l'éditeur, action exigée par la CISA, références étiquetées
 * « correctif » ou « avis éditeur ». Quand rien n'est publié, on le dit et on propose des mesures
 * d'attente génériques (exposition réseau, type de faiblesse), clairement marquées comme telles.
 * L'IA peut ensuite reformuler en français (voir ai.ts) ; elle n'invente pas de version.
 */
import type { Priority, Remediation, RemediationStep, Vuln } from "./types.ts";

export interface VendorGuidance {
  solutions?: string[];
  workarounds?: string[];
}

const DELAY_DAYS: Record<Priority, number> = { urgente: 2, haute: 7, moyenne: 30, basse: 90 };
const DELAY_LABEL: Record<Priority, string> = {
  urgente: "sous 48 heures",
  haute: "sous 7 jours",
  moyenne: "sous 30 jours",
  basse: "au prochain cycle de mise à jour (90 jours)",
};

const SOURCE_LABEL: Record<string, string> = { CNA: "Éditeur", NVD: "NVD", OSV: "OSV" };

/** Mesures d'attente selon le type de faiblesse (CWE), quand l'éditeur n'en propose pas. */
const CWE_MITIGATION: Record<string, string> = {
  "CWE-22": "Bloquez les chemins contenant « ../ » ou leurs variantes encodées au niveau du proxy inverse ou du WAF.",
  "CWE-77": "Filtrez les caractères de commande (; | & ` $) dans les paramètres exposés, via le WAF si possible.",
  "CWE-78": "Filtrez les caractères de commande (; | & ` $) dans les paramètres exposés, via le WAF si possible.",
  "CWE-79": "Activez une politique CSP stricte et les règles anti-XSS du WAF sur l'application concernée.",
  "CWE-89": "Activez les règles anti-injection SQL du WAF et limitez les droits du compte de base de données.",
  "CWE-94": "Restreignez l'accès à la fonctionnalité vulnérable et activez les règles d'injection de code du WAF.",
  "CWE-287": "Restreignez l'accès à l'interface d'administration (VPN, liste d'adresses autorisées) et surveillez les connexions.",
  "CWE-288": "Restreignez l'accès à l'interface d'administration (VPN, liste d'adresses autorisées) et surveillez les connexions.",
  "CWE-306": "Restreignez l'accès à l'interface concernée (VPN, liste d'adresses autorisées) : elle ne vérifie pas l'identité.",
  "CWE-352": "Vérifiez que les sessions d'administration ne restent pas ouvertes et limitez l'accès à l'interface.",
  "CWE-400": "Activez la limitation de débit et la protection anti-DoS devant le service.",
  "CWE-434": "Bloquez le téléversement de fichiers exécutables et désactivez l'exécution dans les dossiers de téléversement.",
  "CWE-502": "Bloquez les objets sérialisés entrants au WAF et n'exposez pas le service à des sources non fiables.",
  "CWE-611": "Désactivez la résolution des entités externes XML (XXE) dans la configuration si le produit le permet.",
  "CWE-787": "Réduisez l'exposition du service : l'écriture hors limites peut permettre l'exécution de code.",
  "CWE-416": "Réduisez l'exposition du service : l'utilisation après libération peut permettre l'exécution de code.",
  "CWE-918": "Interdisez au serveur concerné les connexions sortantes vers le réseau interne et les métadonnées cloud.",
};

function addDays(now: number, days: number): string {
  return new Date(now + days * 86400_000).toISOString().slice(0, 10);
}

function dateFrLong(iso: string): string {
  return new Date(`${iso.slice(0, 10)}T12:00:00Z`).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
}

/** Délai de traitement : échéance CISA si la faille est au catalogue KEV, sinon selon la priorité. */
export function remediationDeadline(v: Pick<Vuln, "priority" | "kev">, now = Date.now()): { label: string; date: string | null } {
  if (v.kev?.dueDate) {
    const due = v.kev.dueDate.slice(0, 10);
    if (Date.parse(due) < now - 86400_000) return { label: `immédiatement (échéance CISA dépassée depuis le ${dateFrLong(due)})`, date: due };
    return { label: `avant le ${dateFrLong(due)} (échéance CISA)`, date: due };
  }
  return { label: DELAY_LABEL[v.priority], date: addDays(now, DELAY_DAYS[v.priority]) };
}

/** Versions corrigées par produit : « FortiOS : 7.0.14, 7.2.7 ». */
export function fixedVersionSteps(v: Pick<Vuln, "affected">): RemediationStep[] {
  const seen = new Set<string>();
  const steps: RemediationStep[] = [];
  for (const a of v.affected) {
    if (!a.fixed.length) continue;
    const key = a.product.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const fixes = [...new Set(a.fixed)].slice(0, 6);
    const name = a.vendor && !a.product.toLowerCase().includes(a.vendor.toLowerCase()) ? `${a.product} (${a.vendor})` : a.product;
    const text =
      fixes.length === 1
        ? `Mettre à jour ${name} vers la version ${fixes[0]} ou ultérieure.`
        : `Mettre à jour ${name} vers une version corrigée de sa branche : ${fixes.join(", ")} ou ultérieure.`;
    steps.push({ kind: "correctif", text, source: SOURCE_LABEL[a.source] ?? a.source });
    if (steps.length >= 6) break;
  }
  return steps;
}

export function buildRemediation(v: Vuln, vendor: VendorGuidance = {}, now = Date.now()): Remediation {
  const steps: RemediationStep[] = [];
  const deadline = remediationDeadline(v, now);

  // ---------- Correctifs ----------
  const versionSteps = fixedVersionSteps(v);
  steps.push(...versionSteps);

  for (const s of vendor.solutions ?? []) {
    steps.push({ kind: "correctif", text: "Appliquer la solution décrite par l'éditeur.", source: "Éditeur", original: s });
  }

  const patchRefs = v.references.filter((r) => r.tags.includes("Correctif") || r.tags.includes("Avis éditeur")).slice(0, 3);
  for (const r of patchRefs) {
    steps.push({
      kind: "correctif",
      text: r.tags.includes("Correctif") ? "Correctif publié : appliquez-le ou installez la version qui l'intègre." : "Lire l'avis de sécurité de l'éditeur (versions, correctifs, mesures d'attente).",
      source: "Éditeur",
      url: r.url,
    });
  }

  if (v.kev?.action) {
    steps.push({ kind: "correctif", text: "Action exigée par la CISA pour cette faille exploitée.", source: "CISA", original: v.kev.action });
  }

  const patchAvailable = versionSteps.length > 0 || (vendor.solutions?.length ?? 0) > 0 || patchRefs.some((r) => r.tags.includes("Correctif"));

  // ---------- Contournements ----------
  for (const w of vendor.workarounds ?? []) {
    steps.push({ kind: "contournement", text: "Contournement proposé par l'éditeur, en attendant le correctif.", source: "Éditeur", original: w });
  }
  for (const r of v.references.filter((r) => r.tags.includes("Contournement")).slice(0, 2)) {
    steps.push({ kind: "contournement", text: "Mesures d'atténuation documentées.", source: "Référence", url: r.url });
  }

  if (!vendor.workarounds?.length) {
    const network = /AV:N/.test(v.vector ?? "");
    if (!patchAvailable || v.priority === "urgente") {
      steps.push({
        kind: "contournement",
        text: network
          ? "En attendant le correctif, retirez le service d'Internet ou filtrez son accès (pare-feu, VPN, liste d'adresses autorisées)."
          : "En attendant le correctif, limitez l'accès au système concerné aux seuls comptes et postes qui en ont besoin.",
        source: "VigilantIQ",
      });
    }
    const cweHint = v.cwes.map((c) => CWE_MITIGATION[c]).find(Boolean);
    if (cweHint && (!patchAvailable || v.priority === "urgente" || v.priority === "haute")) {
      steps.push({ kind: "contournement", text: cweHint, source: "VigilantIQ" });
    }
  }

  // ---------- Détection ----------
  const exploited = Boolean(v.kev) || v.ssvc?.exploitation === "active";
  const pocs = v.exploits?.length ?? 0;
  if (exploited) {
    const since = v.published ? ` depuis le ${dateFrLong(v.published)}` : "";
    steps.push({
      kind: "detection",
      text: `Faille exploitée : recherchez des traces de compromission sur les systèmes concernés${since} (journaux du service, pare-feu, EDR), avant et après la mise à jour.`,
      source: v.kev ? "CISA" : "SSVC",
    });
  }
  if (v.kev?.ransomware) {
    steps.push({ kind: "detection", text: "Utilisée par des rançongiciels : vérifiez que les sauvegardes sont hors ligne et testées.", source: "CISA" });
  }
  if (pocs > 0) {
    steps.push({
      kind: "detection",
      text: `${pocs} code${pocs > 1 ? "s" : ""} d'exploitation public${pocs > 1 ? "s" : ""} : ajoutez une règle de détection dans le SIEM ou l'IDS et surveillez les tentatives.`,
      source: "VigilantIQ",
    });
  }

  // ---------- Vérification ----------
  steps.push({
    kind: "verification",
    text: patchAvailable
      ? "Après la mise à jour, vérifiez la version installée sur chaque équipement concerné, puis marquez la CVE « Traitée »."
      : "Aucun correctif n'est encore publié : surveillez l'avis de l'éditeur ; VigilantIQ mettra la fiche à jour dès qu'une version corrigée apparaît.",
    source: "VigilantIQ",
  });

  // Le délai est affiché à part : la synthèse dit seulement quoi faire.
  const firstFix = versionSteps[0]?.text;
  const summary = patchAvailable
    ? (firstFix ?? "Appliquer le correctif de l'éditeur.")
    : vendor.workarounds?.length
      ? "Pas encore de correctif : appliquez le contournement de l'éditeur."
      : "Pas encore de correctif publié : limitez l'exposition et surveillez l'avis de l'éditeur.";

  return { deadline: deadline.label, deadlineDate: deadline.date, summary, steps, patchAvailable };
}
