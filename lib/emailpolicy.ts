/**
 * Inscription réservée aux adresses professionnelles : les messageries gratuites et jetables
 * (Gmail, Yahoo, Outlook, iCloud, Proton, adresses temporaires…) ne permettent pas de créer un compte.
 * Liste : free-email-domains (MIT, ~30 000 domaines, mise à jour quotidienne en amont) + compléments locaux.
 *
 * SIGNUP_BUSINESS_ONLY=false désactive la règle ; ALLOWED_EMAIL_DOMAINS, s'il est défini, reste prioritaire.
 */
import freeDomains from "free-email-domains";

const EXTRA = ["orange.sn", "yahoo.sn", "gmail.sn"];
const PERSONAL = new Set<string>([...(freeDomains as string[]), ...EXTRA].map((d) => d.toLowerCase()));

export const businessOnly = () => process.env.SIGNUP_BUSINESS_ONLY !== "false";

/** Domaine d'une messagerie gratuite ou jetable (le domaine ou l'un de ses parents est listé). */
export function isPersonalDomain(domain: string): boolean {
  const parts = domain.toLowerCase().replace(/\.$/, "").split(".");
  for (let i = 0; i < parts.length - 1; i++) if (PERSONAL.has(parts.slice(i).join("."))) return true;
  return false;
}

export const PERSONAL_EMAIL_MESSAGE =
  "Utilisez votre adresse e-mail professionnelle : les adresses personnelles ou temporaires (Gmail, Yahoo, Outlook, iCloud…) ne permettent pas de créer un compte VigilantIQ.";

/** Le domaine reçoit-il du courrier (enregistrement MX, ou A à défaut) ? En cas de panne réseau, on ne bloque pas. */
export async function domainReceivesMail(domain: string): Promise<boolean> {
  const q = async (type: "MX" | "A") => {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(4000),
      cache: "no-store",
    });
    if (!r.ok) throw new Error(`DoH ${r.status}`);
    const j = (await r.json()) as { Status?: number; Answer?: { type: number }[] };
    return { nx: j.Status === 3, ok: (j.Answer ?? []).some((a) => a.type === (type === "MX" ? 15 : 1)) };
  };
  try {
    const mx = await q("MX");
    if (mx.ok) return true;
    if (mx.nx) return false;
    return (await q("A")).ok;
  } catch {
    return true;
  }
}
