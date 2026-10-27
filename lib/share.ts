/**
 * Partage d'une vulnérabilité : lien public signé, textes et liens vers les réseaux.
 *
 * La page publique /partage/{CVE}/{jeton} ne montre que des données publiques (NVD, CVE.org, CISA, EPSS, PoC).
 * Le jeton (HMAC du secret de l'application) n'est délivré qu'aux utilisateurs connectés : seules les CVE
 * effectivement partagées sont consultables sans compte, ce qui évite qu'un anonyme fasse générer
 * des résumés IA pour n'importe quelle CVE.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

function secret(): string | null {
  if (process.env.SHARE_SECRET) return process.env.SHARE_SECRET;
  if (process.env.BETTER_AUTH_SECRET) return process.env.BETTER_AUTH_SECRET;
  if (process.env.DATABASE_URL) return createHash("sha256").update(`vigilantiq:share:${process.env.DATABASE_URL}`).digest("base64url");
  return null;
}

export function shareToken(cveId: string): string | null {
  const s = secret();
  if (!s) return null;
  return createHmac("sha256", s).update(`share:v1:${cveId.toUpperCase()}`).digest("base64url").slice(0, 16);
}

export function verifyShareToken(cveId: string, token: string): boolean {
  const expected = shareToken(cveId);
  if (!expected || typeof token !== "string" || token.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

export function sharePath(cveId: string): string | null {
  const t = shareToken(cveId);
  return t ? `/partage/${cveId.toUpperCase()}/${t}` : null;
}
