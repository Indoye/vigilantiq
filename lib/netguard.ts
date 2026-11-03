/** Adresses fournies par une organisation (connecteurs, SIEM, MISP…) : HTTPS et nom public uniquement (pas de SSRF). */
export class UnsafeUrlError extends Error {}

export function publicHttpsUrl(raw: string, what = "Le service"): string {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new UnsafeUrlError(`Adresse invalide pour ${what.toLowerCase()}.`);
  }
  if (u.protocol !== "https:") throw new UnsafeUrlError(`${what} doit être joignable en HTTPS.`);
  if (u.username || u.password) throw new UnsafeUrlError("Les identifiants ne doivent pas figurer dans l’adresse.");
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".lan") ||
    /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(h) ||
    h === "::1" ||
    h.startsWith("fd") ||
    h.startsWith("fc") ||
    h.startsWith("fe80") ||
    /^\d+$/.test(h)
  )
    throw new UnsafeUrlError("Adresse locale ou privée refusée : le service doit être joignable depuis Internet.");
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}${u.search}`;
}
