/**
 * Accès à l'API v1 : jeton défini par l'administrateur (outils, scripts, SIEM, XSOAR…) ou session d'un utilisateur connecté.
 *
 * VIGILANTIQ_API_TOKENS = "siem:jeton1,xsoar:jeton2" (ou des jetons sans nom, séparés par des virgules).
 * Envoi : en-tête « Authorization: Bearer <jeton> » ou « X-API-Key: <jeton> ». 24 caractères minimum.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { currentSession } from "./auth";

export type Caller = { kind: "token"; name: string; userId: null } | { kind: "session"; name: string; userId: string; email: string };

const digest = (s: string) => createHash("sha256").update(s).digest();

function configuredTokens(): { name: string; hash: Buffer }[] {
  return (process.env.VIGILANTIQ_API_TOKENS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry, i) => {
      const sep = entry.indexOf(":");
      const [name, token] = sep > 0 ? [entry.slice(0, sep).trim(), entry.slice(sep + 1).trim()] : [`jeton-${i + 1}`, entry];
      return { name, token };
    })
    .filter((t) => t.token.length >= 24)
    .map((t) => ({ name: t.name, hash: digest(t.token) }));
}

export function apiTokensConfigured(): boolean {
  return configuredTokens().length > 0;
}

function presentedToken(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (h?.toLowerCase().startsWith("bearer ")) return h.slice(7).trim();
  return req.headers.get("x-api-key")?.trim() || null;
}

export async function authorize(req: Request): Promise<Caller | null> {
  const token = presentedToken(req);
  if (token) {
    const h = digest(token);
    // Comparaison en temps constant, sur l'empreinte (longueur fixe).
    const match = configuredTokens().find((t) => timingSafeEqual(t.hash, h));
    return match ? { kind: "token", name: match.name, userId: null } : null;
  }
  const s = await currentSession();
  return s ? { kind: "session", name: s.user.email, userId: s.user.id, email: s.user.email } : null;
}

export function unauthorized() {
  return NextResponse.json(
    { error: "Authentification requise : jeton API (Authorization: Bearer …) ou session VigilantIQ." },
    { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="vigilantiq"' } },
  );
}

/** ADMIN_EMAILS = adresses autorisées à tester les connecteurs. Vide : tous les utilisateurs connectés. */
export function isAdmin(email: string | null | undefined): boolean {
  const admins = (process.env.ADMIN_EMAILS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (admins.length === 0) return true;
  return Boolean(email && admins.includes(email.toLowerCase()));
}
