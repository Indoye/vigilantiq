/**
 * Accès à l'API v1 (multitenant) :
 * - clé d'API d'une organisation (« vqo_… », créée dans Mon compte → Organisation) : données de cette organisation ;
 *   portée « lecture » ou « ecriture » (création de tickets) ;
 * - session d'un utilisateur connecté : données de son organisation, selon son rôle ;
 * - jetons de plateforme (VIGILANTIQ_API_TOKENS, hérités) : données publiques uniquement, sans aucune donnée d'organisation.
 * Envoi : en-tête « Authorization: Bearer <clé> » ou « X-API-Key: <clé> ».
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { and, desc, eq, isNull } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db";
import { orgApiKey } from "@/db/schema";
import { can, currentTenant, TenantError, type Role, type Tenant } from "./tenant";

export type Caller =
  | { kind: "platform"; name: string; orgId: null; userId: null; canWrite: false }
  | { kind: "key"; name: string; orgId: string; userId: null; canWrite: boolean }
  | { kind: "session"; name: string; orgId: string; userId: string; email: string; role: Role; canWrite: boolean };

const digest = (s: string) => createHash("sha256").update(s).digest();
const hex = (s: string) => createHash("sha256").update(s).digest("hex");

function platformTokens(): { name: string; hash: Buffer }[] {
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

function presentedToken(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (h?.toLowerCase().startsWith("bearer ")) return h.slice(7).trim();
  return req.headers.get("x-api-key")?.trim() || null;
}

export async function authorize(req: Request): Promise<Caller | null> {
  const token = presentedToken(req);
  if (token) {
    if (/^vqo_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{32,}$/.test(token)) {
      const [k] = await getDb()
        .select()
        .from(orgApiKey)
        .where(and(eq(orgApiKey.keyHash, hex(token)), isNull(orgApiKey.revokedAt)));
      if (!k) return null;
      await getDb().update(orgApiKey).set({ lastUsedAt: new Date() }).where(eq(orgApiKey.id, k.id));
      return { kind: "key", name: k.name, orgId: k.orgId, userId: null, canWrite: k.scope === "ecriture" };
    }
    const h = digest(token);
    // Comparaison en temps constant, sur l'empreinte (longueur fixe).
    const match = platformTokens().find((t) => timingSafeEqual(t.hash, h));
    return match ? { kind: "platform", name: match.name, orgId: null, userId: null, canWrite: false } : null;
  }
  const t = await currentTenant();
  return t ? { kind: "session", name: t.email, orgId: t.orgId, userId: t.userId, email: t.email, role: t.role, canWrite: can(t.role, "analyst") } : null;
}

export function unauthorized() {
  return NextResponse.json(
    { error: "Authentification requise : clé d’API de votre organisation (Authorization: Bearer vqo_…) ou session VigilantIQ." },
    { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="vigilantiq"' } },
  );
}

export function orgRequired() {
  return NextResponse.json({ error: "Cette opération porte sur les données d’une organisation : utilisez une clé d’API d’organisation." }, { status: 403 });
}

// ---------- Clés d'API d'organisation ----------

export async function createApiKey(t: Tenant, name: string, scope: string): Promise<{ id: number; key: string }> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  const n = name.trim().slice(0, 60);
  if (!n) throw new TenantError("Nom de la clé obligatoire.");
  const prefix = randomBytes(6).toString("base64url").replace(/[-_]/g, "x").slice(0, 8);
  const key = `vqo_${prefix}_${randomBytes(24).toString("base64url")}`;
  const [r] = await getDb()
    .insert(orgApiKey)
    .values({ orgId: t.orgId, name: n, prefix, keyHash: hex(key), scope: scope === "ecriture" ? "ecriture" : "lecture", createdBy: t.userId })
    .returning({ id: orgApiKey.id });
  return { id: r.id, key };
}

export async function listApiKeys(orgId: string) {
  const rows = await getDb().select().from(orgApiKey).where(eq(orgApiKey.orgId, orgId)).orderBy(desc(orgApiKey.createdAt));
  return rows.map((r) => ({ id: r.id, name: r.name, prefix: `vqo_${r.prefix}_…`, scope: r.scope, createdAt: r.createdAt.toISOString(), lastUsedAt: r.lastUsedAt?.toISOString() ?? null, revoked: Boolean(r.revokedAt) }));
}

export async function revokeApiKey(t: Tenant, id: number): Promise<void> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  await getDb()
    .update(orgApiKey)
    .set({ revokedAt: new Date() })
    .where(and(eq(orgApiKey.orgId, t.orgId), eq(orgApiKey.id, id)));
}
