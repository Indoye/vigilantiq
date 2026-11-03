/**
 * Multitenant : chaque compte appartient à une organisation (locataire) ; toutes les données métier
 * (stack, suivi des CVE, surveillance, Threat Hunting, parc, connecteurs, clés d'API…) sont rattachées
 * à l'organisation et filtrées par elle. Rôles : owner > admin > analyst > viewer.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { and, asc, eq, gt, isNull, ne, sql } from "drizzle-orm";
import { NextResponse } from "next/server";
import { cache } from "react";
import { getDb } from "@/db";
import { organization, orgInvite, orgMember, orgSettings, user } from "@/db/schema";

export const ROLES = ["owner", "admin", "analyst", "viewer"] as const;
export type Role = (typeof ROLES)[number];
const RANK: Record<Role, number> = { owner: 4, admin: 3, analyst: 2, viewer: 1 };
export const ROLE_FR: Record<Role, string> = { owner: "Propriétaire", admin: "Administrateur", analyst: "Analyste", viewer: "Lecteur" };
export const can = (role: Role, min: Role) => RANK[role] >= RANK[min];

export class TenantError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

export interface Tenant {
  orgId: string;
  orgName: string;
  role: Role;
  userId: string;
  email: string;
  user: { id: string; name: string; email: string; image: string | null; emailVerified: boolean; twoFactorEnabled: boolean };
}

const orgNameFor = (email: string, name?: string | null) => email.split("@")[1] || name || "Mon organisation";

/** Organisation personnelle (créée à l'inscription, ou à la volée pour un compte qui n'en a pas). */
export async function createOrgFor(userId: string, email: string, name?: string | null): Promise<string> {
  const db = getDb();
  const id = `org_${randomUUID()}`;
  await db.insert(organization).values({ id, name: orgNameFor(email, name) });
  await db.insert(orgMember).values({ orgId: id, userId, role: "owner" });
  await db.insert(orgSettings).values({ orgId: id, stack: process.env.STACK_KEYWORDS ?? "" }).onConflictDoNothing();
  return id;
}

/** Organisation et rôle d'un compte (mis en cache le temps de la requête). */
export const membershipOf = cache(async (userId: string, email: string): Promise<{ orgId: string; orgName: string; role: Role }> => {
  const db = getDb();
  const [m] = await db
    .select({ orgId: orgMember.orgId, role: orgMember.role, name: organization.name })
    .from(orgMember)
    .innerJoin(organization, eq(organization.id, orgMember.orgId))
    .where(eq(orgMember.userId, userId));
  if (m) return { orgId: m.orgId, orgName: m.name, role: (ROLES.includes(m.role as Role) ? m.role : "viewer") as Role };
  const orgId = await createOrgFor(userId, email);
  return { orgId, orgName: orgNameFor(email), role: "owner" };
});

/** Contexte locataire de la requête, ou null sans session valide (double authentification comprise). */
export async function currentTenant(): Promise<Tenant | null> {
  const { currentSession } = await import("./auth");
  const s = await currentSession();
  if (!s) return null;
  const m = await membershipOf(s.user.id, s.user.email);
  const u = s.user;
  return { ...m, userId: u.id, email: u.email, user: { id: u.id, name: u.name, email: u.email, image: u.image ?? null, emailVerified: u.emailVerified, twoFactorEnabled: Boolean(u.twoFactorEnabled) } };
}

/** Pour les routes : contexte locataire avec un rôle minimal, sinon réponse 401/403. */
export async function requireTenant(min: Role = "viewer", loginMessage = "Connectez-vous pour accéder à cette ressource."): Promise<Tenant | NextResponse> {
  const t = await currentTenant();
  if (!t) return NextResponse.json({ error: loginMessage }, { status: 401 });
  if (!can(t.role, min)) return NextResponse.json({ error: `Action réservée au rôle ${ROLE_FR[min].toLowerCase()} ou supérieur dans votre organisation.` }, { status: 403 });
  return t;
}

// ---------- Gestion de l'organisation ----------

export async function renameOrg(t: Tenant, name: string): Promise<void> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  const n = name.trim().slice(0, 80);
  if (!n) throw new TenantError("Nom obligatoire.");
  await getDb().update(organization).set({ name: n, updatedAt: new Date() }).where(eq(organization.id, t.orgId));
}

export async function listMembers(orgId: string) {
  return getDb()
    .select({ userId: user.id, name: user.name, email: user.email, role: orgMember.role, since: orgMember.createdAt, mfa: user.twoFactorEnabled })
    .from(orgMember)
    .innerJoin(user, eq(user.id, orgMember.userId))
    .where(eq(orgMember.orgId, orgId))
    .orderBy(asc(orgMember.createdAt));
}

async function ownerCount(orgId: string): Promise<number> {
  const [{ n }] = await getDb()
    .select({ n: sql<number>`count(*)::int` })
    .from(orgMember)
    .where(and(eq(orgMember.orgId, orgId), eq(orgMember.role, "owner")));
  return n;
}

export async function setMemberRole(t: Tenant, userId: string, role: string): Promise<void> {
  if (!ROLES.includes(role as Role)) throw new TenantError("Rôle inconnu.");
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  const db = getDb();
  const [m] = await db.select().from(orgMember).where(and(eq(orgMember.orgId, t.orgId), eq(orgMember.userId, userId)));
  if (!m) throw new TenantError("Membre introuvable.", 404);
  // Seul un propriétaire peut nommer ou retirer un propriétaire.
  if ((role === "owner" || m.role === "owner") && t.role !== "owner") throw new TenantError("Seul un propriétaire peut modifier le rôle de propriétaire.", 403);
  if (m.role === "owner" && role !== "owner" && (await ownerCount(t.orgId)) <= 1) throw new TenantError("L’organisation doit garder au moins un propriétaire.");
  await db.update(orgMember).set({ role }).where(and(eq(orgMember.orgId, t.orgId), eq(orgMember.userId, userId)));
}

/** Retire un membre : il repart dans une nouvelle organisation personnelle, vide. */
export async function removeMember(t: Tenant, userId: string): Promise<void> {
  const self = userId === t.userId;
  if (!self && !can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  const db = getDb();
  const [m] = await db.select().from(orgMember).where(and(eq(orgMember.orgId, t.orgId), eq(orgMember.userId, userId)));
  if (!m) throw new TenantError("Membre introuvable.", 404);
  if (m.role === "owner" && !self && t.role !== "owner") throw new TenantError("Seul un propriétaire peut retirer un propriétaire.", 403);
  if (m.role === "owner" && (await ownerCount(t.orgId)) <= 1) throw new TenantError("Nommez d’abord un autre propriétaire.");
  const [u] = await db.select({ email: user.email, name: user.name }).from(user).where(eq(user.id, userId));
  await db.delete(orgMember).where(and(eq(orgMember.orgId, t.orgId), eq(orgMember.userId, userId)));
  await createOrgFor(userId, u?.email ?? "", u?.name);
}

// ---------- Invitations ----------

const INVITE_DAYS = 7;
const hashToken = (t: string) => createHash("sha256").update(t).digest("hex");

export async function createInvite(t: Tenant, email: string, role: string): Promise<{ token: string; expiresAt: Date }> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  const e = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw new TenantError("Adresse e-mail invalide.");
  if (!ROLES.includes(role as Role)) throw new TenantError("Rôle inconnu.");
  if (role === "owner" && t.role !== "owner") throw new TenantError("Seul un propriétaire peut inviter un propriétaire.", 403);
  const db = getDb();
  const [already] = await db
    .select({ id: user.id })
    .from(user)
    .innerJoin(orgMember, eq(orgMember.userId, user.id))
    .where(and(eq(user.email, e), eq(orgMember.orgId, t.orgId)));
  if (already) throw new TenantError("Cette personne fait déjà partie de l’organisation.");
  const token = randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + INVITE_DAYS * 86_400_000);
  // Une seule invitation en cours par adresse et par organisation
  await db.delete(orgInvite).where(and(eq(orgInvite.orgId, t.orgId), eq(orgInvite.email, e), isNull(orgInvite.acceptedAt)));
  await db.insert(orgInvite).values({ id: randomUUID(), orgId: t.orgId, email: e, role, tokenHash: hashToken(token), invitedBy: t.userId, expiresAt });
  return { token, expiresAt };
}

export async function listInvites(orgId: string) {
  return getDb()
    .select({ id: orgInvite.id, email: orgInvite.email, role: orgInvite.role, createdAt: orgInvite.createdAt, expiresAt: orgInvite.expiresAt })
    .from(orgInvite)
    .where(and(eq(orgInvite.orgId, orgId), isNull(orgInvite.acceptedAt), gt(orgInvite.expiresAt, new Date())))
    .orderBy(asc(orgInvite.createdAt));
}

export async function revokeInvite(t: Tenant, id: string): Promise<void> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  await getDb().delete(orgInvite).where(and(eq(orgInvite.orgId, t.orgId), eq(orgInvite.id, id)));
}

export async function inviteInfo(token: string) {
  const [r] = await getDb()
    .select({ id: orgInvite.id, email: orgInvite.email, role: orgInvite.role, orgId: orgInvite.orgId, orgName: organization.name, expiresAt: orgInvite.expiresAt, acceptedAt: orgInvite.acceptedAt })
    .from(orgInvite)
    .innerJoin(organization, eq(organization.id, orgInvite.orgId))
    .where(eq(orgInvite.tokenHash, hashToken(token)));
  if (!r || r.acceptedAt || r.expiresAt < new Date()) return null;
  return r;
}

/**
 * Accepte une invitation : l'adresse du compte doit être celle invitée. Le compte quitte son organisation actuelle,
 * qui est supprimée avec ses données si le compte en était le seul membre.
 */
export async function acceptInvite(token: string, userId: string, email: string): Promise<{ orgId: string; orgName: string }> {
  const inv = await inviteInfo(token);
  if (!inv) throw new TenantError("Invitation invalide ou expirée.", 404);
  if (inv.email !== email.toLowerCase()) throw new TenantError(`Cette invitation est destinée à ${inv.email}. Connectez-vous avec cette adresse.`, 403);
  const db = getDb();
  const [cur] = await db.select().from(orgMember).where(eq(orgMember.userId, userId));
  if (cur?.orgId === inv.orgId) throw new TenantError("Vous faites déjà partie de cette organisation.");
  if (cur) {
    const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(orgMember).where(and(eq(orgMember.orgId, cur.orgId), ne(orgMember.userId, userId)));
    if (n > 0 && cur.role === "owner" && (await ownerCount(cur.orgId)) <= 1) throw new TenantError("Vous êtes le seul propriétaire de votre organisation actuelle : nommez d’abord un autre propriétaire.");
    await db.delete(orgMember).where(eq(orgMember.userId, userId));
    if (n === 0) await db.delete(organization).where(eq(organization.id, cur.orgId));
  }
  await db.insert(orgMember).values({ orgId: inv.orgId, userId, role: inv.role });
  await db.update(orgInvite).set({ acceptedAt: new Date() }).where(eq(orgInvite.id, inv.id));
  return { orgId: inv.orgId, orgName: inv.orgName };
}

/** À l'inscription : rejoint l'organisation qui a invité cette adresse, sinon crée une organisation personnelle. */
export async function onUserCreated(userId: string, email: string, name?: string | null): Promise<void> {
  const db = getDb();
  const [inv] = await db
    .select()
    .from(orgInvite)
    .where(and(eq(orgInvite.email, email.toLowerCase()), isNull(orgInvite.acceptedAt), gt(orgInvite.expiresAt, new Date())))
    .orderBy(asc(orgInvite.createdAt))
    .limit(1);
  if (inv) {
    await db.insert(orgMember).values({ orgId: inv.orgId, userId, role: inv.role }).onConflictDoNothing();
    await db.update(orgInvite).set({ acceptedAt: new Date() }).where(eq(orgInvite.id, inv.id));
    return;
  }
  await createOrgFor(userId, email, name);
}

/** Avant la suppression d'un compte : l'organisation garde un propriétaire, ou disparaît si elle n'a plus de membre. */
export async function onUserDeleting(userId: string): Promise<void> {
  const db = getDb();
  const [m] = await db.select().from(orgMember).where(eq(orgMember.userId, userId));
  if (!m) return;
  const others = await db.select().from(orgMember).where(and(eq(orgMember.orgId, m.orgId), ne(orgMember.userId, userId))).orderBy(asc(orgMember.createdAt));
  if (!others.length) {
    await db.delete(organization).where(eq(organization.id, m.orgId));
    return;
  }
  if (m.role === "owner" && !others.some((o) => o.role === "owner")) {
    const heir = others.find((o) => o.role === "admin") ?? others[0];
    await db.update(orgMember).set({ role: "owner" }).where(and(eq(orgMember.orgId, m.orgId), eq(orgMember.userId, heir.userId)));
  }
}

/** Adresses des membres à prévenir (propriétaires, administrateurs, analystes). */
export async function alertRecipients(orgId: string): Promise<{ email: string; name: string }[]> {
  return getDb()
    .select({ email: user.email, name: user.name })
    .from(orgMember)
    .innerJoin(user, eq(user.id, orgMember.userId))
    .where(and(eq(orgMember.orgId, orgId), ne(orgMember.role, "viewer")));
}

export async function getOrgStack(orgId: string): Promise<string> {
  const [r] = await getDb().select({ stack: orgSettings.stack }).from(orgSettings).where(eq(orgSettings.orgId, orgId));
  return r?.stack ?? "";
}

export async function setOrgStack(orgId: string, stack: string): Promise<void> {
  await getDb()
    .insert(orgSettings)
    .values({ orgId, stack })
    .onConflictDoUpdate({ target: orgSettings.orgId, set: { stack, updatedAt: new Date() } });
}
