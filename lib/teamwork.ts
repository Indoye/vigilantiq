/**
 * Travail d'équipe sur une CVE : responsable, fil de discussion, équipements du parc touchés.
 * Tout est isolé par organisation.
 */
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import { getDb } from "@/db";
import { cveAssignment, cveComment, orgMember, patchVuln, user } from "@/db/schema";
import { can, TenantError, type Tenant } from "./tenant";

export interface TeamInfo {
  assignee: { userId: string; name: string; email: string; assignedAt: string } | null;
  comments: { id: number; userId: string | null; name: string; body: string; createdAt: string; mine: boolean }[];
  members: { userId: string; name: string; email: string }[];
  parc: { devices: number; open: number };
  me: string;
  canEdit: boolean;
}

export async function teamInfo(t: Tenant, cveId: string): Promise<TeamInfo> {
  const db = getDb();
  const [a, comments, members, parc] = await Promise.all([
    db
      .select({ userId: cveAssignment.assigneeId, name: user.name, email: user.email, at: cveAssignment.assignedAt })
      .from(cveAssignment)
      .innerJoin(user, eq(user.id, cveAssignment.assigneeId))
      .where(and(eq(cveAssignment.orgId, t.orgId), eq(cveAssignment.cveId, cveId))),
    db
      .select({ id: cveComment.id, userId: cveComment.userId, name: user.name, email: user.email, body: cveComment.body, createdAt: cveComment.createdAt })
      .from(cveComment)
      .leftJoin(user, eq(user.id, cveComment.userId))
      .where(and(eq(cveComment.orgId, t.orgId), eq(cveComment.cveId, cveId)))
      .orderBy(asc(cveComment.createdAt))
      .limit(200),
    db.select({ userId: user.id, name: user.name, email: user.email }).from(orgMember).innerJoin(user, eq(user.id, orgMember.userId)).where(eq(orgMember.orgId, t.orgId)),
    db
      .select({ devices: sql<number>`count(distinct ${patchVuln.deviceId})::int`, open: sql<number>`count(distinct ${patchVuln.deviceId}) filter (where ${patchVuln.status} = 'ouverte')::int` })
      .from(patchVuln)
      .where(and(eq(patchVuln.orgId, t.orgId), eq(patchVuln.cveId, cveId))),
  ]);
  return {
    assignee: a[0] ? { userId: a[0].userId, name: a[0].name, email: a[0].email, assignedAt: a[0].at.toISOString() } : null,
    comments: comments.map((c) => ({ id: c.id, userId: c.userId, name: c.name || c.email || "Ancien membre", body: c.body, createdAt: c.createdAt.toISOString(), mine: c.userId === t.userId })),
    members: members.map((m) => ({ userId: m.userId, name: m.name || m.email, email: m.email })),
    parc: { devices: parc[0]?.devices ?? 0, open: parc[0]?.open ?? 0 },
    me: t.userId,
    canEdit: can(t.role, "analyst"),
  };
}

/** Assigne (ou libère avec null) une ou plusieurs CVE à un membre de l'organisation. */
export async function assign(t: Tenant, cveIds: string[], assigneeId: string | null): Promise<void> {
  if (!can(t.role, "analyst")) throw new TenantError("Réservé aux analystes.", 403);
  const ids = [...new Set(cveIds)].slice(0, 200);
  if (!ids.length) return;
  const db = getDb();
  if (!assigneeId) {
    await db.delete(cveAssignment).where(and(eq(cveAssignment.orgId, t.orgId), inArray(cveAssignment.cveId, ids)));
    return;
  }
  const [m] = await db.select({ u: orgMember.userId }).from(orgMember).where(and(eq(orgMember.orgId, t.orgId), eq(orgMember.userId, assigneeId)));
  if (!m) throw new TenantError("Cette personne ne fait pas partie de l’organisation.", 400);
  await db
    .insert(cveAssignment)
    .values(ids.map((cveId) => ({ orgId: t.orgId, cveId, assigneeId, assignedBy: t.userId })))
    .onConflictDoUpdate({ target: [cveAssignment.orgId, cveAssignment.cveId], set: { assigneeId, assignedBy: t.userId, assignedAt: new Date() } });
}

export async function addComment(t: Tenant, cveId: string, body: string): Promise<void> {
  if (!can(t.role, "analyst")) throw new TenantError("Réservé aux analystes.", 403);
  const b = body.trim().slice(0, 4000);
  if (!b) throw new TenantError("Commentaire vide.");
  await getDb().insert(cveComment).values({ orgId: t.orgId, cveId, userId: t.userId, body: b });
}

export async function deleteComment(t: Tenant, id: number): Promise<void> {
  const db = getDb();
  const [c] = await db.select({ userId: cveComment.userId }).from(cveComment).where(and(eq(cveComment.orgId, t.orgId), eq(cveComment.id, id)));
  if (!c) throw new TenantError("Commentaire introuvable.", 404);
  if (c.userId !== t.userId && !can(t.role, "admin")) throw new TenantError("Vous ne pouvez supprimer que vos commentaires.", 403);
  await db.delete(cveComment).where(and(eq(cveComment.orgId, t.orgId), eq(cveComment.id, id)));
}

/** Responsables de l'organisation pour une liste de CVE (affichage dans les listes). */
export async function assignments(orgId: string): Promise<Record<string, { userId: string; name: string }>> {
  const rows = await getDb()
    .select({ cveId: cveAssignment.cveId, userId: cveAssignment.assigneeId, name: user.name, email: user.email })
    .from(cveAssignment)
    .innerJoin(user, eq(user.id, cveAssignment.assigneeId))
    .where(eq(cveAssignment.orgId, orgId));
  return Object.fromEntries(rows.map((r) => [r.cveId, { userId: r.userId, name: r.name || r.email }]));
}
