/**
 * Centre de notifications : alertes de surveillance, correspondances dark web, CVE assignées à l'utilisateur
 * et commentaires de l'équipe sur ses CVE. « Non lu » = postérieur à la dernière ouverture du centre.
 */
import { and, desc, eq, gt, inArray, ne } from "drizzle-orm";
import { getDb } from "@/db";
import { ctiAlert, cveAssignment, cveComment, dwMatch, dwPattern, user, userSettings } from "@/db/schema";
import type { Tenant } from "./tenant";

export interface Notification {
  id: string;
  kind: "alerte" | "darkweb" | "assignation" | "commentaire";
  title: string;
  detail: string;
  href: string;
  severity: string;
  at: string;
  unread: boolean;
}

const DAYS = 30;

export async function notificationsFor(t: Tenant): Promise<{ items: Notification[]; unread: number }> {
  const db = getDb();
  const since = new Date(Date.now() - DAYS * 86_400_000);
  const [us] = await db.select({ seen: userSettings.notificationsSeenAt }).from(userSettings).where(eq(userSettings.userId, t.userId));
  const seen = us?.seen?.getTime() ?? 0;
  const mine = await db.select({ cveId: cveAssignment.cveId }).from(cveAssignment).where(and(eq(cveAssignment.orgId, t.orgId), eq(cveAssignment.assigneeId, t.userId)));
  const myCves = mine.map((m) => m.cveId);
  const [alerts, matches, assigned, comments] = await Promise.all([
    db
      .select({ id: ctiAlert.id, title: ctiAlert.title, severity: ctiAlert.severity, source: ctiAlert.source, watch: ctiAlert.watchValue, at: ctiAlert.createdAt })
      .from(ctiAlert)
      // Les mentions dark web arrivent par leurs correspondances (plus précises) : pas de doublon
      .where(and(eq(ctiAlert.orgId, t.orgId), gt(ctiAlert.createdAt, since), ne(ctiAlert.source, "dw_forum")))
      .orderBy(desc(ctiAlert.createdAt))
      .limit(25),
    db
      .select({ id: dwMatch.id, host: dwMatch.host, name: dwPattern.name, severity: dwPattern.severity, at: dwMatch.createdAt })
      .from(dwMatch)
      .innerJoin(dwPattern, eq(dwPattern.id, dwMatch.patternId))
      .where(and(eq(dwMatch.orgId, t.orgId), gt(dwMatch.createdAt, since), eq(dwMatch.status, "nouvelle")))
      .orderBy(desc(dwMatch.createdAt))
      .limit(15),
    db
      .select({ cveId: cveAssignment.cveId, by: user.name, byMail: user.email, at: cveAssignment.assignedAt, assignedBy: cveAssignment.assignedBy })
      .from(cveAssignment)
      .leftJoin(user, eq(user.id, cveAssignment.assignedBy))
      .where(and(eq(cveAssignment.orgId, t.orgId), eq(cveAssignment.assigneeId, t.userId), gt(cveAssignment.assignedAt, since)))
      .orderBy(desc(cveAssignment.assignedAt))
      .limit(15),
    myCves.length
      ? db
          .select({ id: cveComment.id, cveId: cveComment.cveId, body: cveComment.body, name: user.name, mail: user.email, at: cveComment.createdAt })
          .from(cveComment)
          .leftJoin(user, eq(user.id, cveComment.userId))
          .where(and(eq(cveComment.orgId, t.orgId), inArray(cveComment.cveId, myCves), ne(cveComment.userId, t.userId), gt(cveComment.createdAt, since)))
          .orderBy(desc(cveComment.createdAt))
          .limit(15)
      : Promise.resolve([]),
  ]);
  const items: Notification[] = [
    ...alerts.map((a) => ({ id: `a${a.id}`, kind: "alerte" as const, title: a.title, detail: a.watch, href: "/?vue=surveillance", severity: a.severity, at: a.at.toISOString(), unread: a.at.getTime() > seen })),
    ...matches.map((m) => ({ id: `d${m.id}`, kind: "darkweb" as const, title: `« ${m.name} » repéré sur un forum du dark web`, detail: m.host, href: "/?vue=dark-web", severity: m.severity, at: m.at.toISOString(), unread: m.at.getTime() > seen })),
    ...assigned
      .filter((a) => a.assignedBy !== t.userId)
      .map((a) => ({ id: `s${a.cveId}`, kind: "assignation" as const, title: `${a.by || a.byMail || "Un collègue"} vous a confié ${a.cveId}`, detail: "Vous en êtes responsable", href: `/cve/${a.cveId}`, severity: "info", at: a.at.toISOString(), unread: a.at.getTime() > seen })),
    ...comments.map((c) => ({ id: `c${c.id}`, kind: "commentaire" as const, title: `${c.name || c.mail || "Un collègue"} a commenté ${c.cveId}`, detail: c.body.slice(0, 140), href: `/cve/${c.cveId}`, severity: "info", at: c.at.toISOString(), unread: c.at.getTime() > seen })),
  ].sort((x, y) => y.at.localeCompare(x.at));
  return { items: items.slice(0, 40), unread: items.filter((i) => i.unread).length };
}

export async function markNotificationsSeen(userId: string): Promise<void> {
  await getDb()
    .insert(userSettings)
    .values({ userId, notificationsSeenAt: new Date() })
    .onConflictDoUpdate({ target: userSettings.userId, set: { notificationsSeenAt: new Date() } });
}
