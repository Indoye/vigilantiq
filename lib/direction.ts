/** Indicateurs pour la direction / le RSSI : avancement du traitement, alertes, dark web et parc, sur 12 semaines. */
import { and, eq, gt, sql } from "drizzle-orm";
import { getDb } from "@/db";
import { ctiAlert, cveAssignment, cveStatus, dwMatch, orgMember } from "@/db/schema";
import { overview } from "./patch/store";

export async function directionMetrics(orgId: string) {
  const db = getDb();
  const since = new Date(Date.now() - 84 * 86_400_000);
  const d30 = new Date(Date.now() - 30 * 86_400_000);
  const n = sql<number>`count(*)::int`;
  const week = (col: unknown) => sql<string>`to_char(date_trunc('week', ${col}), 'YYYY-MM-DD')`;
  const [byStatus, treatedWeekly, alertsWeekly, alerts30, dw30, members, assigned, parc] = await Promise.all([
    db.select({ status: cveStatus.status, n }).from(cveStatus).where(eq(cveStatus.orgId, orgId)).groupBy(cveStatus.status),
    db
      .select({ week: week(cveStatus.updatedAt), n })
      .from(cveStatus)
      .where(and(eq(cveStatus.orgId, orgId), eq(cveStatus.status, "traitee"), gt(cveStatus.updatedAt, since)))
      .groupBy(sql`1`),
    db
      .select({ week: week(ctiAlert.createdAt), n })
      .from(ctiAlert)
      .where(and(eq(ctiAlert.orgId, orgId), gt(ctiAlert.createdAt, since)))
      .groupBy(sql`1`),
    db.select({ severity: ctiAlert.severity, n }).from(ctiAlert).where(and(eq(ctiAlert.orgId, orgId), gt(ctiAlert.createdAt, d30))).groupBy(ctiAlert.severity),
    db.select({ n }).from(dwMatch).where(and(eq(dwMatch.orgId, orgId), gt(dwMatch.createdAt, d30))),
    db.select({ n }).from(orgMember).where(eq(orgMember.orgId, orgId)),
    db.select({ n }).from(cveAssignment).where(eq(cveAssignment.orgId, orgId)),
    overview(orgId).catch(() => null),
  ]);
  // 12 semaines, lundi par lundi, y compris les semaines vides
  const weeks: string[] = [];
  const monday = new Date();
  monday.setUTCHours(0, 0, 0, 0);
  monday.setUTCDate(monday.getUTCDate() - ((monday.getUTCDay() + 6) % 7));
  for (let i = 11; i >= 0; i--) weeks.push(new Date(monday.getTime() - i * 7 * 86_400_000).toISOString().slice(0, 10));
  const tw = new Map(treatedWeekly.map((r) => [r.week, r.n]));
  const aw = new Map(alertsWeekly.map((r) => [r.week, r.n]));
  const st = Object.fromEntries(byStatus.map((r) => [r.status, r.n]));
  return {
    statuses: { en_cours: st.en_cours ?? 0, traitee: st.traitee ?? 0, non_concernee: st.non_concernee ?? 0 },
    treated30: treatedWeekly.filter((r) => Date.parse(r.week) >= d30.getTime() - 7 * 86_400_000).reduce((a, r) => a + r.n, 0),
    weekly: weeks.map((w) => ({ week: w, treated: tw.get(w) ?? 0, alerts: aw.get(w) ?? 0 })),
    alerts30: Object.fromEntries(alerts30.map((r) => [r.severity, r.n])) as Record<string, number>,
    darkweb30: dw30[0]?.n ?? 0,
    members: members[0]?.n ?? 0,
    assigned: assigned[0]?.n ?? 0,
    parc: parc
      ? { devices: parc.kpis.devices, compliance: parc.kpis.compliance, urgent: parc.kpis.urgent, high: parc.kpis.high, mttrDays: parc.kpis.mttrDays, deploySuccess: parc.kpis.deploySuccess, trend: parc.trend }
      : null,
  };
}
