/** Tickets créés dans les outils de l'équipe : un seul par CVE et par outil, pour éviter les doublons. */
import { and, eq, inArray } from "drizzle-orm";
import { dbConfigured, getDb } from "@/db";
import { ticket } from "@/db/schema";
import { sendToConnector, type ConnectorId } from "./connectors";
import type { Remediation, TicketRef, Vuln } from "./types";

function toRef(r: typeof ticket.$inferSelect): TicketRef {
  return { connector: r.connector, externalId: r.externalId, url: r.url, createdAt: r.createdAt.toISOString() };
}

export async function ticketsFor(cveId: string): Promise<TicketRef[]> {
  if (!dbConfigured()) return [];
  const rows = await getDb().select().from(ticket).where(eq(ticket.cveId, cveId));
  return rows.filter((r) => r.externalId !== PENDING).map(toRef);
}

/** CVE déjà envoyées à un outil, parmi une liste. */
export async function alreadySent(connector: ConnectorId, cveIds: string[]): Promise<Set<string>> {
  if (!dbConfigured() || cveIds.length === 0) return new Set();
  const rows = await getDb()
    .select({ cveId: ticket.cveId })
    .from(ticket)
    .where(and(eq(ticket.connector, connector), inArray(ticket.cveId, cveIds)));
  return new Set(rows.map((r) => r.cveId));
}

const PENDING = "__en_cours__";

export class AlreadySentError extends Error {
  constructor(public existing: TicketRef | null) {
    super("Déjà envoyé à cet outil");
  }
}

/**
 * Réserve la ligne (CVE, outil) avant l'envoi : deux clics simultanés ne créent pas deux tickets.
 * En cas d'échec de l'envoi, la réservation est annulée pour permettre un nouvel essai.
 */
export async function sendAndRecord(connector: ConnectorId, v: Vuln, r: Remediation, appUrl: string, userId: string | null): Promise<TicketRef> {
  if (!dbConfigured()) {
    const res = await sendToConnector(connector, v, r, appUrl);
    return { connector, ...res, createdAt: new Date().toISOString() };
  }
  const db = getDb();
  const reserved = await db
    .insert(ticket)
    .values({ cveId: v.id, connector, externalId: PENDING, createdBy: userId })
    .onConflictDoNothing()
    .returning();
  if (reserved.length === 0) {
    const [row] = await db.select().from(ticket).where(and(eq(ticket.cveId, v.id), eq(ticket.connector, connector)));
    throw new AlreadySentError(row && row.externalId !== PENDING ? toRef(row) : null);
  }
  try {
    const res = await sendToConnector(connector, v, r, appUrl);
    const [row] = await db
      .update(ticket)
      .set({ externalId: res.externalId || "envoyé", url: res.url })
      .where(and(eq(ticket.cveId, v.id), eq(ticket.connector, connector)))
      .returning();
    return toRef(row);
  } catch (e) {
    await db.delete(ticket).where(and(eq(ticket.cveId, v.id), eq(ticket.connector, connector)));
    throw e;
  }
}

/** Adresse publique de l'application, pour les liens dans les tickets et e-mails. */
export function appUrl(): string {
  return (
    process.env.APP_URL ||
    process.env.BETTER_AUTH_URL ||
    (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "http://localhost:3000")
  );
}
