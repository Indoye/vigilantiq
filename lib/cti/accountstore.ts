/** Comptes exposés : vérification de propriété des domaines, import des adresses, contrôles progressifs. */
import { randomBytes } from "node:crypto";
import { and, asc, eq, inArray, isNotNull, isNull, lt, or, sql } from "drizzle-orm";
import { dbConfigured, getDb } from "@/db";
import { watchAccount, watchItem } from "@/db/schema";
import { belongsTo, domainHasToken, draftAccount, extractEmails, fetchAccountBreaches, fetchAccountStealers, type AccountBreach, type AccountStealer } from "./accounts.ts";
import { saveDrafts } from "./store.ts";

export const MAX_ACCOUNTS = Number(process.env.CTI_MAX_ACCOUNTS || 500);
const RECHECK_MS = 7 * 86400_000;

export class AccountError extends Error {}

// ---------- Propriété du domaine ----------

export async function verifyDomain(userId: string, watchId: number): Promise<{ verified: boolean; token: string; domain: string }> {
  const db = getDb();
  const [w] = await db.select().from(watchItem).where(and(eq(watchItem.userId, userId), eq(watchItem.id, watchId)));
  if (!w || w.kind !== "domain") throw new AccountError("Domaine introuvable dans votre liste.");
  let token = w.verifyToken;
  if (!token) {
    token = randomBytes(12).toString("hex");
    await db.update(watchItem).set({ verifyToken: token }).where(eq(watchItem.id, w.id));
  }
  if (w.verifiedAt) return { verified: true, token, domain: w.value };
  const ok = await domainHasToken(w.value, token);
  if (ok) await db.update(watchItem).set({ verifiedAt: new Date() }).where(eq(watchItem.id, w.id));
  return { verified: ok, token, domain: w.value };
}

async function verifiedDomains(userId: string): Promise<string[]> {
  const rows = await getDb()
    .select({ value: watchItem.value })
    .from(watchItem)
    .where(and(eq(watchItem.userId, userId), eq(watchItem.kind, "domain"), isNotNull(watchItem.verifiedAt)));
  return rows.map((r) => r.value);
}

// ---------- Adresses ----------

export interface AccountRow {
  id: number;
  domain: string;
  email: string;
  status: string;
  breaches: AccountBreach[];
  stealers: AccountStealer[];
  error: string | null;
  checkedAt: string | null;
}

export async function listAccounts(userId: string): Promise<AccountRow[]> {
  const rows = await getDb().select().from(watchAccount).where(eq(watchAccount.userId, userId)).orderBy(asc(watchAccount.email));
  return rows.map((r) => ({
    id: r.id,
    domain: r.domain,
    email: r.email,
    status: r.status,
    breaches: r.breaches as unknown as AccountBreach[],
    stealers: r.stealers as unknown as AccountStealer[],
    error: r.error,
    checkedAt: r.checkedAt?.toISOString() ?? null,
  }));
}

/** Ajoute les adresses appartenant à un domaine vérifié de l'utilisateur ; les autres sont refusées. */
export async function addAccounts(userId: string, text: string): Promise<{ added: number; rejected: string[]; duplicates: number }> {
  const domains = await verifiedDomains(userId);
  if (!domains.length) throw new AccountError("Vérifiez d’abord la propriété d’un domaine (enregistrement DNS TXT).");
  const emails = extractEmails(text);
  if (!emails.length) throw new AccountError("Aucune adresse e-mail valide trouvée.");
  const accepted: { email: string; domain: string }[] = [];
  const rejected: string[] = [];
  for (const e of emails) {
    const d = domains.find((dom) => belongsTo(e, dom));
    if (d) accepted.push({ email: e, domain: d });
    else rejected.push(e);
  }
  const db = getDb();
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(watchAccount).where(eq(watchAccount.userId, userId));
  const room = Math.max(0, MAX_ACCOUNTS - n);
  if (accepted.length > room) throw new AccountError(`Limite de ${MAX_ACCOUNTS} comptes surveillés : il reste ${room} place(s).`);
  let added = 0;
  for (let i = 0; i < accepted.length; i += 200) {
    const res = await db
      .insert(watchAccount)
      .values(accepted.slice(i, i + 200).map((a) => ({ userId, ...a })))
      .onConflictDoNothing()
      .returning({ id: watchAccount.id });
    added += res.length;
  }
  return { added, rejected: rejected.slice(0, 50), duplicates: accepted.length - added };
}

export async function removeAccounts(userId: string, ids: number[] | "all"): Promise<void> {
  const where = ids === "all" ? eq(watchAccount.userId, userId) : and(eq(watchAccount.userId, userId), inArray(watchAccount.id, ids));
  await getDb().delete(watchAccount).where(where);
}

// ---------- Contrôles ----------

async function checkOne(row: typeof watchAccount.$inferSelect): Promise<number> {
  const [b, s] = await Promise.allSettled([fetchAccountBreaches(row.email), fetchAccountStealers(row.email)]);
  const breaches = b.status === "fulfilled" ? b.value : (row.breaches as unknown as AccountBreach[]);
  const stealers = s.status === "fulfilled" ? s.value : (row.stealers as unknown as AccountStealer[]);
  const errors = [b, s].filter((r): r is PromiseRejectedResult => r.status === "rejected").map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)));
  const bothFailed = errors.length === 2;
  const status = bothFailed ? "error" : breaches.length || stealers.length ? "exposed" : "clean";
  await getDb()
    .update(watchAccount)
    .set({ status, breaches: breaches as unknown as Record<string, unknown>[], stealers: stealers as unknown as Record<string, unknown>[], error: errors.join(" ; ") || null, checkedAt: new Date() })
    .where(eq(watchAccount.id, row.id));
  return bothFailed ? 0 : saveDrafts(row.userId, draftAccount(row.email, b.status === "fulfilled" ? breaches : [], s.status === "fulfilled" ? stealers : []));
}

const due = () =>
  or(
    isNull(watchAccount.checkedAt),
    lt(watchAccount.checkedAt, new Date(Date.now() - RECHECK_MS)),
    and(eq(watchAccount.status, "error"), lt(watchAccount.checkedAt, new Date(Date.now() - 3600_000))),
  );

/** Contrôle un lot d'adresses (jamais vérifiées, en erreur ou vérifiées il y a plus de 7 jours). */
export async function checkAccounts(userId: string | null, batch = 12): Promise<{ checked: number; alerts: number; remaining: number }> {
  if (!dbConfigured()) return { checked: 0, alerts: 0, remaining: 0 };
  const db = getDb();
  const where = userId ? and(eq(watchAccount.userId, userId), due()) : due();
  const rows = await db.select().from(watchAccount).where(where).orderBy(asc(watchAccount.checkedAt)).limit(batch);
  let alerts = 0;
  // 3 en parallèle pour rester poli avec les services gratuits
  for (let i = 0; i < rows.length; i += 3) {
    const res = await Promise.allSettled(rows.slice(i, i + 3).map(checkOne));
    for (const r of res) if (r.status === "fulfilled") alerts += r.value;
  }
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(watchAccount).where(userId ? and(eq(watchAccount.userId, userId), due()) : due());
  return { checked: rows.length, alerts, remaining: n };
}
