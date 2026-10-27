import { and, eq } from "drizzle-orm";
import { getDb } from "@/db";
import { account, cveStatus, userSettings } from "@/db/schema";

export const STATUSES = ["a_traiter", "en_cours", "traitee", "non_concernee"] as const;
export type CveStatusValue = (typeof STATUSES)[number];
export const MIN_PRIORITIES = ["urgente", "haute", "moyenne"] as const;

export interface Settings {
  stack: string;
  digestEnabled: boolean;
  digestMinPriority: (typeof MIN_PRIORITIES)[number];
  digestStackOnly: boolean;
}

export async function getSettings(userId: string): Promise<Settings> {
  const db = getDb();
  const [row] = await db.select().from(userSettings).where(eq(userSettings.userId, userId));
  if (row) {
    return {
      stack: row.stack,
      digestEnabled: row.digestEnabled,
      digestMinPriority: (MIN_PRIORITIES as readonly string[]).includes(row.digestMinPriority)
        ? (row.digestMinPriority as Settings["digestMinPriority"])
        : "haute",
      digestStackOnly: row.digestStackOnly,
    };
  }
  // Compte créé avant l'ajout des préférences : on crée la ligne par défaut.
  const defaults: Settings = { stack: process.env.STACK_KEYWORDS ?? "", digestEnabled: true, digestMinPriority: "haute", digestStackOnly: false };
  await db.insert(userSettings).values({ userId, ...defaults }).onConflictDoNothing();
  return defaults;
}

/** Valide une mise à jour partielle venue du navigateur ; renvoie null si elle est invalide. */
export function parseSettingsPatch(body: unknown): Partial<Settings> | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  const out: Partial<Settings> = {};
  if ("stack" in b) {
    if (typeof b.stack !== "string" || b.stack.length > 2000) return null;
    out.stack = b.stack;
  }
  if ("digestEnabled" in b) {
    if (typeof b.digestEnabled !== "boolean") return null;
    out.digestEnabled = b.digestEnabled;
  }
  if ("digestStackOnly" in b) {
    if (typeof b.digestStackOnly !== "boolean") return null;
    out.digestStackOnly = b.digestStackOnly;
  }
  if ("digestMinPriority" in b) {
    if (!(MIN_PRIORITIES as readonly unknown[]).includes(b.digestMinPriority)) return null;
    out.digestMinPriority = b.digestMinPriority as Settings["digestMinPriority"];
  }
  return Object.keys(out).length ? out : null;
}

export async function updateSettings(userId: string, patch: Partial<Settings>): Promise<Settings> {
  await getSettings(userId);
  await getDb()
    .update(userSettings)
    .set({ ...patch, updatedAt: new Date() })
    .where(eq(userSettings.userId, userId));
  return getSettings(userId);
}

export async function getStatuses(userId: string): Promise<Record<string, CveStatusValue>> {
  const rows = await getDb().select().from(cveStatus).where(eq(cveStatus.userId, userId));
  return Object.fromEntries(rows.map((r) => [r.cveId, r.status as CveStatusValue]));
}

export async function setStatus(userId: string, cveId: string, status: CveStatusValue): Promise<void> {
  const db = getDb();
  if (status === "a_traiter") {
    await db.delete(cveStatus).where(and(eq(cveStatus.userId, userId), eq(cveStatus.cveId, cveId)));
    return;
  }
  await db
    .insert(cveStatus)
    .values({ userId, cveId, status })
    .onConflictDoUpdate({ target: [cveStatus.userId, cveStatus.cveId], set: { status, updatedAt: new Date() } });
}

/** Méthodes de connexion du compte : « credential » (mot de passe) et/ou « google ». */
export async function getProviders(userId: string): Promise<string[]> {
  const rows = await getDb().select({ p: account.providerId }).from(account).where(eq(account.userId, userId));
  return [...new Set(rows.map((r) => r.p))];
}
