import { and, eq } from "drizzle-orm";
import { getDb } from "@/db";
import { account, cveStatus, userSettings } from "@/db/schema";
import { getOrgStack, setOrgStack } from "./tenant";

export const STATUSES = ["a_traiter", "en_cours", "traitee", "non_concernee"] as const;
export type CveStatusValue = (typeof STATUSES)[number];
export const MIN_PRIORITIES = ["urgente", "haute", "moyenne"] as const;

export interface Settings {
  stack: string;
  digestEnabled: boolean;
  digestMinPriority: (typeof MIN_PRIORITIES)[number];
  digestStackOnly: boolean;
}

/** Préférences : la stack est celle de l'organisation ; le digest est propre à chaque compte. */
export async function getSettings(userId: string, orgId: string): Promise<Settings> {
  const db = getDb();
  const [[row], stack] = await Promise.all([db.select().from(userSettings).where(eq(userSettings.userId, userId)), getOrgStack(orgId)]);
  if (row) {
    return {
      stack,
      digestEnabled: row.digestEnabled,
      digestMinPriority: (MIN_PRIORITIES as readonly string[]).includes(row.digestMinPriority)
        ? (row.digestMinPriority as Settings["digestMinPriority"])
        : "haute",
      digestStackOnly: row.digestStackOnly,
    };
  }
  // Compte créé avant l'ajout des préférences : on crée la ligne par défaut.
  const defaults = { digestEnabled: true, digestMinPriority: "haute" as const, digestStackOnly: false };
  await db.insert(userSettings).values({ userId, ...defaults }).onConflictDoNothing();
  return { stack, ...defaults };
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

export async function updateSettings(userId: string, orgId: string, patch: Partial<Settings>): Promise<Settings> {
  await getSettings(userId, orgId);
  const { stack, ...personal } = patch;
  if (stack !== undefined) await setOrgStack(orgId, stack);
  if (Object.keys(personal).length) await getDb().update(userSettings).set({ ...personal, updatedAt: new Date() }).where(eq(userSettings.userId, userId));
  return getSettings(userId, orgId);
}

export async function getStatuses(orgId: string): Promise<Record<string, CveStatusValue>> {
  const rows = await getDb().select().from(cveStatus).where(eq(cveStatus.orgId, orgId));
  return Object.fromEntries(rows.map((r) => [r.cveId, r.status as CveStatusValue]));
}

export async function setStatus(orgId: string, cveId: string, status: CveStatusValue): Promise<void> {
  const db = getDb();
  if (status === "a_traiter") {
    await db.delete(cveStatus).where(and(eq(cveStatus.orgId, orgId), eq(cveStatus.cveId, cveId)));
    return;
  }
  await db
    .insert(cveStatus)
    .values({ orgId, cveId, status })
    .onConflictDoUpdate({ target: [cveStatus.orgId, cveStatus.cveId], set: { status, updatedAt: new Date() } });
}

/** Méthodes de connexion du compte : « credential » (mot de passe) et/ou « google ». */
export async function getProviders(userId: string): Promise<string[]> {
  const rows = await getDb().select({ p: account.providerId }).from(account).where(eq(account.userId, userId));
  return [...new Set(rows.map((r) => r.p))];
}
