/**
 * Connecteurs d'une organisation : Jira, ServiceNow, XSOAR, SIEM (tickets / événements) et MISP, TAXII (fuites).
 * Configuration chiffrée en base (AES-256-GCM) ; les secrets ne sont jamais renvoyés au navigateur.
 */
import { and, eq } from "drizzle-orm";
import { getDb } from "@/db";
import { orgConnector } from "@/db/schema";
import { serverSecret } from "./cti/leakstore.ts";
import { CONNECTOR_IDS, connectorInfo, FIELDS, type ConnectorConfig, type ConnectorId, type FieldSpec } from "./connectors.ts";
import { seal, unseal } from "./hunt/core.ts";
import { publicHttpsUrl, UnsafeUrlError } from "./netguard.ts";
import { can, TenantError, type Tenant } from "./tenant.ts";

export type OrgConnectorType = ConnectorId | "misp" | "taxii";
export const ORG_CONNECTOR_TYPES: OrgConnectorType[] = [...CONNECTOR_IDS, "misp", "taxii"];

export const LEAK_FIELDS: Record<"misp" | "taxii", FieldSpec[]> = {
  misp: [
    { key: "MISP_URL", label: "Adresse MISP", required: true, placeholder: "https://misp.entreprise.sn" },
    { key: "MISP_API_KEY", label: "Clé d’API", required: true, secret: true },
    { key: "MISP_TAGS", label: "Étiquettes à suivre", placeholder: "dark-web,data-leak" },
    { key: "MISP_RELIABILITY", label: "Fiabilité (A à F)", placeholder: "B" },
  ],
  taxii: [
    { key: "TAXII_URL", label: "Racine d’API TAXII 2.1", required: true, placeholder: "https://taxii…/api1/" },
    { key: "TAXII_COLLECTION", label: "Collection", required: true },
    { key: "TAXII_TOKEN", label: "Jeton (Bearer)", secret: true },
    { key: "TAXII_USER", label: "Utilisateur" },
    { key: "TAXII_PASSWORD", label: "Mot de passe", secret: true },
    { key: "TAXII_RELIABILITY", label: "Fiabilité (A à F)", placeholder: "C" },
  ],
};
const AUTO_FIELD: FieldSpec = { key: "AUTO_MIN_PRIORITY", label: "Priorité minimale de l’envoi automatique", placeholder: "urgente" };

export const fieldsOf = (type: OrgConnectorType): FieldSpec[] =>
  type === "misp" || type === "taxii" ? LEAK_FIELDS[type] : [...FIELDS[type], ...(type === "siem" || type === "jira" || type === "servicenow" || type === "xsoar" ? [AUTO_FIELD] : [])];
const urlKeys = (type: OrgConnectorType) => fieldsOf(type).filter((f) => f.key.endsWith("_URL") && f.key !== "XSOAR_INCIDENT_URL").map((f) => f.key);

export interface OrgConnector {
  type: OrgConnectorType;
  cfg: ConnectorConfig;
  enabled: boolean;
  autoSend: boolean;
  lastError: string | null;
  lastRunAt: Date | null;
}

function decrypt(enc: string): ConnectorConfig {
  try {
    return JSON.parse(unseal(serverSecret(), enc)) as ConnectorConfig;
  } catch {
    return {};
  }
}

export async function getOrgConnector(orgId: string, type: OrgConnectorType): Promise<OrgConnector | null> {
  const [r] = await getDb().select().from(orgConnector).where(and(eq(orgConnector.orgId, orgId), eq(orgConnector.type, type)));
  if (!r) return null;
  return { type, cfg: decrypt(r.configEnc), enabled: r.enabled, autoSend: r.autoSend, lastError: r.lastError, lastRunAt: r.lastRunAt };
}

/** Vue sans secrets pour l'interface : valeurs non sensibles, présence des secrets, état. */
export async function listOrgConnectors(orgId: string) {
  const rows = await getDb().select().from(orgConnector).where(eq(orgConnector.orgId, orgId));
  const by = new Map(rows.map((r) => [r.type, r]));
  return ORG_CONNECTOR_TYPES.map((type) => {
    const r = by.get(type);
    const cfg = r ? decrypt(r.configEnc) : {};
    const fields = fieldsOf(type);
    const missing = fields.filter((f) => f.required && !cfg[f.key]).map((f) => f.key);
    return {
      type,
      name: type === "misp" ? "MISP" : type === "taxii" ? "TAXII 2.1" : connectorInfo(type).name,
      kind: type === "misp" || type === "taxii" ? "fuites" : type === "siem" ? "event" : "ticket",
      fields: fields.map((f) => ({ ...f, value: f.secret ? "" : (cfg[f.key] ?? ""), set: Boolean(cfg[f.key]) })),
      configured: Boolean(r) && missing.length === 0,
      enabled: r?.enabled ?? false,
      autoSend: r?.autoSend ?? false,
      lastError: r?.lastError ?? null,
      lastRunAt: r?.lastRunAt?.toISOString() ?? null,
    };
  });
}

/** Enregistre la configuration : un champ secret laissé vide conserve la valeur actuelle. */
export async function saveOrgConnector(t: Tenant, type: string, body: Record<string, unknown>): Promise<void> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  if (!ORG_CONNECTOR_TYPES.includes(type as OrgConnectorType)) throw new TenantError("Connecteur inconnu.");
  const ty = type as OrgConnectorType;
  const prev = (await getOrgConnector(t.orgId, ty))?.cfg ?? {};
  const values = (body.values ?? {}) as Record<string, unknown>;
  const cfg: ConnectorConfig = {};
  for (const f of fieldsOf(ty)) {
    const v = typeof values[f.key] === "string" ? (values[f.key] as string).trim().slice(0, 2000) : "";
    if (v) cfg[f.key] = v;
    else if (f.secret && prev[f.key] && values[f.key] !== null) cfg[f.key] = prev[f.key];
  }
  try {
    for (const k of urlKeys(ty)) if (cfg[k]) cfg[k] = publicHttpsUrl(cfg[k], fieldsOf(ty).find((f) => f.key === k)?.label ?? "Le service");
  } catch (e) {
    throw new TenantError(e instanceof UnsafeUrlError ? e.message : "Adresse invalide.");
  }
  const missing = fieldsOf(ty).filter((f) => f.required && !cfg[f.key]).map((f) => f.label);
  if (missing.length) throw new TenantError(`Champs obligatoires : ${missing.join(", ")}.`);
  const enabled = body.enabled !== false;
  const autoSend = body.autoSend === true && ty !== "misp" && ty !== "taxii";
  await getDb()
    .insert(orgConnector)
    .values({ orgId: t.orgId, type: ty, configEnc: seal(serverSecret(), JSON.stringify(cfg)), enabled, autoSend })
    .onConflictDoUpdate({ target: [orgConnector.orgId, orgConnector.type], set: { configEnc: seal(serverSecret(), JSON.stringify(cfg)), enabled, autoSend, lastError: null, updatedAt: new Date() } });
}

export async function deleteOrgConnector(t: Tenant, type: string): Promise<void> {
  if (!can(t.role, "admin")) throw new TenantError("Réservé aux administrateurs.", 403);
  await getDb().delete(orgConnector).where(and(eq(orgConnector.orgId, t.orgId), eq(orgConnector.type, type)));
}

export async function markConnectorRun(orgId: string, type: OrgConnectorType, error: string | null): Promise<void> {
  await getDb()
    .update(orgConnector)
    .set({ lastRunAt: new Date(), lastError: error?.slice(0, 300) ?? null })
    .where(and(eq(orgConnector.orgId, orgId), eq(orgConnector.type, type)));
}

/** Toutes les organisations ayant un connecteur actif d'un type donné (passes quotidiennes). */
export async function connectorsOfType(type: OrgConnectorType): Promise<(OrgConnector & { orgId: string })[]> {
  const rows = await getDb()
    .select()
    .from(orgConnector)
    .where(and(eq(orgConnector.type, type), eq(orgConnector.enabled, true)));
  return rows.map((r) => ({ orgId: r.orgId, type, cfg: decrypt(r.configEnc), enabled: r.enabled, autoSend: r.autoSend, lastError: r.lastError, lastRunAt: r.lastRunAt }));
}
