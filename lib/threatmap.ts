/**
 * Données de la ThreatMap.
 *
 * - Flux d'attaques pays → pays : Cloudflare Radar (attaques applicatives L7 et DDoS réseau L3 observées
 *   et bloquées par Cloudflare), si CLOUDFLARE_API_TOKEN est défini (jeton gratuit « Account > Radar > Read »).
 * - Sans clé : serveurs de commande de botnets actifs (abuse.ch Feodo Tracker) et ports les plus attaqués
 *   (SANS ISC / DShield, capteurs d'attaques sur Internet).
 *
 * Les valeurs Radar sont des parts (%) du trafic d'attaque mitigé sur la période, pas des nombres d'attaques.
 */
const UA = "vigilantiq/0.2 (+https://vercel.com)";
const RADAR = "https://api.cloudflare.com/client/v4/radar";

export type Layer = "L7" | "L3";
export type Period = "1d" | "7d" | "28d";
export const PERIODS: Period[] = ["1d", "7d", "28d"];

export interface Flow {
  from: string;
  to: string;
  /** Part du trafic d'attaque mitigé (%) */
  value: number;
  layer: Layer;
}

export interface C2Country {
  cc: string;
  count: number;
  online: number;
  malware: { name: string; count: number }[];
}

export interface PortStat {
  port: number;
  records: number;
  targets: number;
  sources: number;
}

export interface ThreatMapData {
  generatedAt: string;
  period: Period;
  country: string | null;
  radar: { configured: boolean; start: string | null; end: string | null };
  flows: Flow[];
  c2: C2Country[];
  c2Total: number;
  ports: PortStat[];
  portsDate: string | null;
  errors: string[];
}

const CC_RE = /^[A-Z]{2}$/;

// ---------- Cloudflare Radar ----------

async function radarGet(path: string, params: Record<string, string>, token: string): Promise<unknown> {
  const url = new URL(`${RADAR}${path}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  url.searchParams.set("format", "json");
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
    signal: AbortSignal.timeout(15000),
    cache: "no-store",
  });
  const body = (await res.json().catch(() => null)) as { success?: boolean; errors?: { message?: string }[]; result?: unknown } | null;
  if (!res.ok || !body?.success) {
    const msg = body?.errors?.map((e) => e.message).filter(Boolean).join(" ; ") || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return body.result;
}

/** Extrait les paires origine → cible d'une réponse « top/attacks » (champs *CountryAlpha2 ou *LocationAlpha2). */
export function parseAttackPairs(result: unknown, layer: Layer): Flow[] {
  const r = result as Record<string, unknown> | null;
  const list = (r && (r.top_0 ?? Object.values(r).find(Array.isArray))) as Record<string, unknown>[] | undefined;
  if (!Array.isArray(list)) return [];
  const out: Flow[] = [];
  for (const it of list) {
    const from = String(it.originCountryAlpha2 ?? it.originLocationAlpha2 ?? it.originAlpha2 ?? "").toUpperCase();
    const to = String(it.targetCountryAlpha2 ?? it.targetLocationAlpha2 ?? it.targetAlpha2 ?? "").toUpperCase();
    const value = Number(it.value);
    if (CC_RE.test(from) && CC_RE.test(to) && Number.isFinite(value) && value > 0) out.push({ from, to, value, layer });
  }
  return out;
}

function radarRange(result: unknown): { start: string | null; end: string | null } {
  const meta = (result as { meta?: { dateRange?: { startTime?: string; endTime?: string }[] | { startTime?: string; endTime?: string } } } | null)?.meta;
  const dr = Array.isArray(meta?.dateRange) ? meta?.dateRange[0] : meta?.dateRange;
  return { start: dr?.startTime ?? null, end: dr?.endTime ?? null };
}

/** Fusionne les doublons (même paire, même couche) en gardant la plus grande valeur. */
export function mergeFlows(flows: Flow[]): Flow[] {
  const m = new Map<string, Flow>();
  for (const f of flows) {
    const k = `${f.layer}:${f.from}>${f.to}`;
    const prev = m.get(k);
    if (!prev || f.value > prev.value) m.set(k, f);
  }
  return [...m.values()].sort((a, b) => b.value - a.value);
}

async function radarFlows(token: string, period: Period, country: string | null, errors: string[]) {
  const base = { dateRange: period };
  const calls: { layer: Layer; path: string; params: Record<string, string> }[] = [];
  for (const layer of ["L7", "L3"] as Layer[]) {
    const path = `/attacks/${layer === "L7" ? "layer7" : "layer3"}/top/attacks`;
    // Deux tirages (limite par pays d'origine, puis par pays cible) pour couvrir davantage de pays.
    calls.push({ layer, path, params: { ...base, limit: "100", limitDirection: "ORIGIN", limitPerLocation: "6" } });
    calls.push({ layer, path, params: { ...base, limit: "100", limitDirection: "TARGET", limitPerLocation: "6" } });
    if (country) calls.push({ layer, path, params: { ...base, limit: "50", location: country } });
  }
  const results = await Promise.allSettled(calls.map((c) => radarGet(c.path, c.params, token)));
  const flows: Flow[] = [];
  let range = { start: null as string | null, end: null as string | null };
  const failed = new Set<string>();
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      flows.push(...parseAttackPairs(r.value, calls[i].layer));
      if (!range.start) range = radarRange(r.value);
    } else failed.add(`${calls[i].layer} : ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`);
  });
  if (failed.size) errors.push(`Cloudflare Radar (${[...failed].slice(0, 2).join(" ; ")})`);
  return { flows: mergeFlows(flows), range };
}

// ---------- abuse.ch Feodo Tracker (sans clé) ----------

export function parseFeodo(json: unknown): { c2: C2Country[]; total: number } {
  const list = Array.isArray(json) ? (json as Record<string, unknown>[]) : [];
  const by = new Map<string, { count: number; online: number; malware: Map<string, number> }>();
  let total = 0;
  for (const it of list) {
    const cc = String(it.country ?? "").toUpperCase();
    if (!CC_RE.test(cc)) continue;
    total++;
    const e = by.get(cc) ?? { count: 0, online: 0, malware: new Map() };
    e.count++;
    if (String(it.status ?? "").toLowerCase() === "online") e.online++;
    const mw = String(it.malware ?? "Inconnu") || "Inconnu";
    e.malware.set(mw, (e.malware.get(mw) ?? 0) + 1);
    by.set(cc, e);
  }
  const c2 = [...by.entries()]
    .map(([cc, e]) => ({ cc, count: e.count, online: e.online, malware: [...e.malware.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count) }))
    .sort((a, b) => b.count - a.count);
  return { c2, total };
}

async function feodo() {
  const res = await fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.json", {
    headers: { "User-Agent": UA },
    signal: AbortSignal.timeout(15000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseFeodo(await res.json());
}

// ---------- SANS ISC / DShield (sans clé) ----------

export function parseTopPorts(json: unknown): { ports: PortStat[]; date: string | null } {
  const o = json as Record<string, unknown> | unknown[] | null;
  const values = Array.isArray(o) ? o : o ? Object.values(o) : [];
  const ports: PortStat[] = [];
  for (const v of values) {
    if (!v || typeof v !== "object") continue;
    const r = v as Record<string, unknown>;
    const port = Number(r.targetport ?? r.port);
    if (!Number.isInteger(port)) continue;
    ports.push({ port, records: Number(r.records) || 0, targets: Number(r.targets) || 0, sources: Number(r.sources) || 0 });
  }
  const date = !Array.isArray(o) && o && typeof o.date === "string" ? o.date : null;
  return { ports: ports.sort((a, b) => b.records - a.records).slice(0, 10), date };
}

async function topPorts() {
  const res = await fetch("https://isc.sans.edu/api/topports/records/10?json", {
    headers: { "User-Agent": UA, Accept: "application/json" },
    signal: AbortSignal.timeout(15000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseTopPorts(await res.json());
}

// ---------- Assemblage ----------

export async function buildThreatMap(period: Period, country: string | null): Promise<ThreatMapData> {
  const errors: string[] = [];
  const token = process.env.CLOUDFLARE_API_TOKEN?.trim() || null;
  const [radarR, feodoR, portsR] = await Promise.allSettled([
    token ? radarFlows(token, period, country, errors) : Promise.resolve(null),
    feodo(),
    topPorts(),
  ]);
  const radar = radarR.status === "fulfilled" ? radarR.value : null;
  if (radarR.status === "rejected") errors.push(`Cloudflare Radar : ${radarR.reason instanceof Error ? radarR.reason.message : radarR.reason}`);
  const fd = feodoR.status === "fulfilled" ? feodoR.value : null;
  if (feodoR.status === "rejected") errors.push(`abuse.ch Feodo Tracker : ${feodoR.reason instanceof Error ? feodoR.reason.message : feodoR.reason}`);
  const tp = portsR.status === "fulfilled" ? portsR.value : null;
  if (portsR.status === "rejected") errors.push(`SANS ISC : ${portsR.reason instanceof Error ? portsR.reason.message : portsR.reason}`);

  return {
    generatedAt: new Date().toISOString(),
    period,
    country,
    radar: { configured: Boolean(token), start: radar?.range.start ?? null, end: radar?.range.end ?? null },
    flows: radar?.flows ?? [],
    c2: fd?.c2 ?? [],
    c2Total: fd?.total ?? 0,
    ports: tp?.ports ?? [],
    portsDate: tp?.date ?? null,
    errors,
  };
}
