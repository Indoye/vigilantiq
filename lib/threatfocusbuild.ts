/** Assemblage de l'écosystème des attaques d'un pays (voir threatfocus.ts). */
import { fetchCountryVictims, hostOf } from "./cti/sources.ts";
import { getBreaches, getIocs } from "./cti/store.ts";
import { parseOutages, parseSummary, splitPairs, type FocusData, type Share } from "./threatfocus.ts";
import { feodo, parseAttackPairs, radarGet, type Period } from "./threatmap.ts";

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

const top = (m: Map<string, number>, n: number): Share[] =>
  [...m.entries()]
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, n);

export async function buildFocus(cc: string, period: Period): Promise<FocusData> {
  const tld = cc.toLowerCase() === "gb" ? "uk" : cc.toLowerCase();
  const token = process.env.CLOUDFLARE_API_TOKEN?.trim() || null;
  const sources: FocusData["sources"] = [];
  const d: FocusData = {
    cc,
    tld,
    period,
    generatedAt: new Date().toISOString(),
    radar: { configured: Boolean(token), start: null, end: null, incoming: [], outgoing: [], products: [], industries: [], outages: [] },
    ransomware: { total: 0, last12m: 0, victims: [], groups: [] },
    c2: { count: 0, online: 0, malware: [] },
    phishing: { count: 0, hosts: [], threats: [] },
    breaches: { count: 0, items: [] },
    sources,
  };

  const radarTask = async () => {
    if (!token) return;
    const base = { dateRange: period, location: cc };
    const [l7, l3, products, industries, outages] = await Promise.allSettled([
      radarGet("/attacks/layer7/top/attacks", { ...base, limit: "50" }, token),
      radarGet("/attacks/layer3/top/attacks", { ...base, limit: "50" }, token),
      radarGet("/attacks/layer7/summary/MITIGATION_PRODUCT", base, token),
      radarGet("/attacks/layer7/summary/INDUSTRY", { ...base, limitPerGroup: "6" }, token),
      radarGet("/annotations/outages", { location: cc, dateRange: "28d", limit: "20" }, token),
    ]);
    const pairs = [
      ...(l7.status === "fulfilled" ? parseAttackPairs(l7.value, "L7") : []),
      ...(l3.status === "fulfilled" ? parseAttackPairs(l3.value, "L3") : []),
    ];
    Object.assign(d.radar, splitPairs(pairs, cc));
    for (const r of [l7, l3]) {
      if (r.status === "fulfilled" && !d.radar.start) {
        const dr = (r.value as { meta?: { dateRange?: { startTime?: string; endTime?: string }[] } }).meta?.dateRange?.[0];
        d.radar.start = dr?.startTime ?? null;
        d.radar.end = dr?.endTime ?? null;
      }
    }
    if (products.status === "fulfilled") d.radar.products = parseSummary(products.value);
    if (industries.status === "fulfilled") d.radar.industries = parseSummary(industries.value).slice(0, 6);
    if (outages.status === "fulfilled") d.radar.outages = parseOutages(outages.value, cc);
    const failed = [l7, l3, products, industries, outages].filter((r) => r.status === "rejected").length;
    sources.push({ name: "Cloudflare Radar", ok: failed < 5, detail: failed ? `${5 - failed}/5 indicateurs` : undefined });
  };

  const ransomTask = async () => {
    const all = await fetchCountryVictims(cc);
    const yearAgo = Date.now() - 365 * 86_400_000;
    const sorted = all.sort((a, b) => (b.discovered ?? "").localeCompare(a.discovered ?? ""));
    const groups = new Map<string, number>();
    for (const v of sorted) groups.set(v.group, (groups.get(v.group) ?? 0) + 1);
    d.ransomware = {
      total: all.length,
      last12m: all.filter((v) => v.discovered && Date.parse(v.discovered) >= yearAgo).length,
      victims: sorted.slice(0, 8).map((v) => ({ victim: v.victim, group: v.group, sector: v.sector, discovered: v.discovered, domain: v.domain })),
      groups: top(groups, 5),
    };
  };

  const c2Task = async () => {
    const f = await feodo();
    const c = f.c2.find((x) => x.cc === cc);
    if (c) d.c2 = { count: c.count, online: c.online, malware: c.malware.slice(0, 5).map((m) => ({ key: m.name, value: m.count })) };
  };

  const phishTask = async () => {
    const feed = await getIocs();
    const suffix = `.${tld}`;
    const hosts = new Map<string, number>();
    const threats = new Map<string, number>();
    let count = 0;
    for (const i of feed.items) {
      if (i.type !== "url" && i.type !== "domain") continue;
      const h = i.type === "url" ? hostOf(i.value) : i.value.toLowerCase();
      if (!h || !h.endsWith(suffix)) continue;
      count++;
      hosts.set(h, (hosts.get(h) ?? 0) + 1);
      const t = i.threat || "Hameçonnage";
      threats.set(t, (threats.get(t) ?? 0) + 1);
    }
    d.phishing = { count, hosts: top(hosts, 6).map((x) => x.key), threats: top(threats, 4) };
  };

  const breachTask = async () => {
    const suffix = `.${tld}`;
    const list = (await getBreaches()).filter((b) => b.domain && b.domain.endsWith(suffix));
    list.sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""));
    d.breaches = { count: list.length, items: list.slice(0, 5).map((b) => ({ title: b.title, domain: b.domain, date: b.breachDate, pwnCount: b.pwnCount })) };
  };

  const named: [string, () => Promise<void>][] = [
    ["ransomware.live", ransomTask],
    ["abuse.ch Feodo Tracker", c2Task],
    ["Flux d’URL malveillantes", phishTask],
    ["Have I Been Pwned", breachTask],
  ];
  const res = await Promise.allSettled([radarTask(), ...named.map(([, f]) => f())]);
  if (res[0].status === "rejected") sources.push({ name: "Cloudflare Radar", ok: false, detail: msg(res[0].reason) });
  named.forEach(([name], i) => {
    const r = res[i + 1];
    sources.push(r.status === "fulfilled" ? { name, ok: true } : { name, ok: false, detail: msg(r.reason) });
  });
  return d;
}
