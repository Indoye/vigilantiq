import { XMLParser } from "fast-xml-parser";
import type { FeedKind, Mention, RssItem, RssSnapshot, SourceStatus } from "./types.ts";

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface FeedSource {
  id: string;
  name: string;
  kind: FeedKind;
  url: string;
}

/** Flux suivis par défaut. Ajoutez-en via RSS_EXTRA_FEEDS="Nom|https://…,Nom 2|https://…". */
export const DEFAULT_FEEDS: FeedSource[] = [
  { id: "certfr", name: "CERT-FR", kind: "cert", url: "https://www.cert.ssi.gouv.fr/feed/" },
  { id: "certeu", name: "CERT-EU", kind: "cert", url: "https://cert.europa.eu/publications/security-advisories-rss" },
  { id: "cisa", name: "CISA", kind: "gouv", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { id: "certcc", name: "CERT/CC", kind: "cert", url: "https://www.kb.cert.org/vuls/atomfeed/" },
  { id: "zdi", name: "Zero Day Initiative", kind: "cert", url: "https://www.zerodayinitiative.com/rss/published/" },
  { id: "msrc", name: "Microsoft", kind: "editeur", url: "https://api.msrc.microsoft.com/update-guide/rss" },
  { id: "cisco", name: "Cisco", kind: "editeur", url: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml" },
  { id: "fortinet", name: "Fortinet", kind: "editeur", url: "https://filestore.fortinet.com/fortiguard/rss/ir.xml" },
  { id: "paloalto", name: "Palo Alto Networks", kind: "editeur", url: "https://security.paloaltonetworks.com/rss.xml" },
  { id: "ubuntu", name: "Ubuntu", kind: "editeur", url: "https://ubuntu.com/security/notices/rss.xml" },
  { id: "exploitdb", name: "Exploit-DB", kind: "exploit", url: "https://www.exploit-db.com/rss.xml" },
  { id: "cvefeed", name: "cvefeed.io", kind: "cve", url: "https://cvefeed.io/rssfeed/latest.xml" },
];

export function configuredFeeds(): FeedSource[] {
  const disabled = new Set((process.env.RSS_DISABLE ?? "").split(",").map((s) => s.trim()).filter(Boolean));
  const extra: FeedSource[] = (process.env.RSS_EXTRA_FEEDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s, i) => {
      const [name, url] = s.split("|").map((x) => x.trim());
      return { id: `extra${i}`, name, kind: "cert" as FeedKind, url };
    })
    .filter((f) => f.name && /^https:\/\//.test(f.url));
  return [...DEFAULT_FEEDS.filter((f) => !disabled.has(f.id)), ...extra];
}

// ---------- Analyse XML (RSS 2.0, RSS 1.0/RDF, Atom) ----------

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@",
  textNodeName: "#text",
  processEntities: true,
  htmlEntities: true,
  trimValues: true,
});

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

function text(v: any): string {
  if (v == null) return "";
  if (typeof v === "string" || typeof v === "number") return String(v);
  if (Array.isArray(v)) return text(v[0]);
  if (typeof v === "object") return text(v["#text"] ?? v["__cdata"] ?? "");
  return "";
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", rsquo: "’", lsquo: "‘", eacute: "é", egrave: "è", agrave: "à" };

export function stripHtml(s: string): string {
  return s
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m)
    .replace(/\s+/g, " ")
    .trim();
}

function linkOf(v: any): string {
  if (!v) return "";
  if (typeof v === "string") return v.trim();
  const list = Array.isArray(v) ? v : [v];
  const alt = list.find((l) => typeof l === "object" && (!l["@rel"] || l["@rel"] === "alternate")) ?? list[0];
  return typeof alt === "string" ? alt.trim() : String(alt?.["@href"] ?? alt?.["#text"] ?? "").trim();
}

function dateOf(...vals: any[]): string {
  for (const v of vals) {
    const s = text(v);
    if (!s) continue;
    const t = Date.parse(s);
    if (!Number.isNaN(t)) return new Date(t).toISOString();
  }
  return "";
}

export function extractCves(s: string): string[] {
  return [...new Set((s.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))].slice(0, 60);
}

export function parseFeed(xml: string, src: Pick<FeedSource, "id" | "name" | "kind">): RssItem[] {
  const doc = parser.parse(xml);
  const raw: any[] = [];
  const add = (x: any) => (Array.isArray(x) ? raw.push(...x) : x ? raw.push(x) : null);
  add(doc?.rss?.channel?.item);
  add(doc?.feed?.entry);
  add(doc?.["rdf:RDF"]?.item);

  return raw
    .map((it): RssItem | null => {
      const title = stripHtml(text(it.title));
      const link = linkOf(it.link) || text(it.guid) || text(it.id);
      const body = stripHtml(text(it["content:encoded"]) || text(it.description) || text(it.summary) || text(it.content));
      const published = dateOf(it.pubDate, it.published, it.updated, it["dc:date"], it["a10:updated"]);
      if (!title || !link) return null;
      const cats = (Array.isArray(it.category) ? it.category : it.category ? [it.category] : []).map(text).join(" ");
      return {
        key: `${src.id}:${link}`,
        source: src.name,
        sourceId: src.id,
        kind: src.kind,
        title,
        link,
        published,
        summary: body.slice(0, 360),
        cves: extractCves(`${title} ${body} ${cats} ${link}`),
      };
    })
    .filter((x): x is RssItem => x !== null);
}

// ---------- Récupération ----------

export const RSS_REVALIDATE = Number(process.env.RSS_REVALIDATE_SECONDS || 180);

async function fetchOne(src: FeedSource): Promise<RssItem[]> {
  const res = await fetch(src.url, {
    headers: {
      "User-Agent": "veille-cve/0.2 (+https://vercel.com)",
      Accept: "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
    },
    signal: AbortSignal.timeout(10_000),
    next: { revalidate: RSS_REVALIDATE },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseFeed(await res.text(), src);
}

/** Tous les flux en parallèle ; un flux en panne n'empêche jamais les autres. */
export async function getRssSnapshot(maxAgeDays = 14): Promise<RssSnapshot> {
  const feeds = configuredFeeds();
  const results = await Promise.allSettled(feeds.map(fetchOne));
  const cutoff = Date.now() - maxAgeDays * 86400_000;
  const items: RssItem[] = [];
  const sources: SourceStatus[] = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      sources.push({ name: feeds[i].name, ok: true, detail: `${r.value.length} éléments` });
      for (const it of r.value) {
        if (!it.published || Date.parse(it.published) >= cutoff) items.push(it);
      }
    } else {
      const e = r.reason;
      sources.push({ name: feeds[i].name, ok: false, detail: e?.name === "TimeoutError" ? "délai dépassé" : String(e?.message ?? e) });
    }
  });
  const seen = new Set<string>();
  const unique = items.filter((it) => (seen.has(it.key) ? false : (seen.add(it.key), true)));
  unique.sort((a, b) => (b.published || "").localeCompare(a.published || ""));
  return { fetchedAt: new Date().toISOString(), items: unique.slice(0, 400), sources };
}

/** Index CVE → mentions dans les flux. */
export function mentionIndex(items: RssItem[]): Map<string, Mention[]> {
  const map = new Map<string, Mention[]>();
  for (const it of items) {
    for (const id of it.cves) {
      const list = map.get(id) ?? [];
      if (!list.some((m) => m.link === it.link) && list.length < 12) {
        list.push({ source: it.source, kind: it.kind, title: it.title, link: it.link, published: it.published });
      }
      map.set(id, list);
    }
  }
  return map;
}
