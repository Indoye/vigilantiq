/** Correspondance entre la liste de surveillance d'un utilisateur et les données de renseignement → alertes. */
import { brandOf, hostOf, type Breach, type InfostealerStats, type Ioc, type RansomVictim } from "./sources.ts";
import type { Lookalike } from "./typosquat.ts";

export type WatchKind = "domain" | "brand";
export type Severity = "critique" | "haute" | "moyenne" | "info";
export type AlertSource = "ransomware" | "infostealer" | "breach" | "typosquat" | "phishing" | "email";

export interface WatchTarget {
  kind: WatchKind;
  value: string;
}

export interface AlertDraft {
  source: AlertSource;
  externalId: string;
  watchValue: string;
  severity: Severity;
  title: string;
  detail: Record<string, unknown>;
  url: string;
}

const norm = (s: string) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");

/** Le terme apparaît comme mot entier (ou nom de domaine) dans le texte. */
export function containsTerm(text: string, term: string): boolean {
  const t = norm(term).trim();
  if (t.length < 4) return false;
  const esc = t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9])${esc}([^a-z0-9]|$)`).test(norm(text));
}

const sameOrSub = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);

/** Termes recherchés pour une cible : le domaine et sa marque (≥ 4 caractères), ou la marque seule. */
export function termsOf(t: WatchTarget): string[] {
  if (t.kind === "brand") return [t.value];
  const b = brandOf(t.value);
  return b.length >= 4 ? [t.value, b] : [t.value];
}

export function matchRansom(targets: WatchTarget[], victims: RansomVictim[]): AlertDraft[] {
  const out: AlertDraft[] = [];
  for (const v of victims) {
    for (const t of targets) {
      const exact = t.kind === "domain" && v.domain && sameOrSub(v.domain, t.value);
      const fuzzy = !exact && termsOf(t).some((term) => containsTerm(`${v.victim} ${v.domain}`, term));
      if (!exact && !fuzzy) continue;
      out.push({
        source: "ransomware",
        externalId: `rw:${v.id}`,
        watchValue: t.value,
        severity: exact ? "critique" : "haute",
        title: `${v.victim} revendiquée par le groupe ${v.group}${exact ? "" : " (correspondance possible)"}`,
        detail: { victim: v.victim, domain: v.domain, group: v.group, country: v.country, sector: v.sector, discovered: v.discovered, exact },
        url: v.url,
      });
      break;
    }
  }
  return out;
}

export function matchBreaches(targets: WatchTarget[], breaches: Breach[]): AlertDraft[] {
  const out: AlertDraft[] = [];
  for (const b of breaches) {
    for (const t of targets) {
      const exact = t.kind === "domain" && b.domain && sameOrSub(b.domain, t.value);
      const fuzzy = !exact && t.kind === "brand" && containsTerm(`${b.title} ${b.name}`, t.value);
      if (!exact && !fuzzy) continue;
      out.push({
        source: "breach",
        externalId: `hibp:${b.name}`,
        watchValue: t.value,
        severity: exact ? "haute" : "moyenne",
        title: `Fuite de données « ${b.title} » : ${b.pwnCount.toLocaleString("fr-FR")} comptes`,
        detail: { name: b.name, domain: b.domain, breachDate: b.breachDate, addedDate: b.addedDate, pwnCount: b.pwnCount, dataClasses: b.dataClasses, exact },
        url: `https://haveibeenpwned.com/Breach/${encodeURIComponent(b.name)}`,
      });
      break;
    }
  }
  return out;
}

export function matchPhishing(targets: WatchTarget[], iocs: Ioc[]): AlertDraft[] {
  const out: AlertDraft[] = [];
  const seenHosts = new Set<string>();
  for (const i of iocs) {
    if (i.type !== "url" && i.type !== "domain") continue;
    const host = i.type === "url" ? hostOf(i.value) : i.value.toLowerCase();
    if (!host || seenHosts.has(host)) continue;
    for (const t of targets) {
      if (t.kind === "domain" && sameOrSub(host, t.value)) continue; // le site légitime lui-même
      const hit = termsOf(t).some((term) => {
        const n = norm(term).replace(/\s+/g, "");
        return n.length >= 4 && norm(host).includes(n);
      });
      if (!hit) continue;
      seenHosts.add(host);
      out.push({
        source: "phishing",
        externalId: `phish:${host}`,
        watchValue: t.value,
        severity: "haute",
        title: `Site d’hameçonnage imitant ${t.value} : ${host}`,
        detail: { host, url: i.value, source: i.source, threat: i.threat, firstSeen: i.firstSeen },
        url: i.ref,
      });
      break;
    }
  }
  return out;
}

export function draftInfostealer(s: InfostealerStats, now = Date.now()): AlertDraft[] {
  if (s.employees + s.users === 0) return [];
  const recent = s.lastEmployee ? now - Date.parse(s.lastEmployee) < 180 * 86400_000 : false;
  const severity: Severity = s.employees > 0 ? (recent ? "critique" : "haute") : "moyenne";
  return [
    {
      source: "infostealer",
      externalId: `hr:${s.domain}:${s.employees}:${s.users}:${s.lastEmployee ?? ""}`,
      watchValue: s.domain,
      severity,
      title:
        s.employees > 0
          ? `${s.employees} poste${s.employees > 1 ? "s" : ""} d’employé${s.employees > 1 ? "s" : ""} infecté${s.employees > 1 ? "s" : ""} par un infostealer (${s.domain})`
          : `${s.users.toLocaleString("fr-FR")} comptes d’utilisateurs de ${s.domain} volés par des infostealers`,
      detail: { ...s },
      url: `https://www.hudsonrock.com/search?domain=${encodeURIComponent(s.domain)}`,
    },
  ];
}

export function draftLookalikes(domain: string, list: Lookalike[]): AlertDraft[] {
  return list.map((l) => ({
    source: "typosquat" as const,
    externalId: `typo:${l.domain}`,
    watchValue: domain,
    severity: (l.mx ? "haute" : "moyenne") as Severity,
    title: `Domaine ressemblant actif : ${l.domain}${l.mx ? " (peut envoyer des e-mails)" : ""}`,
    detail: { lookalike: l.domain, ips: l.ips, mx: l.mx },
    url: `https://crt.sh/?q=${encodeURIComponent(l.domain)}`,
  }));
}

export function draftEmail(email: string, breaches: string[]): AlertDraft[] {
  return breaches.map((name) => ({
    source: "email" as const,
    externalId: `email:${email.toLowerCase()}:${name}`,
    watchValue: email,
    severity: "moyenne" as Severity,
    title: `Votre adresse ${email} figure dans la fuite « ${name} »`,
    detail: { email, breach: name },
    url: `https://haveibeenpwned.com/Breach/${encodeURIComponent(name)}`,
  }));
}
