/** Export des indicateurs de compromission : CSV, JSON et STIX 2.1 (MISP, OpenCTI, SIEM). */
import { createHash } from "node:crypto";
import type { Ioc } from "./sources.ts";

const csvCell = (v: unknown) => {
  const s = v == null ? "" : String(v);
  // Neutralise les formules (injection CSV dans Excel/LibreOffice)
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n;]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

export function iocsToCsv(items: Ioc[]): string {
  const head = ["type", "valeur", "menace", "malware", "source", "premiere_vue", "confiance", "etiquettes", "reference"];
  const lines = items.map((i) => [i.type, i.value, i.threat, i.malware, i.source, i.firstSeen ?? "", i.confidence ?? "", i.tags.join(" "), i.ref].map(csvCell).join(","));
  return [head.join(","), ...lines].join("\n") + "\n";
}

/** Identifiant STIX déterministe (UUID v5-like dérivé du contenu) pour des exports stables. */
function stixId(kind: string, key: string): string {
  const h = createHash("sha1").update(`vigilantiq:${kind}:${key}`).digest("hex");
  return `${kind}--${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/'/g, "\\'");

export function stixPattern(i: Ioc): string | null {
  switch (i.type) {
    case "ip":
      return `[ipv4-addr:value = '${esc(i.value)}']`;
    case "ip:port": {
      const [ip, port] = i.value.split(":");
      return port ? `[network-traffic:dst_ref.value = '${esc(ip)}' AND network-traffic:dst_port = ${Number(port)}]` : `[ipv4-addr:value = '${esc(ip)}']`;
    }
    case "domain":
      return `[domain-name:value = '${esc(i.value)}']`;
    case "url":
      return `[url:value = '${esc(i.value)}']`;
    case "md5":
      return `[file:hashes.MD5 = '${esc(i.value)}']`;
    case "sha1":
      return `[file:hashes.'SHA-1' = '${esc(i.value)}']`;
    case "sha256":
      return `[file:hashes.'SHA-256' = '${esc(i.value)}']`;
  }
}

export function iocsToStix(items: Ioc[], now = new Date().toISOString()): Record<string, unknown> {
  const identity = {
    type: "identity",
    spec_version: "2.1",
    id: stixId("identity", "vigilantiq"),
    created: "2026-01-01T00:00:00.000Z",
    modified: "2026-01-01T00:00:00.000Z",
    name: "VigilantIQ",
    identity_class: "system",
  };
  const objects: Record<string, unknown>[] = [identity];
  for (const i of items) {
    const pattern = stixPattern(i);
    if (!pattern) continue;
    const created = i.firstSeen ?? now;
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: stixId("indicator", `${i.type}|${i.value}`),
      created_by_ref: identity.id,
      created,
      modified: created,
      name: `${i.threat}${i.malware ? ` – ${i.malware}` : ""} : ${i.value}`.slice(0, 250),
      indicator_types: ["malicious-activity"],
      pattern,
      pattern_type: "stix",
      valid_from: created,
      confidence: i.confidence ?? undefined,
      labels: [i.source, ...(i.malware ? [i.malware] : []), ...i.tags].filter(Boolean).slice(0, 8),
      external_references: i.ref ? [{ source_name: i.source, url: i.ref }] : undefined,
    });
  }
  return { type: "bundle", id: stixId("bundle", `${now}|${items.length}`), objects };
}
