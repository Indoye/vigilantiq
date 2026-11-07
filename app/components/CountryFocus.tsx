"use client";

import { geoCircle, geoPath, geoProjection } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useEffect, useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { relTime } from "@/lib/format";
import { BY_CC, BY_NUM, COUNTRIES, countryName, flag } from "@/lib/geo/zones";
import type { FocusData, Share } from "@/lib/threatfocus";
import type { Layer, Period } from "@/lib/threatmap";

const S = 420;
const R = S / 2 - 10;
const PERIOD_LABEL: Record<Period, string> = { "1d": "24 h", "7d": "7 jours", "28d": "28 jours" };
const LAYER_LABEL: Record<Layer, string> = { L7: "Applicative", L3: "DDoS réseau" };
const PRODUCT_FR: Record<string, string> = {
  DDOS: "Protection DDoS",
  WAF: "Pare-feu applicatif (WAF)",
  BOT_MANAGEMENT: "Gestion des bots",
  ACCESS_RULES: "Règles d’accès",
  IP_REPUTATION: "Réputation des adresses IP",
  API_SHIELD: "Protection des API",
  DATA_LOSS_PREVENTION: "Prévention des fuites",
};
const INDUSTRY_FR: Record<string, string> = {
  "Information Technology and Services": "Informatique et services",
  "Computer Software": "Logiciels",
  Internet: "Internet",
  Telecommunications: "Télécommunications",
  "Banking & Financial Services": "Banque et finance",
  "Financial Services": "Services financiers",
  Banking: "Banque",
  "Government Administration": "Administration publique",
  Government: "Administration publique",
  "Media & Publishing": "Médias et édition",
  "Online Media": "Médias en ligne",
  Education: "Éducation",
  "Education Management": "Éducation",
  "Higher Education": "Enseignement supérieur",
  Gambling: "Jeux d’argent",
  "Gambling & Casinos": "Jeux d’argent",
  Retail: "Commerce",
  "Consumer Services": "Services aux particuliers",
  "Hospital & Health Care": "Santé",
  Healthcare: "Santé",
  "Travel & Tourism": "Tourisme",
  Cryptocurrency: "Cryptomonnaies",
  "Non-Profit Organization Management": "Associations",
  "Marketing & Advertising": "Marketing et publicité",
  Energy: "Énergie",
  "Oil & Energy": "Pétrole et énergie",
};
const CAUSE_FR: Record<string, string> = {
  POWER_OUTAGE: "Coupure d’électricité",
  GOVERNMENT_DIRECTED: "Décision des autorités",
  CABLE_CUT: "Câble sectionné",
  TECHNICAL_PROBLEM: "Incident technique",
  MAINTENANCE: "Maintenance",
  WEATHER: "Intempéries",
  MILITARY_ACTION: "Action militaire",
  CYBERATTACK: "Cyberattaque",
  UNKNOWN: "Cause inconnue",
};
const RINGS_KM = [500, 2000, 5000, 10000];
const pct = (v: number) => `${v < 0.1 ? v.toFixed(2) : v.toFixed(1)} %`.replace(".", ",");
const fmt = (n: number) => n.toLocaleString("fr-FR");
const label = (s: string) => s.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase());

/**
 * Projection azimutale « vue depuis le pays » : distances réelles près du centre dilatées (échelle logarithmique),
 * pour que le pays et ses voisins restent lisibles tout en gardant le monde entier dans le disque.
 */
function fisheye() {
  const K = 7;
  const norm = Math.log1p(Math.PI * K);
  const raw = (lambda: number, phi: number): [number, number] => {
    const cosc = Math.max(-1, Math.min(1, Math.cos(phi) * Math.cos(lambda)));
    const c = Math.acos(cosc);
    if (c < 1e-9) return [0, 0];
    const r = (Math.log1p(c * K) / norm) * Math.PI;
    const k = r / Math.sin(c);
    return [k * Math.cos(phi) * Math.sin(lambda), k * Math.sin(phi)];
  };
  return geoProjection(raw);
}

/** Mini-carte de l'écosystème des attaques d'un pays (Sénégal par défaut). */
export default function CountryFocus({ cc = "SN", operator = false }: { cc?: string; operator?: boolean }) {
  const [period, setPeriod] = useState<Period>("7d");
  const [data, setData] = useState<FocusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let alive = true;
    setLoading(true);
    fetch(`/api/threatmap/pays?pays=${cc}&periode=${period}`, { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => alive && (setData(j), setNow(Date.now())))
      .catch(() => alive && setData(null))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [cc, period]);

  const home = BY_CC.get(cc);
  const geo = useMemo(() => {
    const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
    const fc = feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>;
    const center: [number, number] = [home?.lng ?? -14.5, home?.lat ?? 14.5];
    const projection = fisheye()
      .rotate([-center[0], -center[1]])
      .clipAngle(178)
      .fitExtent(
        [
          [S / 2 - R, S / 2 - R],
          [S / 2 + R, S / 2 + R],
        ],
        { type: "Sphere" },
      );
    const path = geoPath(projection);
    const shapes = fc.features
      .filter((f) => f.id !== "010")
      .map((f: Feature<Geometry, { name: string }>) => {
        const c = BY_NUM.get(String(f.id ?? "").padStart(3, "0"));
        return { key: String(f.id ?? f.properties.name), cc: c?.cca2 ?? null, name: c?.name ?? f.properties.name, d: path(f) ?? "" };
      });
    const pts = new Map<string, [number, number]>();
    for (const c of COUNTRIES) {
      const p = projection([c.lng, c.lat]);
      if (p) pts.set(c.cca2, [p[0], p[1]]);
    }
    const rings = RINGS_KM.map((km) => ({ km, d: path(geoCircle().center(center).radius(km / 111.2)()) ?? "" }));
    const c = projection(center) ?? [S / 2, S / 2];
    return { shapes, pts, rings, outline: path({ type: "Sphere" }) ?? "", cx: c[0], cy: c[1] };
  }, [home]);

  // Par pays : la plus forte des deux couches
  const merge = (list: { cc: string; value: number; layer: Layer }[]) => {
    const m = new Map<string, { cc: string; value: number; layers: Layer[] }>();
    for (const x of list) {
      const p = m.get(x.cc);
      if (!p) m.set(x.cc, { cc: x.cc, value: x.value, layers: [x.layer] });
      else {
        p.value = Math.max(p.value, x.value);
        if (!p.layers.includes(x.layer)) p.layers.push(x.layer);
      }
    }
    return [...m.values()].sort((a, b) => b.value - a.value);
  };
  const incoming = useMemo(() => merge(data?.radar.incoming ?? []), [data]);
  const outgoing = useMemo(() => merge(data?.radar.outgoing ?? []), [data]);
  const maxIn = incoming[0]?.value ?? 1;

  const arcs = useMemo(() => {
    const mk = (list: typeof incoming, dir: "in" | "out") =>
      list.slice(0, dir === "in" ? 14 : 6).flatMap((f, i) => {
        const p = geo.pts.get(f.cc);
        if (!p) return [];
        const [x0, y0] = dir === "in" ? p : [geo.cx, geo.cy];
        const [x1, y1] = dir === "in" ? [geo.cx, geo.cy] : p;
        const mx = (x0 + x1) / 2;
        const my = (y0 + y1) / 2;
        const dx = x1 - x0;
        const dy = y1 - y0;
        const bend = 0.18;
        const d = `M${x0.toFixed(1)},${y0.toFixed(1)} Q${(mx - dy * bend).toFixed(1)},${(my + dx * bend).toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
        return [{ key: `${dir}-${f.cc}`, d, f, dir, x: p[0], y: p[1], delay: (i * 0.37) % 2.4, w: Math.sqrt(f.value / maxIn) }];
      });
    return [...mk(incoming, "in"), ...mk(outgoing, "out")];
  }, [incoming, outgoing, geo, maxIn]);

  // Étiquettes des principales origines, sans chevauchement (les plus fortes d'abord)
  const labels = useMemo(() => {
    const out: { cc: string; x: number; y: number }[] = [];
    for (const f of incoming.slice(0, 8)) {
      const p = geo.pts.get(f.cc);
      if (!p || out.length >= 4) continue;
      if (out.some((o) => Math.abs(o.x - p[0]) < 70 && Math.abs(o.y - p[1]) < 16)) continue;
      out.push({ cc: f.cc, x: p[0], y: p[1] });
    }
    return out;
  }, [incoming, geo]);

  const r = data?.radar;
  const name = home?.name ?? cc;
  // Article : « le Sénégal », « du Sénégal » (les autres pays gardent leur nom seul)
  const le = cc === "SN" ? "le Sénégal" : name;
  const du = cc === "SN" ? "du Sénégal" : `de ${name}`;

  return (
    <section className="card tm-panel cf" aria-labelledby="cf-title">
      <div className="cf-head">
        <div>
          <h2 id="cf-title">
            <span aria-hidden="true">{flag(cc)}</span> {name} : écosystème des attaques
          </h2>
          <p className="hint">Vue centrée sur le pays : plus un pays est loin du centre, plus il est éloigné géographiquement.</p>
        </div>
        <div className="segmented" role="group" aria-label="Période">
          {(Object.keys(PERIOD_LABEL) as Period[]).map((p) => (
            <button key={p} type="button" aria-pressed={period === p} className={period === p ? "is-on" : ""} onClick={() => setPeriod(p)}>
              {PERIOD_LABEL[p]}
            </button>
          ))}
        </div>
      </div>

      <div className="cf-body">
        <figure className="tm-map cf-map" aria-label={`Attaques visant ${name}`}>
          <svg viewBox={`0 0 ${S} ${S}`} role="img" aria-labelledby="cf-cap">
            <defs>
              <radialGradient id="cf-glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#0a84ff" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#0a84ff" stopOpacity="0" />
              </radialGradient>
            </defs>
            <path d={geo.outline} className="cf-sphere" />
            {geo.rings.map((g) => (
              <path key={g.km} d={g.d} className="cf-ring" />
            ))}
            <g className="tm-land">
              {geo.shapes.map((s) => (
                <path key={s.key} d={s.d} className={`tm-country cf-country${s.cc === cc ? " is-home" : ""}`}>
                  <title>{s.name}</title>
                </path>
              ))}
            </g>
            <g>
              {arcs.map((a) => (
                <g key={a.key}>
                  <path d={a.d} className={`cf-trail cf-${a.dir}`} strokeWidth={0.6 + 2.2 * a.w}>
                    <title>
                      {a.dir === "in"
                        ? `${countryName(a.f.cc)} → ${name} · ${a.f.layers.map((l) => LAYER_LABEL[l]).join(", ")} · ${pct(a.f.value)}`
                        : `${name} → ${countryName(a.f.cc)} · ${pct(a.f.value)}`}
                    </title>
                  </path>
                  <path d={a.d} pathLength={1} className={`cf-comet cf-${a.dir}`} strokeWidth={1.4 + 2.6 * a.w} style={{ animationDelay: `${a.delay.toFixed(2)}s` }} />
                  <circle cx={a.x} cy={a.y} r={1.8 + 3.2 * a.w} className={`cf-dot cf-${a.dir}`} />
                </g>
              ))}
            </g>
            <circle cx={geo.cx} cy={geo.cy} r={22} className="cf-pulse" />
            <circle cx={geo.cx} cy={geo.cy} r={4} className="cf-home" />
            {labels.map((l) => (
              <text key={l.cc} x={l.x} y={l.y - 7} className="cf-label" textAnchor="middle">
                {flag(l.cc)} {countryName(l.cc)}
              </text>
            ))}
          </svg>
          <figcaption id="cf-cap" className="sr-only">
            Attaques visant {le} par pays d’origine{outgoing.length ? `, et attaques parties ${du}` : ""}.
          </figcaption>
        </figure>

        <div className="cf-side">
          <p className="tm-legend cf-legend">
            <span>
              <i className="cf-key cf-in" /> Attaques visant {le}
            </span>
            {outgoing.length > 0 && (
              <span>
                <i className="cf-key cf-out" /> Attaques parties {du}
              </span>
            )}
            <span className="hint">Cercles : 500, 2 000, 5 000 et 10 000 km</span>
          </p>
          <div className="cf-kpis">
            <Tile k="Rançongiciels" v={data ? fmt(data.ransomware.last12m) : "–"} n={data ? `victimes en 12 mois · ${fmt(data.ransomware.total)} au total` : "victimes revendiquées"} />
            <Tile k="Coupures Internet" v={r ? fmt(r.outages.length) : "–"} n="28 derniers jours" />
            <Tile k="Serveurs C2" v={data ? fmt(data.c2.count) : "–"} n={data ? `hébergés au pays · ${fmt(data.c2.online)} actifs` : "botnets"} />
            <Tile k={`URL malveillantes .${data?.tld ?? "sn"}`} v={data ? fmt(data.phishing.count) : "–"} n="hameçonnage, logiciels malveillants" />
          </div>

          {r && !r.configured ? (
            <p className="callout">{operator ? "Les origines des attaques nécessitent le jeton Cloudflare Radar (CLOUDFLARE_API_TOKEN)." : "Les origines des attaques ne sont pas encore disponibles."}</p>
          ) : (
            <div>
              <h3>D’où viennent les attaques</h3>
              {loading && !data ? (
                <p className="hint">Chargement…</p>
              ) : incoming.length === 0 ? (
                <p className="hint">Aucune origine significative sur la période.</p>
              ) : (
                <ol className="tm-list tm-list-compact">
                  {incoming.slice(0, 7).map((f) => (
                    <li key={f.cc}>
                      <span className="tm-cc">
                        {flag(f.cc)} {countryName(f.cc)}
                      </span>
                      {f.layers.map((l) => (
                        <span key={l} className={`tm-badge tm-b-${l}`}>
                          {l}
                        </span>
                      ))}
                      <span className="tm-bar">
                        <span className={`tm-fill-${f.layers[0]}`} style={{ width: `${Math.max(4, (f.value / maxIn) * 100)}%` }} />
                      </span>
                      <span className="tm-val">{pct(f.value)}</span>
                    </li>
                  ))}
                </ol>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="tm-two cf-more">
        {r && r.products.length > 0 && <Bars title="Protections déclenchées" rows={r.products} fmtKey={(k) => PRODUCT_FR[k] ?? label(k)} />}
        {r && r.industries.length > 0 && <Bars title="Secteurs les plus visés" rows={r.industries} fmtKey={(k) => INDUSTRY_FR[k] ?? k} />}
        {data && data.ransomware.victims.length > 0 && (
          <div>
            <h3>Dernières victimes de rançongiciels</h3>
            <ul className="tm-list tm-list-compact">
              {data.ransomware.victims.slice(0, 6).map((v, i) => (
                <li key={`${v.victim}-${i}`}>
                  <span className="cf-victim">{v.victim}</span>
                  <span className="tm-mw">{v.group}</span>
                  <span className="tm-val">{v.discovered ? relTime(v.discovered, now) : ""}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {r && r.outages.length > 0 && (
          <div>
            <h3>Coupures Internet</h3>
            <ul className="tm-list tm-list-compact">
              {r.outages.map((o, i) => (
                <li key={`${o.start}-${i}`}>
                  <span className="cf-victim">{CAUSE_FR[o.cause] ?? (o.cause ? label(o.cause) : "Coupure")}</span>
                  <span className="tm-mw">{o.networks.join(", ") || (o.type === "NATIONWIDE" ? "Tout le pays" : o.type ? label(o.type) : "")}</span>
                  <span className="tm-val">{relTime(o.start, now)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {data && data.c2.malware.length > 0 && <Bars title="Botnets hébergés" rows={data.c2.malware} fmtKey={(k) => k} count />}
        {data && data.breaches.count > 0 && (
          <div>
            <h3>Fuites publiques de services .{data.tld}</h3>
            <ul className="tm-list tm-list-compact">
              {data.breaches.items.map((b) => (
                <li key={b.title}>
                  <span className="cf-victim">{b.title}</span>
                  <span className="tm-mw">{b.domain}</span>
                  <span className="tm-val">{fmt(b.pwnCount)} comptes</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {data && data.phishing.hosts.length > 0 && (
          <div>
            <h3>Domaines .{data.tld} servant des URL malveillantes</h3>
            <ul className="tm-list tm-list-compact">
              {data.phishing.hosts.map((h) => (
                <li key={h}>
                  <code className="cf-victim">{h}</code>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {data && (
        <p className="hint">
          Sources : {data.sources.filter((s) => s.ok).map((s) => s.name).join(", ")}
          {r?.end ? ` · Cloudflare Radar mis à jour ${relTime(r.end, now)}` : ""}. Les parts Radar sont des pourcentages du trafic d’attaque
          bloqué par Cloudflare, pas des nombres d’attaques.
        </p>
      )}
    </section>
  );
}

function Tile({ k, v, n }: { k: string; v: string; n: string }) {
  return (
    <div className="tile">
      <span className="tile-k">{k}</span>
      <span className="tile-v">{v}</span>
      <span className="tile-n">{n}</span>
    </div>
  );
}

function Bars({ title, rows, fmtKey, count = false }: { title: string; rows: Share[]; fmtKey: (k: string) => string; count?: boolean }) {
  const max = rows[0]?.value ?? 1;
  return (
    <div>
      <h3>{title}</h3>
      <ol className="tm-list tm-list-compact">
        {rows.slice(0, 6).map((x) => (
          <li key={x.key}>
            <span className="tm-cc">{fmtKey(x.key)}</span>
            <span className="tm-bar">
              <span className="tm-fill-port" style={{ width: `${Math.max(4, (x.value / max) * 100)}%` }} />
            </span>
            <span className="tm-val">{count ? fmt(x.value) : pct(x.value)}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
