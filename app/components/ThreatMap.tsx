"use client";

import { geoNaturalEarth1, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useCallback, useEffect, useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { relTime } from "@/lib/format";
import { BY_CC, BY_NUM, COUNTRIES, countryName, flag, ZONES, zoneLabel, zoneMembers } from "@/lib/geo/zones";
import type { Flow, Layer, Period, ThreatMapData } from "@/lib/threatmap";
import { Icon } from "./ui";

const W = 960;
const H = 470;
const REFRESH_MS = 5 * 60 * 1000;
const MAX_ARCS = 70;

type Direction = "tout" | "entrantes" | "sortantes";
type LayerSel = "tout" | Layer;

const PERIOD_LABEL: Record<Period, string> = { "1d": "24 h", "7d": "7 jours", "28d": "28 jours" };
const LAYER_LABEL: Record<Layer, string> = { L7: "Applicative", L3: "DDoS réseau" };
const PORT_NAMES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP", 123: "NTP", 135: "RPC", 139: "NetBIOS",
  443: "HTTPS", 445: "SMB", 1433: "MS SQL", 1723: "PPTP", 2222: "SSH", 2323: "Telnet", 3306: "MySQL", 3389: "RDP",
  5060: "SIP", 5432: "PostgreSQL", 5555: "ADB", 5900: "VNC", 6379: "Redis", 8080: "HTTP", 8088: "HTTP", 8443: "HTTPS",
  9200: "Elasticsearch", 27017: "MongoDB", 37215: "Huawei HG532", 52869: "Realtek UPnP",
};

const pct = (v: number) => `${v < 0.1 ? v.toFixed(2) : v.toFixed(1)} %`.replace(".", ",");
const fmt = (n: number) => n.toLocaleString("fr-FR");

/** Pondération pseudo-aléatoire stable (durée et décalage des animations). */
function seeded(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return ((h >>> 0) % 1000) / 1000;
}

export default function ThreatMap() {
  const [period, setPeriod] = useState<Period>("1d");
  const [zone, setZone] = useState("monde");
  const [direction, setDirection] = useState<Direction>("tout");
  const [layer, setLayer] = useState<LayerSel>("tout");
  const [showC2, setShowC2] = useState(true);
  const [data, setData] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const country = zone.startsWith("pays:") ? zone.slice(5) : null;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/threatmap?periode=${period}${country ? `&pays=${country}` : ""}`, { cache: "no-store" });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
      setData(j);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Données indisponibles");
    } finally {
      setLoading(false);
    }
  }, [period, country]);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(id);
  }, []);

  // ---------- Géométrie ----------
  const geo = useMemo(() => {
    const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
    const fc = feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>;
    const features = fc.features.filter((f) => f.id !== "010"); // sans l'Antarctique
    const projection = geoNaturalEarth1().fitExtent(
      [
        [8, 8],
        [W - 8, H - 8],
      ],
      { type: "FeatureCollection", features } as FeatureCollection,
    );
    const path = geoPath(projection);
    const shapes = features.map((f: Feature<Geometry, { name: string }>) => {
      const c = BY_NUM.get(String(f.id ?? "").padStart(3, "0"));
      return { key: String(f.id ?? f.properties.name), cc: c?.cca2 ?? null, name: c?.name ?? f.properties.name, d: path(f) ?? "" };
    });
    const pts = new Map<string, [number, number]>();
    for (const c of COUNTRIES) {
      const p = projection([c.lng, c.lat]);
      if (p) pts.set(c.cca2, [p[0], p[1]]);
    }
    return { shapes, pts, outline: path({ type: "Sphere" }) ?? "" };
  }, []);

  // ---------- Filtrage ----------
  const members = useMemo(() => zoneMembers(zone), [zone]);
  const inZone = useCallback((cc: string) => !members || members.has(cc), [members]);

  const flows = useMemo(() => {
    const all = data?.flows ?? [];
    return all.filter((f) => {
      if (layer !== "tout" && f.layer !== layer) return false;
      if (!members) return true;
      if (direction === "entrantes") return members.has(f.to);
      if (direction === "sortantes") return members.has(f.from);
      return members.has(f.from) || members.has(f.to);
    });
  }, [data, layer, members, direction]);

  const sumBy = (key: "from" | "to") => {
    const m = new Map<string, number>();
    for (const f of flows) m.set(f[key], (m.get(f[key]) ?? 0) + f.value);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  };
  const origins = useMemo(() => sumBy("from"), [flows]); // eslint-disable-line react-hooks/exhaustive-deps
  const targets = useMemo(() => sumBy("to"), [flows]); // eslint-disable-line react-hooks/exhaustive-deps
  const c2 = useMemo(() => (data?.c2 ?? []).filter((c) => inZone(c.cc)), [data, inZone]);
  const c2Count = c2.reduce((s, c) => s + c.count, 0);

  const maxFlow = flows[0]?.value ?? 1;
  type Arc =
    | { f: Flow; key: string; self: true; x: number; y: number; r: number }
    | { f: Flow; key: string; self: false; d: string; len: number; r: number };
  const arcs = useMemo((): Arc[] => {
    return flows.slice(0, MAX_ARCS).flatMap((f): Arc[] => {
      const a = geo.pts.get(f.from);
      const b = geo.pts.get(f.to);
      if (!a || !b) return [];
      const key = `${f.layer}:${f.from}>${f.to}`;
      const r = seeded(key);
      if (f.from === f.to) return [{ f, key, self: true, x: a[0], y: a[1], r }];
      const dx = b[0] - a[0];
      const dy = b[1] - a[1];
      const dist = Math.hypot(dx, dy);
      // Point de contrôle décalé perpendiculairement, toujours vers le haut de la carte.
      let nx = -dy / dist;
      let ny = dx / dist;
      if (ny > 0) {
        nx = -nx;
        ny = -ny;
      }
      const lift = Math.min(160, dist * 0.32);
      const cx = (a[0] + b[0]) / 2 + nx * lift;
      const cy = (a[1] + b[1]) / 2 + ny * lift;
      return [{ f, key, self: false, d: `M${a[0].toFixed(1)},${a[1].toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${b[0].toFixed(1)},${b[1].toFixed(1)}`, len: dist * 1.25, r }];
    });
  }, [flows, geo]);

  const targetPulses = useMemo(() => targets.slice(0, 25).flatMap(([cc, v]) => {
    const p = geo.pts.get(cc);
    return p ? [{ cc, v, x: p[0], y: p[1] }] : [];
  }), [targets, geo]);
  const maxTarget = targetPulses[0]?.v ?? 1;
  const c2Dots = useMemo(() => (showC2 ? c2 : []).flatMap((c) => {
    const p = geo.pts.get(c.cc);
    return p ? [{ ...c, x: p[0], y: p[1] }] : [];
  }), [c2, showC2, geo]);
  const maxC2 = c2Dots[0]?.count ?? 1;

  const radarOff = data && !data.radar.configured;
  const selectedCountries = [...COUNTRIES].sort((a, b) => a.name.localeCompare(b.name, "fr"));
  const hoverInfo = hover ? describe(hover, data?.flows ?? [], data?.c2 ?? [], layer) : null;

  return (
    <div className="tm">
      <div className="tm-controls">
        <label className="tm-select">
          <span className="sr-only">Zone géographique</span>
          <Icon name="radio" size={14} />
          <select value={zone.startsWith("pays:") ? "" : zone} onChange={(e) => e.target.value && setZone(e.target.value)} aria-label="Zone géographique">
            {zone.startsWith("pays:") && <option value="">{zoneLabel(zone)}</option>}
            {ZONES.map((z) => (
              <option key={z.id} value={z.id}>
                {z.label}
              </option>
            ))}
          </select>
        </label>
        <label className="tm-select">
          <span className="sr-only">Pays</span>
          <span aria-hidden="true">{country ? flag(country) : "🌐"}</span>
          <select value={country ?? ""} onChange={(e) => setZone(e.target.value ? `pays:${e.target.value}` : "monde")} aria-label="Pays">
            <option value="">Tous les pays</option>
            {selectedCountries.map((c) => (
              <option key={c.cca2} value={c.cca2}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        <div className="segmented" role="group" aria-label="Période">
          {(Object.keys(PERIOD_LABEL) as Period[]).map((p) => (
            <button key={p} type="button" aria-pressed={period === p} className={period === p ? "is-on" : ""} onClick={() => setPeriod(p)}>
              {PERIOD_LABEL[p]}
            </button>
          ))}
        </div>
      </div>
      <div className="tm-controls">
        <div className="segmented" role="group" aria-label="Sens des attaques">
          {(
            [
              ["tout", "Tous les flux"],
              ["entrantes", "Attaques reçues"],
              ["sortantes", "Attaques émises"],
            ] as [Direction, string][]
          ).map(([k, l]) => (
            <button key={k} type="button" aria-pressed={direction === k} className={direction === k ? "is-on" : ""} onClick={() => setDirection(k)} disabled={!members}>
              {l}
            </button>
          ))}
        </div>
        <div className="segmented" role="group" aria-label="Type d’attaque">
          {(
            [
              ["tout", "Toutes"],
              ["L7", "Applicatives (L7)"],
              ["L3", "DDoS réseau (L3)"],
            ] as [LayerSel, string][]
          ).map(([k, l]) => (
            <button key={k} type="button" aria-pressed={layer === k} className={layer === k ? "is-on" : ""} onClick={() => setLayer(k)}>
              {l}
            </button>
          ))}
        </div>
        <label className="switch-row">
          <span>Botnets C2</span>
          <span className="switch">
            <input type="checkbox" role="switch" aria-label="Afficher les serveurs C2 de botnets" checked={showC2} onChange={(e) => setShowC2(e.target.checked)} />
            <span />
          </span>
        </label>
      </div>

      {radarOff && (
        <p className="callout" role="status">
          Les flux pays → pays nécessitent un jeton gratuit Cloudflare Radar. Créez un jeton personnalisé avec la permission
          « Account › Radar › Read » sur dash.cloudflare.com, puis ajoutez la variable <code>CLOUDFLARE_API_TOKEN</code> au projet
          Vercel. En attendant, la carte montre les serveurs de botnets actifs et les ports les plus attaqués.
        </p>
      )}
      {err && <p className="callout callout-err">{err}</p>}
      {data && data.errors.length > 0 && <p className="callout callout-err">Sources partielles : {data.errors.join(" ; ")}.</p>}

      <div className="tm-kpis">
        <div className="tile">
          <span className="tile-k">Flux affichés</span>
          <span className="tile-v">{data?.radar.configured ? fmt(flows.length) : "–"}</span>
          <span className="tile-n">{zoneLabel(zone)}</span>
        </div>
        <div className="tile">
          <span className="tile-k">Pays d’origine</span>
          <span className="tile-v">{data?.radar.configured ? origins.length : "–"}</span>
          <span className="tile-n">{origins[0] ? `en tête : ${countryName(origins[0][0])}` : "aucun"}</span>
        </div>
        <div className="tile">
          <span className="tile-k">Pays ciblés</span>
          <span className="tile-v">{data?.radar.configured ? targets.length : "–"}</span>
          <span className="tile-n">{targets[0] ? `en tête : ${countryName(targets[0][0])}` : "aucun"}</span>
        </div>
        <div className="tile">
          <span className="tile-k">Serveurs C2 actifs</span>
          <span className="tile-v">{data ? fmt(c2Count) : "–"}</span>
          <span className="tile-n">{c2[0] ? `surtout ${countryName(c2[0].cc)}` : "dans la zone"}</span>
        </div>
      </div>

      <figure className="tm-map" aria-label={`Carte des attaques : ${zoneLabel(zone)}`}>
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-labelledby="tm-cap">
          <defs>
            <radialGradient id="tm-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#ff453a" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#ff453a" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="tm-l7" x1="0" x2="1">
              <stop offset="0%" stopColor="#ff9f0a" />
              <stop offset="100%" stopColor="#ff453a" />
            </linearGradient>
            <linearGradient id="tm-l3" x1="0" x2="1">
              <stop offset="0%" stopColor="#64d2ff" />
              <stop offset="100%" stopColor="#bf5af2" />
            </linearGradient>
          </defs>
          <path d={geo.outline} className="tm-sphere" />
          <g className="tm-land">
            {geo.shapes.map((s) => {
              const cls = ["tm-country"];
              if (s.cc && members?.has(s.cc)) cls.push("is-zone");
              if (s.cc && country === s.cc) cls.push("is-selected");
              if (s.cc && hover === s.cc) cls.push("is-hover");
              return (
                <path
                  key={s.key}
                  d={s.d}
                  className={cls.join(" ")}
                  onMouseEnter={() => s.cc && setHover(s.cc)}
                  onMouseLeave={() => setHover(null)}
                  onClick={() => s.cc && setZone(country === s.cc ? "monde" : `pays:${s.cc}`)}
                >
                  <title>{s.name}</title>
                </path>
              );
            })}
          </g>

          <g className="tm-arcs">
            {arcs.map((a) =>
              a.self ? (
                <circle key={a.key} cx={a.x} cy={a.y} r={4 + 10 * Math.sqrt(a.f.value / maxFlow)} className={`tm-self tm-${a.f.layer}`} style={{ animationDelay: `${(a.r * 2).toFixed(2)}s` }}>
                  <title>{`${countryName(a.f.from)} → ${countryName(a.f.to)} (attaques internes) · ${LAYER_LABEL[a.f.layer]} · ${pct(a.f.value)}`}</title>
                </circle>
              ) : (
                <g key={a.key}>
                  <path d={a.d} className={`tm-trail tm-${a.f.layer}`} strokeWidth={0.6 + 2.4 * Math.sqrt(a.f.value / maxFlow)}>
                    <title>{`${countryName(a.f.from)} → ${countryName(a.f.to)} · ${LAYER_LABEL[a.f.layer]} · ${pct(a.f.value)}`}</title>
                  </path>
                  <path
                    d={a.d}
                    className={`tm-comet tm-${a.f.layer}`}
                    strokeWidth={1.4 + 3 * Math.sqrt(a.f.value / maxFlow)}
                    style={
                      {
                        "--len": `${a.len.toFixed(0)}`,
                        animationDuration: `${(1.6 + a.r * 1.8).toFixed(2)}s`,
                        animationDelay: `${(a.r * 3).toFixed(2)}s`,
                      } as React.CSSProperties
                    }
                  />
                </g>
              ),
            )}
          </g>

          <g className="tm-targets">
            {targetPulses.map((t) => {
              const r = 3 + 9 * Math.sqrt(t.v / maxTarget);
              return (
                <g key={t.cc} transform={`translate(${t.x.toFixed(1)} ${t.y.toFixed(1)})`}>
                  <circle r={r * 2.4} className="tm-pulse" style={{ animationDelay: `${(seeded(t.cc) * 2).toFixed(2)}s` }} />
                  <circle r={r} className="tm-target">
                    <title>{`${countryName(t.cc)} : ${pct(t.v)} des flux affichés reçus`}</title>
                  </circle>
                </g>
              );
            })}
          </g>

          <g className="tm-c2">
            {c2Dots.map((c) => {
              const s = 3 + 7 * Math.sqrt(c.count / maxC2);
              return (
                <rect key={c.cc} x={c.x - s / 2} y={c.y - s / 2} width={s} height={s} transform={`rotate(45 ${c.x.toFixed(1)} ${c.y.toFixed(1)})`} className="tm-c2dot">
                  <title>{`${countryName(c.cc)} : ${c.count} serveur${c.count > 1 ? "s" : ""} C2 (${c.malware.map((m) => m.name).slice(0, 3).join(", ")})`}</title>
                </rect>
              );
            })}
          </g>
        </svg>

        {hoverInfo && <div className="tm-hover" aria-live="polite">{hoverInfo}</div>}

        <figcaption id="tm-cap" className="tm-legend">
          <span>
            <i className="lg lg-l7" /> Applicatives (L7)
          </span>
          <span>
            <i className="lg lg-l3" /> DDoS réseau (L3)
          </span>
          <span>
            <i className="lg lg-target" /> Pays ciblé
          </span>
          <span>
            <i className="lg lg-c2" /> Serveurs C2 de botnets
          </span>
          <span className="tm-updated">
            {loading ? (
              <>
                <Icon name="refresh" size={12} className="spin" /> Actualisation…
              </>
            ) : data ? (
              `Mis à jour ${relTime(data.generatedAt, now)}`
            ) : null}
          </span>
        </figcaption>
      </figure>

      <div className="tm-grid">
        <section className="card tm-panel" aria-labelledby="tm-h-flows">
          <h2 id="tm-h-flows">Principaux flux</h2>
          {!data?.radar.configured ? (
            <p className="hint">Disponible avec le jeton Cloudflare Radar.</p>
          ) : flows.length === 0 ? (
            <p className="hint">Aucun flux pour cette zone sur la période.</p>
          ) : (
            <ol className="tm-list">
              {flows.slice(0, 12).map((f) => (
                <li key={`${f.layer}:${f.from}>${f.to}`}>
                  <span className="tm-pair">
                    <button type="button" className="tm-cc" onClick={() => setZone(`pays:${f.from}`)}>
                      {flag(f.from)} {countryName(f.from)}
                    </button>
                    <span className="tm-arrow" aria-label="vers">
                      →
                    </span>
                    <button type="button" className="tm-cc" onClick={() => setZone(`pays:${f.to}`)}>
                      {flag(f.to)} {countryName(f.to)}
                    </button>
                  </span>
                  <span className={`tm-badge tm-b-${f.layer}`}>{f.layer}</span>
                  <span className="tm-bar">
                    <span style={{ width: `${Math.max(4, (f.value / maxFlow) * 100)}%` }} className={`tm-fill-${f.layer}`} />
                  </span>
                  <span className="tm-val">{pct(f.value)}</span>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="card tm-panel" aria-labelledby="tm-h-countries">
          <h2 id="tm-h-countries">Origines et cibles</h2>
          {!data?.radar.configured ? (
            <p className="hint">Disponible avec le jeton Cloudflare Radar.</p>
          ) : (
            <div className="tm-two">
              <CountryRank title="D’où partent les attaques" rows={origins} onPick={(cc) => setZone(`pays:${cc}`)} />
              <CountryRank title="Pays les plus visés" rows={targets} onPick={(cc) => setZone(`pays:${cc}`)} />
            </div>
          )}
        </section>

        <section className="card tm-panel" aria-labelledby="tm-h-c2">
          <h2 id="tm-h-c2">Serveurs C2 de botnets actifs</h2>
          {c2.length === 0 ? (
            <p className="hint">{data ? "Aucun serveur C2 recensé dans cette zone." : "Chargement…"}</p>
          ) : (
            <ol className="tm-list">
              {c2.slice(0, 10).map((c) => (
                <li key={c.cc}>
                  <button type="button" className="tm-cc" onClick={() => setZone(`pays:${c.cc}`)}>
                    {flag(c.cc)} {countryName(c.cc)}
                  </button>
                  <span className="tm-mw">{c.malware.slice(0, 3).map((m) => `${m.name} ×${m.count}`).join(" · ")}</span>
                  <span className="tm-val">{c.count}</span>
                </li>
              ))}
            </ol>
          )}
          <p className="tm-src">
            Source : <a href="https://feodotracker.abuse.ch/" target="_blank" rel="noreferrer">abuse.ch Feodo Tracker</a>
            {data ? ` · ${fmt(data.c2Total)} serveurs dans le monde` : ""}
          </p>
        </section>

        <section className="card tm-panel" aria-labelledby="tm-h-ports">
          <h2 id="tm-h-ports">Ports les plus attaqués</h2>
          {(data?.ports.length ?? 0) === 0 ? (
            <p className="hint">{data ? "Données SANS ISC indisponibles pour le moment." : "Chargement…"}</p>
          ) : (
            <ol className="tm-list">
              {data!.ports.map((p) => (
                <li key={p.port}>
                  <span className="tm-port">
                    {p.port}
                    {PORT_NAMES[p.port] && <span className="tm-svc">{PORT_NAMES[p.port]}</span>}
                  </span>
                  <span className="tm-bar">
                    <span style={{ width: `${Math.max(4, (p.records / data!.ports[0].records) * 100)}%` }} className="tm-fill-port" />
                  </span>
                  <span className="tm-val">{fmt(p.sources)} sources</span>
                </li>
              ))}
            </ol>
          )}
          <p className="tm-src">
            Source : <a href="https://isc.sans.edu/" target="_blank" rel="noreferrer">SANS Internet Storm Center</a> (capteurs DShield, monde entier)
            {data?.portsDate ? `, ${data.portsDate}` : ""}
          </p>
        </section>
      </div>

      <p className="foot-note">
        Flux : <a href="https://radar.cloudflare.com/security" target="_blank" rel="noreferrer">Cloudflare Radar</a>, part (%) du
        trafic d’attaque bloqué par Cloudflare sur la période{data?.radar.start ? ` (du ${new Date(data.radar.start).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" })} au ${new Date(data.radar.end ?? data.generatedAt).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" })})` : ""} ;
        l’origine est le pays de l’adresse IP attaquante, qui peut être un relais. Les animations illustrent ces volumes, pas des attaques
        individuelles. Données pays : mledoze/countries (ODbL).
      </p>
    </div>
  );
}

function CountryRank({ title, rows, onPick }: { title: string; rows: [string, number][]; onPick: (cc: string) => void }) {
  const max = rows[0]?.[1] ?? 1;
  return (
    <div>
      <h3>{title}</h3>
      {rows.length === 0 ? (
        <p className="hint">Aucun.</p>
      ) : (
        <ol className="tm-list tm-list-compact">
          {rows.slice(0, 8).map(([cc, v]) => (
            <li key={cc}>
              <button type="button" className="tm-cc" onClick={() => onPick(cc)}>
                {flag(cc)} {countryName(cc)}
              </button>
              <span className="tm-bar">
                <span style={{ width: `${Math.max(4, (v / max) * 100)}%` }} className="tm-fill-L7" />
              </span>
              <span className="tm-val">{pct(v)}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function describe(cc: string, flows: Flow[], c2: ThreatMapData["c2"], layer: LayerSel): string {
  const f = flows.filter((x) => layer === "tout" || x.layer === layer);
  const out = f.filter((x) => x.from === cc).reduce((s, x) => s + x.value, 0);
  const inc = f.filter((x) => x.to === cc).reduce((s, x) => s + x.value, 0);
  const c = c2.find((x) => x.cc === cc)?.count ?? 0;
  const parts = [`${flag(cc)} ${BY_CC.get(cc)?.name ?? cc}`];
  if (out) parts.push(`émet ${pct(out)}`);
  if (inc) parts.push(`reçoit ${pct(inc)}`);
  if (c) parts.push(`${c} C2`);
  return parts.join(" · ");
}
