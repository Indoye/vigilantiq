"use client";

import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { relTime } from "@/lib/format";
import { Icon } from "../ui";
import { fmtInt, Kpi, Skeleton, useJson } from "../cti/common";

// ---------- Types (réponses des API /api/parc) ----------

type Prio = "urgente" | "haute" | "moyenne" | "basse";
interface DeviceRow {
  id: number;
  name: string;
  hostname: string;
  kind: string;
  osFamily: string;
  osName: string;
  osVersion: string;
  arch: string;
  ip: string | null;
  domain: string;
  loggedUser: string;
  groupName: string;
  tags: string[];
  ring: string;
  agentVersion: string;
  appManager: boolean;
  rebootPending: boolean;
  lastSeenAt: string | null;
  lastInventoryAt: string | null;
  correlatedAt: string | null;
  correlateError: string | null;
  enrolledAt: string;
  vulns: Record<Prio | "kev" | "patchable", number>;
  pendingJobs: number;
}
interface JobView {
  id: number;
  device: string;
  deviceId: number;
  action: string;
  phase: string | null;
  status: string;
  cves: number;
  log: string;
  notBefore: string | null;
  finishedAt: string | null;
}
interface DeploymentRow {
  id: number;
  title: string;
  status: string;
  message: string;
  policyId: number | null;
  window: Win | null;
  reboot: string;
  pilot: boolean;
  pilotThreshold: number;
  devices: number;
  createdBy: string | null;
  approvedBy: string | null;
  createdAt: string;
  finishedAt: string | null;
  jobs: JobView[];
}
interface Win {
  days: number[];
  start: string;
  end: string;
  tz: string;
}
interface Policy {
  id: number;
  name: string;
  enabled: boolean;
  target: { groups?: string[]; tags?: string[]; os?: string[]; kinds?: string[] };
  content: string;
  minPriority: Prio;
  kevOnly: boolean;
  approval: string;
  window: Win | null;
  reboot: string;
  rebootDeferHours: number;
  maxParallel: number;
  pilot: boolean;
  pilotThreshold: number;
}
interface Overview {
  kpis: {
    devices: number;
    online: number;
    inventoried: number;
    compliance: number | null;
    openCves: number;
    openRows: number;
    urgent: number;
    high: number;
    kev: number;
    rebootPending: number;
    mttrDays: number | null;
    deploySuccess: number | null;
  };
  trend: { day: string; high: number; total: number }[];
  devices: DeviceRow[];
  deployments: DeploymentRow[];
  policies: Policy[];
  enrollment: { createdAt: string } | null;
  agentVersion: string;
  events: { actor: string; action: string; target: string; detail: Record<string, unknown>; at: string }[];
}
interface Fix {
  kind: string;
  label?: string;
  fixedVersion?: string | null;
  winget?: string;
}
interface VulnRow {
  id: number;
  deviceId: number;
  cveId: string;
  componentKind: string;
  componentName: string;
  componentVersion: string;
  source: string;
  advisory: string;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  ransomware: boolean;
  score: number;
  priority: Prio;
  reasons: string[];
  fix: Fix;
  status: string;
  ignoredReason: string | null;
  ignoredBy: string | null;
  firstSeen: string;
  fixedAt: string | null;
}
interface FleetVuln {
  cveId: string;
  score: number;
  priority: Prio;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  ransomware: boolean;
  reasons: string[];
  components: string[];
  fixes: string[];
  patchable: boolean;
  devices: { id: number; name: string; vulnId: number; component: string; version: string; status: string; fix: string }[];
}
interface DeviceDetail {
  device: DeviceRow;
  hardware: Record<string, string>;
  components: { kind: string; name: string; vendor: string; version: string; source: string; extra: Record<string, string>; catalog: string | null }[];
  vulns: VulnRow[];
  jobs: { id: number; action: string; phase: string | null; status: string; deploymentId: number | null; payload: Record<string, unknown>; log: string; result: Record<string, unknown> | null; createdAt: string; sentAt: string | null; finishedAt: string | null; notBefore: string | null }[];
  events: { actor: string; action: string; detail: Record<string, unknown>; at: string }[];
}
interface Kit {
  token: string | null;
  createdAt?: string;
  installers?: { windows: string; linux: string };
  commands?: { windows: string[]; linux: string[] };
}

// ---------- Libellés ----------

const PRIO_LABEL: Record<Prio, string> = { urgente: "Urgente", haute: "Haute", moyenne: "Moyenne", basse: "Basse" };
const DEP_STATUS: Record<string, { label: string; cls: string }> = {
  attente_approbation: { label: "À approuver", cls: "tag tag-prio p-haute" },
  planifie: { label: "Planifié", cls: "tag" },
  pilote: { label: "Anneau pilote", cls: "tag tag-stack" },
  production: { label: "Production", cls: "tag tag-stack" },
  termine: { label: "Terminé", cls: "tag tag-good" },
  echec: { label: "Échec", cls: "tag tag-bad" },
  annule: { label: "Annulé", cls: "tag" },
};
const JOB_STATUS: Record<string, { label: string; cls: string }> = {
  en_attente: { label: "En attente", cls: "tag" },
  envoye: { label: "En cours", cls: "tag tag-stack" },
  succes: { label: "Réussi", cls: "tag tag-good" },
  echec: { label: "Échec", cls: "tag tag-bad" },
  annule: { label: "Annulé", cls: "tag" },
};
const ACTION_LABEL: Record<string, string> = { scan: "Scan", install: "Installation", rollback: "Retour arrière", reboot: "Redémarrage" };
const KIND_LABEL: Record<string, string> = { os: "Système", kb: "Mises à jour Windows", app: "Applications", package: "Paquets", driver: "Pilotes", bios: "BIOS / firmware" };
const COMPONENT_LABEL: Record<string, string> = { os: "Système", app: "Application", package: "Paquet", bios: "Firmware" };
const AUDIT_LABEL: Record<string, string> = {
  agent_enrole: "Agent enrôlé",
  agent_reinstalle: "Agent réinstallé",
  jeton_renouvele: "Jeton d’enrôlement renouvelé",
  jeton_revoque: "Jeton d’enrôlement révoqué",
  tache_succes: "Tâche réussie",
  tache_echec: "Tâche en échec",
  retour_arriere: "Retour arrière lancé",
  retour_arriere_demande: "Retour arrière demandé",
  politique_enregistree: "Politique enregistrée",
  politique_supprimee: "Politique supprimée",
  deploiement_cree: "Déploiement créé",
  deploiement_approuve: "Déploiement approuvé",
  deploiement_annule: "Déploiement annulé",
  deploiement_termine: "Déploiement terminé",
  deploiement_echec: "Déploiement en échec",
  pilote_reussi: "Anneau pilote réussi",
  scan_demande: "Scan demandé",
  redemarrage_demande: "Redémarrage demandé",
  equipement_modifie: "Équipement modifié",
  equipement_supprime: "Équipement supprimé",
  cve_ignoree: "CVE ignorée",
  cve_reouverte: "CVE rouverte",
};
const DAYS = ["", "Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"];
const ONLINE_MS = 5 * 60_000;

async function send(url: string, method: string, body?: unknown) {
  const r = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
  return j;
}

const isOnline = (d: DeviceRow, now: number) => Boolean(d.lastSeenAt && now - Date.parse(d.lastSeenAt) < ONLINE_MS);
const windowText = (w: Win | null) => (w ? `${w.days.length === 7 ? "Tous les jours" : w.days.map((d) => DAYS[d]).join(", ")} ${w.start}–${w.end} (${w.tz})` : "À tout moment");

function PrioTag({ p }: { p: Prio }) {
  return <span className={`tag tag-prio p-${p}`}>{PRIO_LABEL[p] ?? p}</span>;
}

function Msg({ m }: { m: { ok: boolean; text: string } | null }) {
  return m ? <p className={`form-msg ${m.ok ? "form-ok" : "form-err"}`}>{m.text}</p> : null;
}

function useAction(after: () => void) {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (f: () => Promise<{ message?: string } | void>, ok?: string) => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await f();
      setMsg({ ok: true, text: (r && r.message) || ok || "C’est fait." });
      after();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Opération impossible" });
    } finally {
      setBusy(false);
    }
  };
  return { msg, busy, run, setMsg };
}

type Tab = "apercu" | "equipements" | "vulns" | "deploiements" | "politiques" | "logiciels" | "agent";
const TABS: [Tab, string][] = [
  ["apercu", "Vue d’ensemble"],
  ["equipements", "Équipements"],
  ["vulns", "Vulnérabilités"],
  ["deploiements", "Déploiements"],
  ["politiques", "Politiques"],
  ["logiciels", "Logiciels"],
  ["agent", "Installer l’agent"],
];

/** Parc & correctifs : agent local, inventaire, CVE par équipement, correctifs automatiques. */
export default function PatchView({ now, guest }: { now: number; guest: boolean }) {
  const { data, error, loading, reload } = useJson<Overview>(guest ? null : "/api/parc", 60_000);
  const [tab, setTab] = useState<Tab>("apercu");
  const [deviceId, setDeviceId] = useState<number | null>(null);
  const [patchFor, setPatchFor] = useState<{ deviceIds: number[]; cves?: string[]; label: string } | null>(null);

  if (guest) {
    return (
      <div className="empty card">
        <p className="empty-title">Parc & correctifs réservé aux comptes</p>
        <p>
          Installez l’agent VigilantIQ sur vos postes et serveurs : la console affiche les CVE de chaque composant (système, applications, paquets,
          firmware) et déploie les correctifs automatiquement, avec anneau pilote et retour arrière. <a href="/connexion">Connectez-vous avec un compte</a>.
        </p>
      </div>
    );
  }
  if (loading && !data) return <Skeleton />;
  if (error && !data) return <p className="callout callout-err">{error}</p>;
  if (!data) return null;

  const open = (id: number) => {
    setDeviceId(id);
    setTab("equipements");
  };
  const first = data.devices.length === 0;

  return (
    <div className="cti parc">
      <div className="segmented parc-tabs" role="tablist" aria-label="Parc & correctifs">
        {TABS.map(([k, l]) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={tab === k}
            className={tab === k ? "is-on" : ""}
            onClick={() => {
              setTab(k);
              if (k !== "equipements") setDeviceId(null);
            }}
          >
            {l}
            {k === "deploiements" && data.deployments.some((d) => d.status === "attente_approbation") ? <span className="parc-dot" aria-label="à approuver" /> : null}
          </button>
        ))}
      </div>

      {patchFor && <PatchDialog target={patchFor} onClose={() => setPatchFor(null)} onDone={() => { setPatchFor(null); reload(); setTab("deploiements"); }} />}

      {first && tab !== "agent" ? (
        <section className="card tm-panel parc-welcome">
          <h2>
            <Icon name="wrench" size={16} /> Commencez par installer l’agent
          </h2>
          <p className="cti-desc">
            L’agent s’installe en une commande sur Windows (10, 11, Server 2016 et plus) ou Linux (Debian, Ubuntu, RHEL, Rocky, AlmaLinux). La machine
            apparaît ici en moins d’une minute, avec son inventaire et ses CVE.
          </p>
          <div className="watch-actions">
            <button type="button" className="btn-primary watch-add" onClick={() => setTab("agent")}>
              Installer l’agent
            </button>
          </div>
        </section>
      ) : null}

      {tab === "apercu" && !first && <OverviewTab data={data} now={now} onOpen={open} onTab={setTab} />}
      {tab === "equipements" &&
        (deviceId ? (
          <DeviceSheet id={deviceId} now={now} onBack={() => setDeviceId(null)} onPatch={setPatchFor} onChange={reload} />
        ) : (
          <DevicesTab devices={data.devices} now={now} onOpen={open} onPatch={setPatchFor} onChange={reload} />
        ))}
      {tab === "vulns" && <VulnsTab onOpen={open} onPatch={setPatchFor} />}
      {tab === "deploiements" && <DeploymentsTab deployments={data.deployments} now={now} onChange={reload} />}
      {tab === "politiques" && <PoliciesTab policies={data.policies} devices={data.devices} onChange={reload} />}
      {tab === "logiciels" && <SoftwareTab />}
      {tab === "agent" && <AgentTab agentVersion={data.agentVersion} onChange={reload} />}
    </div>
  );
}

// ---------- Vue d'ensemble ----------

function OverviewTab({ data, now, onOpen, onTab }: { data: Overview; now: number; onOpen: (id: number) => void; onTab: (t: Tab) => void }) {
  const k = data.kpis;
  const exposed = [...data.devices].filter((d) => d.vulns.urgente + d.vulns.haute > 0).sort((a, b) => b.vulns.urgente - a.vulns.urgente || b.vulns.haute - a.vulns.haute).slice(0, 6);
  const toApprove = data.deployments.filter((d) => d.status === "attente_approbation");
  const running = data.deployments.filter((d) => d.status === "pilote" || d.status === "production");
  return (
    <>
      <section className="tiles parc-tiles">
        <Kpi k="Équipements" v={fmtInt(k.devices)} n={`${k.online} en ligne`} />
        <Kpi k="CVE ouvertes" v={fmtInt(k.openCves)} n={`${k.urgent} urgente${k.urgent > 1 ? "s" : ""}, ${k.high} haute${k.high > 1 ? "s" : ""}`} />
        <Kpi k="Exploitées (KEV)" v={fmtInt(k.kev)} n="à corriger en premier" />
        <Kpi k="Conformité" v={k.compliance == null ? "–" : `${k.compliance} %`} n="sans CVE urgente ni KEV" />
        <Kpi k="Délai moyen de correction" v={k.mttrDays == null ? "–" : k.mttrDays < 1 ? "< 1 j" : `${k.mttrDays} j`} n="CVE urgentes et hautes, 90 j" />
        <Kpi k="Réussite des déploiements" v={k.deploySuccess == null ? "–" : `${k.deploySuccess} %`} n={k.rebootPending ? `${k.rebootPending} redémarrage${k.rebootPending > 1 ? "s" : ""} en attente` : "90 derniers jours"} />
      </section>

      {toApprove.length > 0 && (
        <section className="callout parc-approve" role="status">
          <Icon name="clock" size={16} />
          <p>
            {toApprove.length} déploiement{toApprove.length > 1 ? "s" : ""} en attente d’approbation.{" "}
            <button type="button" className="btn-plain" onClick={() => onTab("deploiements")}>
              Examiner
            </button>
          </p>
        </section>
      )}

      <section className="card tm-panel">
        <div className="hunt-head">
          <div>
            <h2>Exposition du parc sur 90 jours</h2>
            <p className="hint">CVE ouvertes chaque jour, toutes priorités et urgentes ou hautes.</p>
          </div>
          <a className="btn-plain" href="/api/parc/export">
            <Icon name="file" size={14} /> Exporter en CSV
          </a>
        </div>
        <TrendChart trend={data.trend} />
      </section>

      <div className="parc-cols">
        <section className="card tm-panel">
          <h2>Équipements les plus exposés</h2>
          {exposed.length === 0 ? (
            <p className="hint">Aucun équipement avec une CVE urgente ou haute ouverte.</p>
          ) : (
            <ul className="dw-sources">
              {exposed.map((d) => (
                <li key={d.id}>
                  <button type="button" className="parc-link" onClick={() => onOpen(d.id)}>
                    <span className="acc-email">{d.name}</span>
                    <span className="cti-desc">{d.osName || d.osFamily}</span>
                  </button>
                  <VulnChips v={d.vulns} />
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="card tm-panel">
          <h2>Déploiements en cours</h2>
          {running.length === 0 ? (
            <p className="hint">Aucun déploiement en cours.</p>
          ) : (
            <ul className="dw-sources">
              {running.map((d) => (
                <li key={d.id}>
                  <span className="acc-main">
                    <span className="acc-email">{d.title}</span>
                    <span className="cti-desc">{d.message}</span>
                  </span>
                  <Progress jobs={d.jobs} />
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="card tm-panel">
        <h2>Journal d’audit</h2>
        {data.events.length === 0 ? (
          <p className="hint">Aucune action pour le moment.</p>
        ) : (
          <AuditList events={data.events} now={now} />
        )}
      </section>
    </>
  );
}

/** Largeur réelle d'un élément (le graphique est dessiné à sa taille, sans mise à l'échelle des textes). */
function useWidth<T extends HTMLElement>(fallback: number) {
  const ref = useRef<T>(null);
  const [w, setW] = useState(fallback);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return { ref, w };
}

function AuditList({ events, now }: { events: Overview["events"]; now: number }) {
  const [all, setAll] = useState(false);
  return (
    <>
      <ul className="parc-audit">
        {(all ? events : events.slice(0, 10)).map((e, i) => (
          <li key={i}>
            <span className="hint">{relTime(e.at, now)}</span>
            <span>
              <strong>{AUDIT_LABEL[e.action] ?? e.action}</strong>
              {e.target ? ` · ${e.target}` : ""}
            </span>
            <span className="hint parc-actor">{e.actor}</span>
          </li>
        ))}
      </ul>
      {events.length > 10 && (
        <button type="button" className="btn-plain parc-more" onClick={() => setAll(!all)}>
          {all ? "Afficher moins" : `Afficher les ${events.length} dernières actions`}
        </button>
      )}
    </>
  );
}

function TrendChart({ trend }: { trend: Overview["trend"] }) {
  const { ref, w: W } = useWidth<HTMLElement>(720);
  const H = 180;
  const pad = { l: 36, r: 12, t: 12, b: 24 };
  const max = Math.max(4, ...trend.map((t) => t.total));
  const x = (i: number) => pad.l + (i / Math.max(1, trend.length - 1)) * (W - pad.l - pad.r);
  const y = (v: number) => pad.t + (1 - v / max) * (H - pad.t - pad.b);
  const line = (k: "total" | "high") => trend.map((t, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(t[k]).toFixed(1)}`).join(" ");
  const area = (k: "total" | "high") => `${line(k)} L${x(trend.length - 1).toFixed(1)} ${y(0)} L${x(0)} ${y(0)} Z`;
  const ticks = [0, Math.round(max / 2), max];
  const last = trend[trend.length - 1];
  const labels = [0, Math.floor(trend.length / 2), trend.length - 1].filter((i) => trend[i]);
  return (
    <figure className="parc-chart" ref={ref}>
      <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label={`CVE ouvertes : ${last?.total ?? 0} aujourd’hui, dont ${last?.high ?? 0} urgentes ou hautes`}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} className="parc-grid" />
            <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" className="parc-axis">
              {t}
            </text>
          </g>
        ))}
        <path d={area("total")} className="parc-area-total" />
        <path d={line("total")} className="parc-line-total" />
        <path d={area("high")} className="parc-area-high" />
        <path d={line("high")} className="parc-line-high" />
        {labels.map((i) => (
          <text key={i} x={x(i)} y={H - 6} textAnchor={i === 0 ? "start" : i === trend.length - 1 ? "end" : "middle"} className="parc-axis">
            {new Date(trend[i].day).toLocaleDateString("fr-FR", { day: "numeric", month: "short" })}
          </text>
        ))}
      </svg>
      <figcaption className="parc-legend">
        <span>
          <i className="parc-key parc-key-total" /> Toutes ({last?.total ?? 0})
        </span>
        <span>
          <i className="parc-key parc-key-high" /> Urgentes et hautes ({last?.high ?? 0})
        </span>
      </figcaption>
    </figure>
  );
}

function VulnChips({ v }: { v: DeviceRow["vulns"] }) {
  const none = v.urgente + v.haute + v.moyenne + v.basse === 0;
  return (
    <span className="chips parc-vchips">
      {none && <span className="tag tag-good">Aucune CVE</span>}
      {v.urgente > 0 && <span className="tag tag-prio p-urgente">{v.urgente} urg.</span>}
      {v.haute > 0 && <span className="tag tag-prio p-haute">{v.haute} hautes</span>}
      {v.moyenne + v.basse > 0 && <span className="tag">{v.moyenne + v.basse} autres</span>}
      {v.kev > 0 && <span className="tag tag-kev">{v.kev} KEV</span>}
    </span>
  );
}

function Progress({ jobs }: { jobs: JobView[] }) {
  const inst = jobs.filter((j) => j.action === "install");
  const done = inst.filter((j) => j.status === "succes").length;
  const ko = inst.filter((j) => j.status === "echec").length;
  const total = inst.length || 1;
  return (
    <span className="parc-progress" title={`${done} réussi(s), ${ko} échec(s) sur ${inst.length}`}>
      <span className="parc-bar">
        <span className="parc-bar-ok" style={{ width: `${(done / total) * 100}%` }} />
        <span className="parc-bar-ko" style={{ width: `${(ko / total) * 100}%` }} />
      </span>
      <span className="hint">
        {done}/{inst.length}
      </span>
    </span>
  );
}

// ---------- Équipements ----------

function DevicesTab({ devices, now, onOpen, onPatch, onChange }: { devices: DeviceRow[]; now: number; onOpen: (id: number) => void; onPatch: (t: { deviceIds: number[]; label: string }) => void; onChange: () => void }) {
  const [q, setQ] = useState("");
  const [os, setOs] = useState("");
  const [sel, setSel] = useState<number[]>([]);
  const { msg, run } = useAction(onChange);
  const list = devices.filter((d) => (!os || d.osFamily === os) && (!q || `${d.name} ${d.hostname} ${d.ip ?? ""} ${d.groupName} ${d.tags.join(" ")} ${d.osName}`.toLowerCase().includes(q.toLowerCase())));
  const toggle = (id: number) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const all = list.length > 0 && list.every((d) => sel.includes(d.id));
  return (
    <section className="card tm-panel">
      <div className="hunt-head">
        <h2>Équipements</h2>
        <div className="parc-filters">
          <label className="search cti-search">
            <Icon name="search" size={15} />
            <span className="sr-only">Filtrer</span>
            <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Nom, adresse IP, groupe, étiquette" />
          </label>
          <div className="segmented" role="group" aria-label="Système">
            {[
              ["", "Tous"],
              ["windows", "Windows"],
              ["linux", "Linux"],
            ].map(([k, l]) => (
              <button key={k} type="button" aria-pressed={os === k} className={os === k ? "is-on" : ""} onClick={() => setOs(k)}>
                {l}
              </button>
            ))}
          </div>
        </div>
      </div>
      {sel.length > 0 && (
        <div className="parc-bulk">
          <span>
            {sel.length} sélectionné{sel.length > 1 ? "s" : ""}
          </span>
          <button type="button" className="btn-plain" onClick={() => onPatch({ deviceIds: sel, label: `${sel.length} équipement${sel.length > 1 ? "s" : ""}` })}>
            Corriger
          </button>
          <button type="button" className="btn-plain" onClick={() => run(async () => { for (const id of sel) await send("/api/parc/devices", "PATCH", { id, action: "scan" }); return { message: `Scan demandé sur ${sel.length} équipement(s).` }; })}>
            Scanner
          </button>
          <button type="button" className="btn-plain" onClick={() => setSel([])}>
            Désélectionner
          </button>
        </div>
      )}
      <Msg m={msg} />
      {list.length === 0 ? (
        <p className="hint">{devices.length ? "Aucun équipement ne correspond au filtre." : "Aucun équipement enrôlé : installez l’agent."}</p>
      ) : (
        <div className="parc-table-wrap">
          <table className="parc-table">
            <thead>
              <tr>
                <th className="parc-check">
                  <input type="checkbox" aria-label="Tout sélectionner" checked={all} onChange={() => setSel(all ? [] : list.map((d) => d.id))} />
                </th>
                <th>Équipement</th>
                <th>Système</th>
                <th>CVE ouvertes</th>
                <th>Anneau</th>
                <th>Dernier contact</th>
              </tr>
            </thead>
            <tbody>
              {list.map((d) => (
                <tr key={d.id} onClick={() => onOpen(d.id)} className="parc-row">
                  <td className="parc-check" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" aria-label={`Sélectionner ${d.name}`} checked={sel.includes(d.id)} onChange={() => toggle(d.id)} />
                  </td>
                  <td>
                    <span className="parc-name">
                      <span className={`parc-led${isOnline(d, now) ? " is-on" : ""}`} aria-label={isOnline(d, now) ? "En ligne" : "Hors ligne"} />
                      {d.name}
                    </span>
                    <span className="hint parc-sub">
                      {d.kind === "serveur" ? "Serveur" : "Poste"}
                      {d.ip ? ` · ${d.ip}` : ""}
                      {d.groupName ? ` · ${d.groupName}` : ""}
                      {d.rebootPending ? " · redémarrage en attente" : ""}
                    </span>
                  </td>
                  <td>
                    <span className="parc-os">{d.osName || (d.osFamily === "windows" ? "Windows" : "Linux")}</span>
                    <span className="hint parc-sub">{d.osVersion}</span>
                  </td>
                  <td>{d.lastInventoryAt ? <VulnChips v={d.vulns} /> : <span className="hint">Inventaire en attente</span>}</td>
                  <td>{d.ring === "pilote" ? <span className="tag tag-stack">Pilote</span> : <span className="hint">Production</span>}</td>
                  <td className="hint">{d.lastSeenAt ? relTime(d.lastSeenAt, now) : "jamais"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function DeviceSheet({ id, now, onBack, onPatch, onChange }: { id: number; now: number; onBack: () => void; onPatch: (t: { deviceIds: number[]; cves?: string[]; label: string }) => void; onChange: () => void }) {
  const { data, error, loading, reload } = useJson<DeviceDetail>(`/api/parc/devices?id=${id}`, 30_000);
  const [sub, setSub] = useState<"cve" | "logiciels" | "historique" | "reglages">("cve");
  const [showClosed, setShowClosed] = useState(false);
  const { msg, busy, run } = useAction(() => {
    reload();
    onChange();
  });
  if (loading && !data) return <Skeleton />;
  if (error && !data) return <p className="callout callout-err">{error}</p>;
  if (!data) return null;
  const d = data.device;
  const vulns = data.vulns.filter((v) => showClosed || v.status === "ouverte");
  const patchable = data.vulns.filter((v) => v.status === "ouverte" && v.fix.kind !== "none");
  return (
    <section className="card tm-panel parc-sheet">
      <button type="button" className="btn-plain parc-back" onClick={onBack}>
        <Icon name="back" size={14} /> Équipements
      </button>
      <div className="hunt-head">
        <div>
          <h2>
            <span className={`parc-led${isOnline(d, now) ? " is-on" : ""}`} /> {d.name}
          </h2>
          <p className="cti-desc">
            {d.osName} {d.osVersion} · {d.arch} · {d.kind === "serveur" ? "serveur" : "poste"}
            {d.ip ? ` · ${d.ip}` : ""}
            {d.loggedUser ? ` · ${d.loggedUser}` : ""}
          </p>
          <p className="hint">
            Agent {d.agentVersion || "?"} · vu {d.lastSeenAt ? relTime(d.lastSeenAt, now) : "jamais"} · inventaire {d.lastInventoryAt ? relTime(d.lastInventoryAt, now) : "en attente"}
            {d.correlatedAt ? ` · CVE analysées ${relTime(d.correlatedAt, now)}` : ""}
          </p>
        </div>
        <div className="watch-actions parc-actions">
          <button type="button" className="btn-secondary" disabled={busy} onClick={() => run(() => send("/api/parc/devices", "PATCH", { id, action: "scan" }))}>
            <Icon name="refresh" size={14} /> Scanner
          </button>
          <button type="button" className="btn-primary watch-add" disabled={!patchable.length} onClick={() => onPatch({ deviceIds: [id], label: d.name })}>
            Corriger ({patchable.length})
          </button>
        </div>
      </div>
      {d.correlateError && <p className="callout">Analyse partielle : {d.correlateError}</p>}
      {d.rebootPending && (
        <p className="callout">
          Redémarrage en attente pour terminer l’installation des correctifs.{" "}
          <button type="button" className="btn-plain" onClick={() => run(() => send("/api/parc/devices", "PATCH", { id, action: "reboot" }))}>
            Redémarrer (préavis de 5 min)
          </button>
        </p>
      )}
      <Msg m={msg} />
      <div className="segmented" role="tablist">
        {(
          [
            ["cve", `CVE (${data.vulns.filter((v) => v.status === "ouverte").length})`],
            ["logiciels", `Inventaire (${data.components.length})`],
            ["historique", "Historique"],
            ["reglages", "Réglages"],
          ] as const
        ).map(([k, l]) => (
          <button key={k} type="button" role="tab" aria-selected={sub === k} className={sub === k ? "is-on" : ""} onClick={() => setSub(k)}>
            {l}
          </button>
        ))}
      </div>

      {sub === "cve" && (
        <>
          <label className="parc-toggle">
            <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Afficher les CVE corrigées et ignorées
          </label>
          {vulns.length === 0 ? (
            <p className="hint">{d.lastInventoryAt ? "Aucune CVE ouverte sur cet équipement." : "L’inventaire n’est pas encore arrivé."}</p>
          ) : (
            <ul className="acc-list">
              {vulns.map((v) => (
                <VulnItem key={v.id} v={v} onPatch={() => onPatch({ deviceIds: [id], cves: [v.cveId], label: `${v.cveId} sur ${d.name}` })} onChange={() => { reload(); onChange(); }} deviceId={id} />
              ))}
            </ul>
          )}
        </>
      )}
      {sub === "logiciels" && <Inventory components={data.components} hardware={data.hardware} vulns={data.vulns} />}
      {sub === "historique" && <History jobs={data.jobs} events={data.events} now={now} />}
      {sub === "reglages" && <DeviceSettings d={d} onDone={() => { reload(); onChange(); }} onDeleted={() => { onChange(); onBack(); }} />}
    </section>
  );
}

function VulnItem({ v, deviceId, onPatch, onChange }: { v: VulnRow; deviceId: number; onPatch: () => void; onChange: () => void }) {
  const { msg, run } = useAction(onChange);
  const ignore = () => {
    const reason = window.prompt(`Pourquoi ignorer ${v.cveId} sur cet équipement ? (conservé dans le journal d’audit)`);
    if (reason) run(() => send("/api/parc/vulns", "PATCH", { cveId: v.cveId, deviceId, action: "ignore", reason }));
  };
  return (
    <li className={`acc-item sev-${v.priority === "urgente" ? "critique" : v.priority}`}>
      <details>
        <summary>
          <span className="sev-dot" />
          <span className="acc-main">
            <span className="acc-email">
              {v.cveId} <PrioTag p={v.priority} /> {v.kev && <span className="tag tag-kev">Exploitée</span>}
              {v.status !== "ouverte" && <span className={`tag ${v.status === "corrigee" ? "tag-good" : ""}`}>{v.status === "corrigee" ? "Corrigée" : "Ignorée"}</span>}
            </span>
            <span className="cti-desc">
              {COMPONENT_LABEL[v.componentKind] ?? v.componentKind} {v.componentName} {v.componentVersion} · {v.fix.kind === "none" ? v.fix.label : `Correctif : ${v.fix.label}${v.fix.fixedVersion ? ` ${v.fix.fixedVersion}` : ""}`}
            </span>
          </span>
          <span className="cti-side">
            <span className="parc-score">{v.score}</span>
            <span className="hint">CVSS {v.cvss ?? "–"}</span>
          </span>
        </summary>
        <div className="acc-detail">
          <ul className="parc-reasons">
            {v.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          <p className="hint">
            Source : {v.source}
            {v.advisory ? ` (${v.advisory})` : ""} · détectée le {new Date(v.firstSeen).toLocaleDateString("fr-FR")}
            {v.epss != null ? ` · EPSS ${(v.epss * 100).toFixed(1)} %` : ""}
            {v.ignoredReason ? ` · ignorée : « ${v.ignoredReason} » (${v.ignoredBy})` : ""}
          </p>
          <div className="watch-actions">
            <a className="btn-plain" href={`/cve/${v.cveId}`}>
              Fiche de la CVE <Icon name="chevron" size={12} />
            </a>
            {v.status === "ouverte" && v.fix.kind !== "none" && (
              <button type="button" className="btn-plain" onClick={onPatch}>
                Corriger maintenant
              </button>
            )}
            {v.status === "ouverte" ? (
              <button type="button" className="btn-plain" onClick={ignore}>
                Ignorer…
              </button>
            ) : v.status === "ignoree" ? (
              <button type="button" className="btn-plain" onClick={() => run(() => send("/api/parc/vulns", "PATCH", { cveId: v.cveId, deviceId, action: "reopen" }))}>
                Rouvrir
              </button>
            ) : null}
          </div>
          <Msg m={msg} />
        </div>
      </details>
    </li>
  );
}

function Inventory({ components, hardware, vulns = [] }: { components: DeviceDetail["components"]; hardware: Record<string, string>; vulns?: DeviceDetail["vulns"] }) {
  const [q, setQ] = useState("");
  // CVE ouvertes par composant (nom + version)
  const byComp = new Map<string, DeviceDetail["vulns"]>();
  for (const v of vulns) {
    if (v.status !== "ouverte") continue;
    const k = `${v.componentName}|${v.componentVersion}`;
    byComp.set(k, [...(byComp.get(k) ?? []), v]);
  }
  const cvesOf = (c: { name: string; version: string }) => (byComp.get(`${c.name.slice(0, 200)}|${c.version.slice(0, 80)}`) ?? []).sort((a, b) => b.score - a.score);
  const groups = ["os", "app", "kb", "package", "driver", "bios"].map((k) => ({ k, items: components.filter((c) => c.kind === k && (!q || `${c.name} ${c.vendor} ${c.version}`.toLowerCase().includes(q.toLowerCase()))) })).filter((g) => g.items.length);
  const hw = [
    ["Constructeur", hardware.manufacturer],
    ["Modèle", hardware.model],
    ["Processeur", hardware.cpu],
    ["Mémoire", hardware.ramMb ? `${Math.round(Number(hardware.ramMb) / 1024)} Go` : ""],
    ["BIOS", [hardware.biosVendor, hardware.biosVersion, hardware.biosDate].filter(Boolean).join(" · ")],
    ["N° de série", hardware.serial],
  ].filter(([, v]) => v);
  return (
    <>
      {hw.length > 0 && (
        <dl className="parc-hw">
          {hw.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      )}
      <label className="search cti-search inv-search">
        <Icon name="search" size={15} />
        <span className="sr-only">Chercher dans l’inventaire</span>
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Chercher un logiciel, un paquet, une mise à jour" />
      </label>
      {groups.map((g) => (
        <details key={g.k} className="parc-group" open={g.k === "os" || g.k === "app" || Boolean(q)}>
          <summary>
            {KIND_LABEL[g.k]} <span className="hint">({g.items.length})</span>
          </summary>
          <div className="parc-table-wrap">
            <table className="parc-table parc-table-compact">
              <tbody>
                {[...g.items]
                  .sort((a, b) => cvesOf(b).length - cvesOf(a).length)
                  .slice(0, 500)
                  .map((c, i) => {
                    const cv = cvesOf(c);
                    return (
                      <tr key={i}>
                        <td>
                          {c.name}
                          {c.catalog && <span className="tag tag-stack parc-cat">suivi</span>}
                        </td>
                        <td className="parc-mono">{c.version}</td>
                        <td className="hint">{c.kind === "package" && c.source !== c.name ? `source ${c.source}` : c.vendor}</td>
                        <td>
                          <span className="inv-cves">
                          {cv.slice(0, 3).map((v) => (
                            <a key={v.cveId} href={`/cve/${v.cveId}`} className={`tag tag-prio ${sevCls(v.cvss)}`} title={`${v.cveId} · CVSS ${v.cvss ?? "?"}${v.kev ? " · exploitée" : ""}`}>
                              {v.cveId}
                              {v.kev ? " ⚠" : ""}
                            </a>
                          ))}
                          {cv.length > 3 && <span className="hint">+{cv.length - 3}</span>}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
            {g.items.length > 500 && <p className="hint">500 premiers sur {g.items.length} : affinez la recherche.</p>}
          </div>
        </details>
      ))}
    </>
  );
}

function History({ jobs, events, now }: { jobs: DeviceDetail["jobs"]; events: DeviceDetail["events"]; now: number }) {
  return (
    <>
      <h3>Tâches</h3>
      {jobs.length === 0 ? (
        <p className="hint">Aucune tâche envoyée à cet équipement.</p>
      ) : (
        <ul className="acc-list">
          {jobs.map((j) => (
            <li key={j.id} className="acc-item">
              <details>
                <summary>
                  <span className="acc-main">
                    <span className="acc-email">
                      {ACTION_LABEL[j.action] ?? j.action} <span className={JOB_STATUS[j.status]?.cls ?? "tag"}>{JOB_STATUS[j.status]?.label ?? j.status}</span>
                      {j.phase === "pilote" && <span className="tag tag-stack">Pilote</span>}
                    </span>
                    <span className="cti-desc">
                      Créée {relTime(j.createdAt, now)}
                      {j.finishedAt ? ` · terminée ${relTime(j.finishedAt, now)}` : j.notBefore && Date.parse(j.notBefore) > now ? ` · prévue le ${new Date(j.notBefore).toLocaleString("fr-FR")}` : ""}
                    </span>
                  </span>
                </summary>
                <div className="acc-detail">{j.log ? <pre className="dw-code parc-log">{j.log}</pre> : <p className="hint">Pas encore de compte rendu.</p>}</div>
              </details>
            </li>
          ))}
        </ul>
      )}
      <h3>Journal</h3>
      <ul className="parc-audit">
        {events.map((e, i) => (
          <li key={i}>
            <span className="hint">{relTime(e.at, now)}</span>
            <span>
              <strong>{AUDIT_LABEL[e.action] ?? e.action}</strong>
            </span>
            <span className="hint parc-actor">{e.actor}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

function DeviceSettings({ d, onDone, onDeleted }: { d: DeviceRow; onDone: () => void; onDeleted: () => void }) {
  const [f, setF] = useState({ name: d.name, groupName: d.groupName, tags: d.tags.join(", "), ring: d.ring });
  const { msg, busy, run } = useAction(onDone);
  return (
    <form
      className="dw-form"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => send("/api/parc/devices", "PATCH", { id: d.id, name: f.name, groupName: f.groupName, tags: f.tags.split(",").map((t) => t.trim()).filter(Boolean), ring: f.ring }));
      }}
    >
      <div className="dw-grid">
        <label className="field">
          <span>Nom affiché</span>
          <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
        </label>
        <label className="field">
          <span>Groupe (site, service…)</span>
          <input value={f.groupName} onChange={(e) => setF({ ...f, groupName: e.target.value })} placeholder="Dakar, Comptabilité…" />
        </label>
        <label className="field">
          <span>Étiquettes (séparées par des virgules)</span>
          <input value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="critique, dmz" />
        </label>
        <label className="field">
          <span>Anneau de déploiement</span>
          <select value={f.ring} onChange={(e) => setF({ ...f, ring: e.target.value })}>
            <option value="production">Production</option>
            <option value="pilote">Pilote (reçoit les correctifs en premier)</option>
          </select>
        </label>
      </div>
      <div className="watch-actions">
        <button type="submit" className="btn-primary watch-add" disabled={busy}>
          Enregistrer
        </button>
        <button
          type="button"
          className="btn-plain parc-danger"
          onClick={() => {
            if (window.confirm(`Supprimer « ${d.name} » ? Sa clé est révoquée et ses données effacées. Désinstallez aussi l’agent sur la machine.`)) {
              send(`/api/parc/devices?id=${d.id}`, "DELETE").then(onDeleted, () => {});
            }
          }}
        >
          Supprimer l’équipement
        </button>
      </div>
      <Msg m={msg} />
    </form>
  );
}

// ---------- Vulnérabilités du parc ----------

function VulnsTab({ onOpen, onPatch }: { onOpen: (id: number) => void; onPatch: (t: { deviceIds: number[]; cves?: string[]; label: string }) => void }) {
  const [status, setStatus] = useState("ouverte");
  const { data, error, loading, reload } = useJson<{ items: FleetVuln[] }>(`/api/parc/vulns?status=${status}`, 0);
  const [q, setQ] = useState("");
  const [prio, setPrio] = useState<"" | Prio>("");
  const [kevOnly, setKevOnly] = useState(false);
  const { msg, run } = useAction(reload);
  const items = (data?.items ?? []).filter((v) => (!prio || v.priority === prio) && (!kevOnly || v.kev) && (!q || `${v.cveId} ${v.components.join(" ")} ${v.devices.map((d) => d.name).join(" ")}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <section className="card tm-panel">
      <div className="hunt-head">
        <h2>Vulnérabilités du parc</h2>
        <div className="segmented" role="group" aria-label="Statut">
          {[
            ["ouverte", "Ouvertes"],
            ["ignoree", "Ignorées"],
            ["corrigee", "Corrigées"],
          ].map(([k, l]) => (
            <button key={k} type="button" aria-pressed={status === k} className={status === k ? "is-on" : ""} onClick={() => setStatus(k)}>
              {l}
            </button>
          ))}
        </div>
      </div>
      <div className="parc-filters">
        <label className="search cti-search">
          <Icon name="search" size={15} />
          <span className="sr-only">Filtrer</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE, logiciel, équipement" />
        </label>
        <select className="parc-select" value={prio} onChange={(e) => setPrio(e.target.value as "" | Prio)} aria-label="Priorité">
          <option value="">Toutes priorités</option>
          {(["urgente", "haute", "moyenne", "basse"] as Prio[]).map((p) => (
            <option key={p} value={p}>
              {PRIO_LABEL[p]}
            </option>
          ))}
        </select>
        <label className="parc-toggle">
          <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> Exploitées (KEV)
        </label>
      </div>
      <Msg m={msg} />
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="callout callout-err">{error}</p>
      ) : items.length === 0 ? (
        <p className="hint">Aucune CVE {status === "ouverte" ? "ouverte" : status === "ignoree" ? "ignorée" : "corrigée"}{q || prio || kevOnly ? " pour ce filtre" : ""}.</p>
      ) : (
        <ul className="acc-list">
          {items.slice(0, 300).map((v) => {
            const ids = [...new Set(v.devices.filter((d) => d.status === "ouverte" && d.fix !== "none").map((d) => d.id))];
            return (
              <li key={v.cveId} className={`acc-item sev-${v.priority === "urgente" ? "critique" : v.priority}`}>
                <details>
                  <summary>
                    <span className="sev-dot" />
                    <span className="acc-main">
                      <span className="acc-email">
                        {v.cveId} <PrioTag p={v.priority} /> {v.kev && <span className="tag tag-kev">Exploitée</span>}
                        {v.ransomware && <span className="tag tag-bad">Rançongiciel</span>}
                      </span>
                      <span className="cti-desc">
                        {v.components.slice(0, 3).join(", ")}
                        {v.components.length > 3 ? "…" : ""} · {v.devices.length} équipement{v.devices.length > 1 ? "s" : ""}
                        {v.fixes.length ? ` · ${v.fixes.slice(0, 2).join(", ")}` : ""}
                      </span>
                    </span>
                    <span className="cti-side">
                      <span className="parc-score">{v.score}</span>
                      <span className="hint">CVSS {v.cvss ?? "–"}</span>
                    </span>
                  </summary>
                  <div className="acc-detail">
                    <ul className="parc-reasons">
                      {v.reasons.map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                    <ul className="dw-sources">
                      {v.devices.map((d) => (
                        <li key={d.vulnId}>
                          <button type="button" className="parc-link" onClick={() => onOpen(d.id)}>
                            <span className="acc-email">{d.name}</span>
                            <span className="cti-desc">
                              {d.component} {d.version}
                            </span>
                          </button>
                          {d.fix === "none" && <span className="hint">Pas de correctif automatique</span>}
                        </li>
                      ))}
                    </ul>
                    <div className="watch-actions">
                      <a className="btn-plain" href={`/cve/${v.cveId}`}>
                        Fiche de la CVE <Icon name="chevron" size={12} />
                      </a>
                      {status === "ouverte" && ids.length > 0 && (
                        <button type="button" className="btn-plain" onClick={() => onPatch({ deviceIds: ids, cves: [v.cveId], label: `${v.cveId} sur ${ids.length} équipement${ids.length > 1 ? "s" : ""}` })}>
                          Corriger sur {ids.length} équipement{ids.length > 1 ? "s" : ""}
                        </button>
                      )}
                      {status === "ouverte" && (
                        <button
                          type="button"
                          className="btn-plain"
                          onClick={() => {
                            const reason = window.prompt(`Pourquoi ignorer ${v.cveId} sur tout le parc ? (conservé dans le journal d’audit)`);
                            if (reason) run(() => send("/api/parc/vulns", "PATCH", { cveId: v.cveId, action: "ignore", reason }).then((r) => ({ message: `${r.count} occurrence(s) ignorée(s).` })));
                          }}
                        >
                          Ignorer sur le parc…
                        </button>
                      )}
                      {status === "ignoree" && (
                        <button type="button" className="btn-plain" onClick={() => run(() => send("/api/parc/vulns", "PATCH", { cveId: v.cveId, action: "reopen" }).then((r) => ({ message: `${r.count} occurrence(s) rouverte(s).` })))}>
                          Rouvrir
                        </button>
                      )}
                    </div>
                  </div>
                </details>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

// ---------- Déploiement manuel ----------

function PatchDialog({ target, onClose, onDone }: { target: { deviceIds: number[]; cves?: string[]; label: string }; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ content: "all", minPriority: target.cves ? "basse" : "haute", kevOnly: false, reboot: "utilisateur", pilot: false, useWindow: false, days: [1, 2, 3, 4, 5, 6, 7], start: "22:00", end: "05:00" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const tz = useMemo(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", []);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await send("/api/parc/deployments", "POST", {
        deviceIds: target.deviceIds,
        cves: target.cves,
        content: f.content,
        minPriority: f.minPriority,
        kevOnly: f.kevOnly,
        reboot: f.reboot,
        pilot: f.pilot,
        window: f.useWindow ? { days: f.days, start: f.start, end: f.end, tz } : null,
      });
      onDone();
    } catch (x) {
      setErr(x instanceof Error ? x.message : "Déploiement impossible");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="parc-modal" role="dialog" aria-modal="true" aria-label="Corriger" onClick={onClose}>
      <form className="card tm-panel dw-form parc-modal-card" onSubmit={submit} onClick={(e) => e.stopPropagation()}>
        <h2>Corriger : {target.label}</h2>
        {target.cves ? <p className="cti-desc">Seul le correctif qui ferme {target.cves.join(", ")} est installé.</p> : null}
        <div className="dw-grid">
          {!target.cves && (
            <>
              <label className="field">
                <span>Contenu</span>
                <select value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })}>
                  <option value="all">Système et applications</option>
                  <option value="os">Système (Windows Update, paquets Linux)</option>
                  <option value="apps">Applications tierces (winget)</option>
                </select>
              </label>
              <label className="field">
                <span>Priorité minimale</span>
                <select value={f.minPriority} onChange={(e) => setF({ ...f, minPriority: e.target.value })}>
                  <option value="urgente">Urgente</option>
                  <option value="haute">Haute et plus</option>
                  <option value="moyenne">Moyenne et plus</option>
                  <option value="basse">Toutes</option>
                </select>
              </label>
            </>
          )}
          <label className="field">
            <span>Redémarrage</span>
            <select value={f.reboot} onChange={(e) => setF({ ...f, reboot: e.target.value })}>
              <option value="utilisateur">Prévenir, puis forcer après 24 h</option>
              <option value="immediat">Immédiat si nécessaire (préavis de 5 min)</option>
              <option value="fenetre">Pendant la fenêtre de maintenance</option>
            </select>
          </label>
        </div>
        {!target.cves && (
          <label className="parc-toggle">
            <input type="checkbox" checked={f.kevOnly} onChange={(e) => setF({ ...f, kevOnly: e.target.checked })} /> Seulement les CVE exploitées (KEV)
          </label>
        )}
        <label className="parc-toggle">
          <input type="checkbox" checked={f.pilot} onChange={(e) => setF({ ...f, pilot: e.target.checked })} /> Passer d’abord par l’anneau pilote
        </label>
        <label className="parc-toggle">
          <input type="checkbox" checked={f.useWindow} onChange={(e) => setF({ ...f, useWindow: e.target.checked })} /> Seulement pendant une fenêtre de maintenance
        </label>
        {f.useWindow && <WindowFields days={f.days} start={f.start} end={f.end} tz={tz} onChange={(w) => setF({ ...f, ...w })} />}
        <p className="hint">Les serveurs ne redémarrent jamais hors fenêtre de maintenance. Une installation en échec déclenche un retour arrière automatique.</p>
        {err && <p className="form-msg form-err">{err}</p>}
        <div className="watch-actions">
          <button type="submit" className="btn-primary watch-add" disabled={busy}>
            {busy ? "Création…" : "Lancer le déploiement"}
          </button>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Annuler
          </button>
        </div>
      </form>
    </div>
  );
}

function WindowFields({ days, start, end, tz, onChange }: { days: number[]; start: string; end: string; tz: string; onChange: (w: { days?: number[]; start?: string; end?: string; tz?: string }) => void }) {
  return (
    <div className="parc-window">
      <div className="chips" role="group" aria-label="Jours">
        {[1, 2, 3, 4, 5, 6, 7].map((d) => (
          <button key={d} type="button" className={`parc-day${days.includes(d) ? " is-on" : ""}`} aria-pressed={days.includes(d)} onClick={() => onChange({ days: days.includes(d) ? days.filter((x) => x !== d) : [...days, d].sort() })}>
            {DAYS[d]}
          </button>
        ))}
      </div>
      <label className="field">
        <span>De</span>
        <input type="time" value={start} onChange={(e) => onChange({ start: e.target.value })} />
      </label>
      <label className="field">
        <span>À</span>
        <input type="time" value={end} onChange={(e) => onChange({ end: e.target.value })} />
      </label>
      <label className="field">
        <span>Fuseau horaire</span>
        <input value={tz} onChange={(e) => onChange({ tz: e.target.value })} />
      </label>
    </div>
  );
}

// ---------- Déploiements ----------

function DeploymentsTab({ deployments, now, onChange }: { deployments: DeploymentRow[]; now: number; onChange: () => void }) {
  const { msg, run } = useAction(onChange);
  const act = (id: number, action: string) => run(() => send("/api/parc/deployments", "PATCH", { id, action }));
  return (
    <section className="card tm-panel">
      <h2>Déploiements</h2>
      <p className="cti-desc">
        Chaque déploiement passe d’abord par l’anneau pilote (si demandé) : un échec y arrête tout et déclenche le retour arrière. Une installation en échec
        est annulée automatiquement ; les CVE ne sont déclarées corrigées qu’après un nouvel inventaire de la machine.
      </p>
      <Msg m={msg} />
      {deployments.length === 0 ? (
        <p className="hint">Aucun déploiement. Lancez-en un depuis un équipement ou une CVE, ou créez une politique.</p>
      ) : (
        <ul className="acc-list">
          {deployments.map((d) => {
            const failed = d.jobs.some((j) => j.action === "install" && j.status === "echec");
            const st = d.status === "termine" && failed ? { label: "Terminé avec échecs", cls: "tag tag-prio p-haute" } : (DEP_STATUS[d.status] ?? { label: d.status, cls: "tag" });
            return (
              <li key={d.id} className="acc-item">
                <details open={d.status === "attente_approbation" || d.status === "pilote"}>
                  <summary>
                    <span className="acc-main">
                      <span className="acc-email">
                        {d.title} <span className={st.cls}>{st.label}</span>
                      </span>
                      <span className="cti-desc">{d.message}</span>
                      <span className="hint">
                        {relTime(d.createdAt, now)} par {d.createdBy ?? "système"} · {d.devices} équipement{d.devices > 1 ? "s" : ""} · {windowText(d.window)}
                        {d.pilot ? ` · pilote (seuil ${d.pilotThreshold} %)` : ""}
                      </span>
                    </span>
                    <span className="cti-side">
                      <Progress jobs={d.jobs} />
                    </span>
                  </summary>
                  <div className="acc-detail">
                    <div className="watch-actions">
                      {d.status === "attente_approbation" && (
                        <button type="button" className="btn-primary watch-add" onClick={() => act(d.id, "approve")}>
                          Approuver et lancer
                        </button>
                      )}
                      {["attente_approbation", "planifie", "pilote", "production"].includes(d.status) && (
                        <button type="button" className="btn-plain parc-danger" onClick={() => window.confirm("Annuler ce déploiement ? Les installations non commencées ne seront pas envoyées.") && act(d.id, "cancel")}>
                          Annuler
                        </button>
                      )}
                      {d.jobs.some((j) => j.action === "install" && j.status === "succes") && (
                        <button type="button" className="btn-plain" onClick={() => window.confirm("Désinstaller les correctifs installés par ce déploiement ?") && act(d.id, "rollback")}>
                          Retour arrière
                        </button>
                      )}
                    </div>
                    {d.jobs.length > 0 && (
                      <div className="parc-table-wrap">
                        <table className="parc-table parc-table-compact">
                          <thead>
                            <tr>
                              <th>Équipement</th>
                              <th>Tâche</th>
                              <th>Phase</th>
                              <th>CVE</th>
                              <th>État</th>
                            </tr>
                          </thead>
                          <tbody>
                            {d.jobs.map((j) => (
                              <tr key={j.id} title={j.log}>
                                <td>{j.device}</td>
                                <td>{ACTION_LABEL[j.action] ?? j.action}</td>
                                <td>{j.phase === "pilote" ? "Pilote" : "Production"}</td>
                                <td>{j.cves || "–"}</td>
                                <td>
                                  <span className={JOB_STATUS[j.status]?.cls ?? "tag"}>{JOB_STATUS[j.status]?.label ?? j.status}</span>
                                  {j.status === "en_attente" && j.notBefore && Date.parse(j.notBefore) > now ? <span className="hint"> · {new Date(j.notBefore).toLocaleString("fr-FR", { weekday: "short", hour: "2-digit", minute: "2-digit" })}</span> : null}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </details>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

// ---------- Politiques ----------

const emptyPolicy = (tz: string) => ({ id: 0, name: "", enabled: true, groups: "", tags: "", os: [] as string[], kinds: [] as string[], content: "all", minPriority: "haute", kevOnly: false, approval: "manuelle", useWindow: true, days: [6, 7], start: "22:00", end: "05:00", tz, reboot: "fenetre", rebootDeferHours: 24, maxParallel: 20, pilot: true, pilotThreshold: 100 });

function PoliciesTab({ policies, devices, onChange }: { policies: Policy[]; devices: DeviceRow[]; onChange: () => void }) {
  const tz = useMemo(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", []);
  const [f, setF] = useState<ReturnType<typeof emptyPolicy> | null>(null);
  const { msg, busy, run } = useAction(onChange);
  const pilots = devices.filter((d) => d.ring === "pilote").length;
  const edit = (p: Policy) =>
    setF({
      id: p.id,
      name: p.name,
      enabled: p.enabled,
      groups: (p.target.groups ?? []).join(", "),
      tags: (p.target.tags ?? []).join(", "),
      os: p.target.os ?? [],
      kinds: p.target.kinds ?? [],
      content: p.content,
      minPriority: p.minPriority,
      kevOnly: p.kevOnly,
      approval: p.approval,
      useWindow: Boolean(p.window),
      days: p.window?.days ?? [6, 7],
      start: p.window?.start ?? "22:00",
      end: p.window?.end ?? "05:00",
      tz: p.window?.tz ?? tz,
      reboot: p.reboot,
      rebootDeferHours: p.rebootDeferHours,
      maxParallel: p.maxParallel,
      pilot: p.pilot,
      pilotThreshold: p.pilotThreshold,
    });
  const save = (e: React.FormEvent) => {
    e.preventDefault();
    if (!f) return;
    const list = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);
    run(async () => {
      const r = await send("/api/parc/policies", "POST", {
        id: f.id || undefined,
        name: f.name,
        enabled: f.enabled,
        target: { groups: list(f.groups), tags: list(f.tags), os: f.os, kinds: f.kinds },
        content: f.content,
        minPriority: f.minPriority,
        kevOnly: f.kevOnly,
        approval: f.approval,
        window: f.useWindow ? { days: f.days, start: f.start, end: f.end, tz: f.tz } : null,
        reboot: f.reboot,
        rebootDeferHours: Number(f.rebootDeferHours),
        maxParallel: Number(f.maxParallel),
        pilot: f.pilot,
        pilotThreshold: Number(f.pilotThreshold),
      });
      setF(null);
      return { message: r.deployments ? `Politique enregistrée : ${r.deployments} déploiement(s) créé(s).` : "Politique enregistrée." };
    });
  };
  const toggleIn = (arr: string[], v: string) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  return (
    <section className="card tm-panel">
      <div className="hunt-head">
        <div>
          <h2>Politiques de correctifs</h2>
          <p className="cti-desc">
            Une politique décide quoi corriger, où, quand et avec quelle approbation. Elle s’applique après chaque inventaire et chaque matin.
            {pilots === 0 ? " Aucun équipement n’est encore dans l’anneau pilote : placez-en un depuis sa fiche (Réglages)." : ` Anneau pilote : ${pilots} équipement${pilots > 1 ? "s" : ""}.`}
          </p>
        </div>
        {!f && (
          <button type="button" className="btn-primary watch-add" onClick={() => setF(emptyPolicy(tz))}>
            Nouvelle politique
          </button>
        )}
      </div>
      <Msg m={msg} />
      {f && (
        <form className="dw-form verify-box parc-policy" onSubmit={save}>
          <div className="dw-grid">
            <label className="field">
              <span>Nom</span>
              <input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Serveurs : correctifs critiques le week-end" />
            </label>
            <label className="field">
              <span>Groupes visés (vide = tous)</span>
              <input value={f.groups} onChange={(e) => setF({ ...f, groups: e.target.value })} placeholder="Dakar, Comptabilité" />
            </label>
            <label className="field">
              <span>Étiquettes visées (vide = toutes)</span>
              <input value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="critique" />
            </label>
            <label className="field">
              <span>Contenu</span>
              <select value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })}>
                <option value="all">Système et applications</option>
                <option value="os">Système seulement</option>
                <option value="apps">Applications seulement</option>
              </select>
            </label>
            <label className="field">
              <span>Priorité minimale</span>
              <select value={f.minPriority} onChange={(e) => setF({ ...f, minPriority: e.target.value })}>
                <option value="urgente">Urgente</option>
                <option value="haute">Haute et plus</option>
                <option value="moyenne">Moyenne et plus</option>
                <option value="basse">Toutes</option>
              </select>
            </label>
            <label className="field">
              <span>Approbation</span>
              <select value={f.approval} onChange={(e) => setF({ ...f, approval: e.target.value })}>
                <option value="manuelle">Manuelle (un administrateur approuve)</option>
                <option value="auto">Automatique</option>
              </select>
            </label>
            <label className="field">
              <span>Redémarrage</span>
              <select value={f.reboot} onChange={(e) => setF({ ...f, reboot: e.target.value })}>
                <option value="fenetre">Pendant la fenêtre</option>
                <option value="utilisateur">Prévenir l’utilisateur, puis forcer</option>
                <option value="immediat">Immédiat (préavis de 5 min)</option>
              </select>
            </label>
            <label className="field">
              <span>Délai avant redémarrage forcé (heures)</span>
              <input type="number" min={1} max={168} value={f.rebootDeferHours} onChange={(e) => setF({ ...f, rebootDeferHours: Number(e.target.value) })} />
            </label>
            <label className="field">
              <span>Équipements en parallèle</span>
              <input type="number" min={1} max={500} value={f.maxParallel} onChange={(e) => setF({ ...f, maxParallel: Number(e.target.value) })} />
            </label>
            <label className="field">
              <span>Seuil de réussite du pilote (%)</span>
              <input type="number" min={1} max={100} value={f.pilotThreshold} disabled={!f.pilot} onChange={(e) => setF({ ...f, pilotThreshold: Number(e.target.value) })} />
            </label>
          </div>
          <div className="chips">
            {[
              ["windows", "Windows"],
              ["linux", "Linux"],
            ].map(([k, l]) => (
              <label key={k} className="parc-toggle">
                <input type="checkbox" checked={f.os.includes(k)} onChange={() => setF({ ...f, os: toggleIn(f.os, k) })} /> {l}
              </label>
            ))}
            {[
              ["poste", "Postes"],
              ["serveur", "Serveurs"],
            ].map(([k, l]) => (
              <label key={k} className="parc-toggle">
                <input type="checkbox" checked={f.kinds.includes(k)} onChange={() => setF({ ...f, kinds: toggleIn(f.kinds, k) })} /> {l}
              </label>
            ))}
            <label className="parc-toggle">
              <input type="checkbox" checked={f.kevOnly} onChange={(e) => setF({ ...f, kevOnly: e.target.checked })} /> Seulement KEV
            </label>
            <label className="parc-toggle">
              <input type="checkbox" checked={f.pilot} onChange={(e) => setF({ ...f, pilot: e.target.checked })} /> Anneau pilote d’abord
            </label>
            <label className="parc-toggle">
              <input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Active
            </label>
          </div>
          <label className="parc-toggle">
            <input type="checkbox" checked={f.useWindow} onChange={(e) => setF({ ...f, useWindow: e.target.checked })} /> Fenêtre de maintenance
          </label>
          {f.useWindow && <WindowFields days={f.days} start={f.start} end={f.end} tz={f.tz} onChange={(w) => setF({ ...f, ...w })} />}
          <div className="watch-actions">
            <button type="submit" className="btn-primary watch-add" disabled={busy || !f.name.trim()}>
              Enregistrer
            </button>
            <button type="button" className="btn-secondary" onClick={() => setF(null)}>
              Annuler
            </button>
          </div>
        </form>
      )}
      {policies.length === 0 && !f ? (
        <p className="hint">Aucune politique : les correctifs ne sont déployés que sur demande.</p>
      ) : (
        <ul className="dw-sources">
          {policies.map((p) => (
            <li key={p.id} className={p.enabled ? "" : "is-off"}>
              <span className="acc-main">
                <span className="acc-email">
                  {p.name} {p.approval === "auto" ? <span className="tag tag-stack">Automatique</span> : <span className="tag">Approbation manuelle</span>}
                  {!p.enabled && <span className="tag">Désactivée</span>}
                </span>
                <span className="cti-desc">
                  {PRIO_LABEL[p.minPriority]} et plus{p.kevOnly ? " (KEV)" : ""} · {p.content === "os" ? "système" : p.content === "apps" ? "applications" : "système et applications"} ·{" "}
                  {[...(p.target.os ?? []), ...(p.target.kinds ?? []), ...(p.target.groups ?? []), ...(p.target.tags ?? []).map((t) => `#${t}`)].join(", ") || "tout le parc"} · {windowText(p.window)}
                  {p.pilot ? ` · pilote ${p.pilotThreshold} %` : ""}
                </span>
              </span>
              <button type="button" className="btn-plain" onClick={() => edit(p)}>
                Modifier
              </button>
              <button type="button" className="btn-plain parc-danger" onClick={() => window.confirm(`Supprimer la politique « ${p.name} » ?`) && run(() => send(`/api/parc/policies?id=${p.id}`, "DELETE").then(() => ({ message: "Politique supprimée." })))}>
                Supprimer
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ---------- Logiciels ----------

interface SoftwareRow {
  kind: string;
  name: string;
  version: string;
  vendor: string;
  n: number;
  catalog: string | null;
  tracking: "systeme" | "catalogue" | "auto" | "manuel" | "aucun" | "ignore" | "en_attente";
  cpe: { vendor: string; product: string; title: string; confidence: number } | null;
  vulns: { cves: number; kev: number; urgent: number; maxCvss: number | null; maxScore: number; devices: number } | null;
}
interface SoftwareCve {
  cveId: string;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  ransomware: boolean;
  score: number;
  priority: string;
  fix: { label?: string; fixedVersion?: string | null; kind?: string };
  advisory: string;
  source: string;
  open: number;
  fixed: number;
  ignored: number;
}

const TRACKING: Record<SoftwareRow["tracking"], { label: string; help: string; cls: string }> = {
  systeme: { label: "Système", help: "CVE du système recherchées via la NVD ou les avis de la distribution.", cls: "tag" },
  catalogue: { label: "Suivi", help: "Logiciel du catalogue : CVE et mise à jour automatique.", cls: "tag tag-stack" },
  auto: { label: "Auto", help: "Produit NVD trouvé automatiquement.", cls: "tag" },
  manuel: { label: "Choisi", help: "Produit NVD choisi par votre organisation.", cls: "tag tag-stack" },
  aucun: { label: "Non référencé", help: "Aucun produit correspondant dans la NVD : pas de CVE publique connue sous ce nom.", cls: "tag" },
  ignore: { label: "Ignoré", help: "Logiciel ignoré par votre organisation.", cls: "tag" },
  en_attente: { label: "En analyse", help: "Recherche du produit NVD au prochain passage (chaque jour).", cls: "tag" },
};

const sevCls = (cvss: number | null | undefined) => (cvss == null ? "" : cvss >= 9 ? "p-urgente" : cvss >= 7 ? "p-haute" : cvss >= 4 ? "p-moyenne" : "p-basse");

function SoftwareTab() {
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const [vulnOnly, setVulnOnly] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    const t = setTimeout(() => setTerm(q), 300);
    return () => clearTimeout(t);
  }, [q]);
  const { data, error, loading, reload } = useJson<{ items: SoftwareRow[] }>(`/api/parc/software?q=${encodeURIComponent(term)}${vulnOnly ? "&vulnerables=1" : ""}`, 0);
  const items = data?.items ?? [];
  const totals = items.reduce((a, s) => ({ cves: a.cves + (s.vulns?.cves ?? 0), kev: a.kev + (s.vulns?.kev ?? 0) }), { cves: 0, kev: 0 });
  return (
    <section className="card tm-panel">
      <h2>Logiciels du parc</h2>
      <p className="cti-desc">
        Chaque logiciel installé est relié à son produit dans la base NVD pour retrouver ses CVE, même hors du catalogue suivi. Dépliez une ligne pour voir
        ses vulnérabilités, les équipements touchés et la version corrigée.
      </p>
      <div className="sw-tools">
        <label className="search cti-search">
          <Icon name="search" size={15} />
          <span className="sr-only">Chercher</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="openssl, chrome, zoom, KB5036892…" />
        </label>
        <div className="segmented" role="group" aria-label="Filtre">
          <button type="button" aria-pressed={vulnOnly} className={vulnOnly ? "is-on" : ""} onClick={() => setVulnOnly(true)}>
            Vulnérables
          </button>
          <button type="button" aria-pressed={!vulnOnly} className={!vulnOnly ? "is-on" : ""} onClick={() => setVulnOnly(false)}>
            Tous
          </button>
        </div>
      </div>
      {vulnOnly && items.length > 0 && (
        <p className="hint">
          {items.length} logiciel{items.length > 1 ? "s" : ""} vulnérable{items.length > 1 ? "s" : ""} · {totals.cves} CVE ouvertes
          {totals.kev ? ` · ${totals.kev} exploitée${totals.kev > 1 ? "s" : ""} activement` : ""}
        </p>
      )}
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="callout callout-err">{error}</p>
      ) : (
        <div className="parc-table-wrap">
          <table className="parc-table sw-table">
            <thead>
              <tr>
                <th>Logiciel</th>
                <th>Version</th>
                <th>Équipements</th>
                <th>Vulnérabilités</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => {
                const k = `${s.kind}|${s.name}|${s.version}`;
                const isOpen = open === k;
                const t = TRACKING[s.tracking];
                return (
                  <Fragment key={k}>
                    <tr className={`sw-row${isOpen ? " is-open" : ""}`} onClick={() => setOpen(isOpen ? null : k)}>
                      <td>
                        <button type="button" className="sw-toggle" aria-expanded={isOpen} aria-label={`${isOpen ? "Replier" : "Déplier"} ${s.name}`} onClick={(e) => (e.stopPropagation(), setOpen(isOpen ? null : k))}>
                          <span className={`sw-caret${isOpen ? " is-open" : ""}`} aria-hidden="true">
                            ›
                          </span>
                        </button>
                        <span className="sw-name">{s.name}</span>
                        <span className={`${t.cls} parc-cat`} title={t.help}>
                          {s.catalog ?? t.label}
                        </span>
                        {s.vendor && <span className="hint parc-sub">{s.vendor}</span>}
                      </td>
                      <td className="parc-mono">{s.version || "—"}</td>
                      <td>{s.vulns ? `${s.vulns.devices} / ${s.n}` : s.n}</td>
                      <td>
                        {s.vulns ? (
                          <span className="sw-badges">
                            <span className={`tag tag-prio ${sevCls(s.vulns.maxCvss)}`}>
                              {s.vulns.cves} CVE{s.vulns.maxCvss != null ? ` · ${s.vulns.maxCvss.toFixed(1)}` : ""}
                            </span>
                            {s.vulns.kev > 0 && <span className="tag tag-kev">{s.vulns.kev} exploitée{s.vulns.kev > 1 ? "s" : ""}</span>}
                          </span>
                        ) : (
                          <span className="hint">{s.tracking === "aucun" || s.tracking === "ignore" || s.tracking === "en_attente" ? t.label : "Aucune"}</span>
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="sw-detail">
                        <td colSpan={4}>
                          <SoftwareDetail s={s} onChange={reload} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {items.length === 0 && <p className="hint">{vulnOnly ? "Aucun logiciel vulnérable détecté. Affichez « Tous » pour voir l’inventaire complet." : "Aucun résultat."}</p>}
        </div>
      )}
    </section>
  );
}

/** CVE d'un logiciel et correspondance avec la NVD (corrigeable par un administrateur). */
function SoftwareDetail({ s, onChange }: { s: SoftwareRow; onChange: () => void }) {
  const [allVersions, setAllVersions] = useState(false);
  const { data, error, loading, reload } = useJson<{ items: SoftwareCve[] }>(`/api/parc/software/cves?nom=${encodeURIComponent(s.name)}${allVersions ? "" : `&version=${encodeURIComponent(s.version)}`}`, 0);
  const [edit, setEdit] = useState(false);
  const [f, setF] = useState({ vendor: s.cpe?.vendor ?? "", product: s.cpe?.product ?? "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const act = async (body: Record<string, unknown>, method: "PUT" | "POST", ok: string) => {
    setBusy(true);
    setMsg(null);
    try {
      const j = await send("/api/parc/software/correspondance", method, body);
      setMsg({ ok: true, text: method === "POST" ? (j.mapping?.vendor ? `Produit trouvé : ${j.mapping.title || `${j.mapping.vendor} ${j.mapping.product}`} (${j.mapping.confidence} %).` : "Aucun produit NVD ne correspond avec assez de certitude : vous pouvez l’indiquer vous-même.") : ok });
      setEdit(false);
      reload();
      onChange();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Échec." });
    } finally {
      setBusy(false);
    }
  };
  const list = data?.items ?? [];
  return (
    <div className="sw-panel">
      {s.kind === "app" && (
        <div className="sw-map">
          <span className="hint">
            {s.tracking === "catalogue"
              ? `Catalogue suivi : CVE et mise à jour automatique (${s.catalog}).`
              : s.cpe
                ? `Produit NVD : ${s.cpe.title || s.cpe.product} (cpe ${s.cpe.vendor}:${s.cpe.product}) · ${s.tracking === "manuel" ? "choisi par votre organisation" : `correspondance automatique ${s.cpe.confidence} %`}`
                : TRACKING[s.tracking].help}
          </span>
          <span className="sw-map-actions">
            {(s.tracking === "en_attente" || s.tracking === "aucun") && (
              <button type="button" className="btn-link" disabled={busy} onClick={() => act({ name: s.name, publisher: s.vendor }, "POST", "")}>
                {busy ? "Recherche…" : "Rechercher maintenant"}
              </button>
            )}
            <button type="button" className="btn-link" onClick={() => setEdit(!edit)}>
              Corriger la correspondance
            </button>
            {s.tracking !== "ignore" ? (
              <button type="button" className="btn-link btn-link-danger" disabled={busy} onClick={() => window.confirm(`Ignorer « ${s.name} » ? Ses CVE ne seront plus recherchées.`) && act({ name: s.name, ignore: true }, "PUT", "Logiciel ignoré.")}>
                Ignorer
              </button>
            ) : null}
            {(s.tracking === "manuel" || s.tracking === "ignore") && (
              <button type="button" className="btn-link" disabled={busy} onClick={() => act({ name: s.name, reset: true }, "PUT", "Correspondance automatique rétablie.")}>
                Rétablir l’automatique
              </button>
            )}
          </span>
        </div>
      )}
      {edit && (
        <form
          className="sw-edit"
          onSubmit={(e) => {
            e.preventDefault();
            void act({ name: s.name, vendor: f.vendor, product: f.product }, "PUT", "Correspondance enregistrée : CVE recalculées.");
          }}
        >
          <label className="field">
            <span>Éditeur (CPE)</span>
            <input required value={f.vendor} onChange={(e) => setF({ ...f, vendor: e.target.value })} placeholder="zoom" spellCheck={false} />
          </label>
          <label className="field">
            <span>Produit (CPE)</span>
            <input required value={f.product} onChange={(e) => setF({ ...f, product: e.target.value })} placeholder="workplace_desktop" spellCheck={false} />
          </label>
          <button type="submit" className="btn-secondary btn-sm" disabled={busy}>
            Enregistrer
          </button>
          <span className="hint sw-edit-help">
            Valeurs de la NVD, visibles dans l’identifiant CPE d’une CVE du produit : cpe:2.3:a:<b>éditeur</b>:<b>produit</b>:…
          </span>
        </form>
      )}
      {msg && <p className={`form-msg ${msg.ok ? "form-ok" : "form-err"}`}>{msg.text}</p>}
      <label className="parc-toggle">
        <input type="checkbox" checked={allVersions} onChange={(e) => setAllVersions(e.target.checked)} /> Toutes les versions de ce logiciel dans le parc
      </label>
      {loading && !data ? (
        <Skeleton />
      ) : error ? (
        <p className="callout callout-err">{error}</p>
      ) : !list.length ? (
        <p className="hint">Aucune CVE connue pour {allVersions ? "ce logiciel" : "cette version"}.</p>
      ) : (
        <table className="parc-table parc-table-compact sw-cves">
          <thead>
            <tr>
              <th>CVE</th>
              <th>CVSS</th>
              <th>EPSS</th>
              <th>Correctif</th>
              <th>Équipements</th>
            </tr>
          </thead>
          <tbody>
            {list.map((c) => (
              <tr key={c.cveId}>
                <td>
                  <a href={`/cve/${c.cveId}`} className="parc-mono">
                    {c.cveId}
                  </a>
                  {c.kev && <span className="tag tag-kev parc-cat">Exploitée</span>}
                  {c.ransomware && <span className="tag tag-bad parc-cat">Rançongiciel</span>}
                </td>
                <td>
                  <span className={`tag tag-prio ${sevCls(c.cvss)}`}>{c.cvss != null ? c.cvss.toFixed(1) : "—"}</span>
                </td>
                <td className="hint">{c.epss != null ? `${(c.epss * 100).toFixed(1)} %` : "—"}</td>
                <td className="hint">{c.fix?.fixedVersion ? `version ${c.fix.fixedVersion}` : (c.fix?.label ?? "—")}</td>
                <td>
                  {c.open > 0 ? <strong>{c.open} vulnérable{c.open > 1 ? "s" : ""}</strong> : <span className="hint">0 vulnérable</span>}
                  {c.fixed > 0 && <span className="hint"> · {c.fixed} corrigé{c.fixed > 1 ? "s" : ""}</span>}
                  {c.ignored > 0 && <span className="hint"> · {c.ignored} ignoré{c.ignored > 1 ? "s" : ""}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------- Installation de l'agent ----------

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="icon-btn ioc-copy"
      aria-label="Copier"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      <Icon name={done ? "check" : "copy"} size={14} />
    </button>
  );
}

function AgentTab({ agentVersion, onChange }: { agentVersion: string; onChange: () => void }) {
  const { data, loading, error, reload, setData } = useJson<Kit>("/api/parc/enroll", 0);
  const [os, setOs] = useState<"windows" | "linux">("windows");
  const { msg, busy, run } = useAction(onChange);
  if (loading && !data) return <Skeleton />;
  if (error && !data) return <p className="callout callout-err">{error}</p>;
  const create = () =>
    run(async () => {
      const k = (await send("/api/parc/enroll", "POST")) as Kit;
      setData(k);
      return { message: data?.token ? "Nouveau jeton créé : l’ancien installeur ne fonctionne plus (les équipements déjà enrôlés ne sont pas touchés)." : "Jeton créé." };
    });
  const lines: ReactNode[] = (data?.commands?.[os] ?? []).map((c, i) =>
    c.endsWith(":") || c.startsWith("Déploiement") ? (
      <p key={i} className="hint">
        {c}
      </p>
    ) : (
      <div key={i} className="parc-cmd">
        <code>{c}</code>
        <Copy text={c} />
      </div>
    ),
  );
  return (
    <section className="card tm-panel">
      <h2>
        <Icon name="wrench" size={16} /> Installer l’agent
      </h2>
      <p className="cti-desc">
        L’agent (version {agentVersion}) tourne sous SYSTEM ou root, ne communique qu’en sortie (HTTPS 443) et signe chaque échange avec la clé de sa machine. Il
        n’exécute que des actions prédéfinies (inventaire, mises à jour, retour arrière, redémarrage) et refuse toute tâche non signée. Il se met à jour tout
        seul.
      </p>
      {!data?.token ? (
        <div className="watch-actions">
          <button type="button" className="btn-primary watch-add" disabled={busy} onClick={create}>
            Créer le jeton d’enrôlement
          </button>
        </div>
      ) : (
        <>
          <div className="segmented" role="group" aria-label="Système">
            <button type="button" aria-pressed={os === "windows"} className={os === "windows" ? "is-on" : ""} onClick={() => setOs("windows")}>
              Windows
            </button>
            <button type="button" aria-pressed={os === "linux"} className={os === "linux" ? "is-on" : ""} onClick={() => setOs("linux")}>
              Linux
            </button>
          </div>
          <div className="parc-cmds">{lines}</div>
          <div className="watch-actions">
            <a className="btn-secondary parc-dl" href={data.installers?.[os]} download>
              <Icon name="file" size={14} /> Télécharger {os === "windows" ? "vigilantiq-agent.ps1" : "vigilantiq-agent.py"}
            </a>
          </div>
          <p className="hint">
            {os === "windows"
              ? "Windows 10, 11 et Server 2016 à 2025. Correctifs système par Windows Update ; applications tierces par winget (Windows 10 1809 et plus)."
              : "Debian 11 à 13, Ubuntu 20.04 à 24.04, RHEL, Rocky et AlmaLinux 8 et 9. Correctifs par apt ou dnf."}
          </p>
          <details className="parc-group">
            <summary>Jeton d’enrôlement</summary>
            <p className="cti-desc">
              Créé le {data.createdAt ? new Date(data.createdAt).toLocaleDateString("fr-FR") : "?"}. Il permet d’ajouter des machines à votre parc : ne le
              publiez pas. Le renouveler invalide les installeurs déjà téléchargés, sans toucher aux équipements enrôlés.
            </p>
            <div className="parc-cmd">
              <code>{data.token}</code>
              <Copy text={data.token} />
            </div>
            <div className="watch-actions">
              <button type="button" className="btn-plain" disabled={busy} onClick={() => window.confirm("Renouveler le jeton ? Les installeurs déjà téléchargés ne fonctionneront plus.") && create()}>
                Renouveler
              </button>
              <button
                type="button"
                className="btn-plain parc-danger"
                disabled={busy}
                onClick={() =>
                  window.confirm("Révoquer le jeton ? Plus aucune machine ne pourra être ajoutée jusqu’à la création d’un nouveau jeton.") &&
                  run(async () => {
                    await send("/api/parc/enroll", "DELETE");
                    await reload();
                    return { message: "Jeton révoqué." };
                  })
                }
              >
                Révoquer
              </button>
            </div>
          </details>
        </>
      )}
      <Msg m={msg} />
    </section>
  );
}
