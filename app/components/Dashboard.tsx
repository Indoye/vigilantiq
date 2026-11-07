"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { cvssFr, dateFr, pct, productName, relTime, timeFr } from "@/lib/format";
import { PRIORITY_LABEL, PRIORITY_ORDER } from "@/lib/score";
import { matchStack, parseStack } from "@/lib/stack";
import type { Feed, FeedKind, Priority, RssItem, RssSnapshot, Vuln } from "@/lib/types";
import { affectedSummary } from "@/lib/versions";
import { byDeadline, deadlineOf, type Deadline } from "@/lib/deadlines";
import CatalogSearch from "./CatalogSearch";
import Onboarding from "./Onboarding";
import CommandPalette from "./CommandPalette";
import DeadlinesView, { DueChip, type DueItem } from "./DeadlinesView";
import { OtherPocCves } from "./Integrations";
import { AppearanceSegmented } from "./Appearance";
import { BrandName, LogoMark } from "./Logo";
import BreachesView from "./cti/BreachesView";
import IocView from "./cti/IocView";
import LeakQualifyView from "./cti/LeakQualifyView";
import DarkwebMonitorView from "./cti/DarkwebMonitorView";
import HuntView from "./hunt/HuntView";
import PatchView from "./patch/PatchView";
import RansomwareView from "./cti/RansomwareView";
import WatchView from "./cti/WatchView";
import ThreatMap from "./ThreatMap";
import { Icon, PRIO_CLASS, Ring } from "./ui";
import UserMenu from "./UserMenu";
import { isClosed, roleAtLeast, STATUS_LABEL, useMe, type CveStatusValue } from "./useMe";

type View = "today" | "echeances" | "kev" | "poc" | "stack" | "suivi" | "live" | "map" | "rw" | "fuites" | "ioc" | "veille" | "hunt" | "analyse" | "parc" | "darkweb";
const WIDE: View[] = ["echeances", "map", "rw", "fuites", "ioc", "veille", "darkweb", "hunt", "analyse", "parc"];
const VIEW_PARAM: Record<string, View> = {
  aujourdhui: "today",
  echeances: "echeances",
  exploitees: "kev",
  poc: "poc",
  stack: "stack",
  "en-cours": "suivi",
  direct: "live",
  threatmap: "map",
  ransomware: "rw",
  fuites: "fuites",
  ioc: "ioc",
  surveillance: "veille",
  "dark-web": "darkweb",
  "threat-hunting": "hunt",
  qualification: "analyse",
  parc: "parc",
};
const PARAM_OF = Object.fromEntries(Object.entries(VIEW_PARAM).map(([k, v]) => [v, k])) as Record<View, string>;
type Seg = "all" | Priority;
type KindSeg = "all" | "alertes" | "editeur" | "exploit" | "cve";

const KIND_LABEL: Record<FeedKind, string> = { cert: "CERT", gouv: "Agence", editeur: "Éditeur", exploit: "Exploit", cve: "Nouvelle CVE" };
const POLL_MS = 60_000;
/** Au-delà de ce retard sur l'échéance CISA, une faille n'apparaît plus que dans les résultats de recherche. */
const STALE_DAYS = 30;

/** Code d'exploitation public connu : dépôt PoC, Exploit-DB, ou SSVC « poc ». */
function hasPoc(v: Vuln): boolean {
  return (v.exploits?.length ?? 0) > 0 || v.mentions.some((m) => m.kind === "exploit") || v.ssvc?.exploitation === "poc";
}

export default function Dashboard({ feed, initialRss }: { feed: Feed; initialRss: RssSnapshot }) {
  const router = useRouter();
  const [view, setViewState] = useState<View>("today");
  // L'onglet est gardé dans l'adresse : le retour depuis la fiche d'une CVE revient au même onglet.
  const setView = useCallback((v: View) => {
    setViewState(v);
    const url = new URL(window.location.href);
    if (v === "today") url.searchParams.delete("vue");
    else url.searchParams.set("vue", PARAM_OF[v]);
    window.history.replaceState(window.history.state, "", url.pathname + url.search);
  }, []);
  const [ctiUnread, setCtiUnread] = useState(0);
  // Lien direct vers un onglet (?vue=surveillance, depuis l'e-mail d'alerte par exemple)
  useEffect(() => {
    const v = VIEW_PARAM[new URLSearchParams(window.location.search).get("vue") ?? ""];
    if (v) setViewState(v);
  }, []);
  const [seg, setSeg] = useState<Seg>("all");
  const [kindSeg, setKindSeg] = useState<KindSeg>("all");
  const [query, setQuery] = useState("");
  const [palette, setPalette] = useState(false);
  const [iocQuery, setIocQuery] = useState("");
  // ⌘K / Ctrl+K partout, « / » hors d'un champ de saisie
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement)?.tagName ?? "") || (e.target as HTMLElement)?.isContentEditable;
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPalette((p) => !p);
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const { me, setMe, guest, statuses, error: meError, saving, setStatus, saveSettings } = useMe(null, { guestOk: true });
  // ---------- Responsables et actions groupées ----------
  const [owners, setOwners] = useState<Record<string, { userId: string; name: string }>>({});
  const [myId, setMyId] = useState<string | null>(null);
  const [selecting, setSelecting] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [members, setMembers] = useState<{ userId: string; name: string }[]>([]);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);
  const meKey = me?.org?.id;
  useEffect(() => {
    if (!meKey) return;
    fetch("/api/me/assignations", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (j) {
          setOwners(j.items ?? {});
          setMyId(j.me ?? null);
        }
      })
      .catch(() => undefined);
  }, [meKey]);
  const startSelecting = () => {
    setSelecting(true);
    setPicked(new Set());
    if (!members.length)
      fetch("/api/org", { cache: "no-store" })
        .then((r) => (r.ok ? r.json() : null))
        .then((j) => j && setMembers((j.members ?? []).map((m: { userId: string; name: string; email: string }) => ({ userId: m.userId, name: m.name || m.email }))))
        .catch(() => undefined);
  };
  const togglePick = (id: string) =>
    setPicked((p) => {
      const n = new Set(p);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const bulkStatus = async (status: CveStatusValue) => {
    const ids = [...picked];
    const r = await fetch("/api/me/status", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cveIds: ids, status }) }).catch(() => null);
    if (!r?.ok) return setBulkMsg("Échec de la mise à jour groupée.");
    setMe((m) => {
      if (!m) return m;
      const st = { ...m.statuses };
      for (const id of ids) {
        if (status === "a_traiter") delete st[id];
        else st[id] = status;
      }
      return { ...m, statuses: st };
    });
    setBulkMsg(`${ids.length} vulnérabilité${ids.length > 1 ? "s" : ""} : ${STATUS_LABEL[status].toLowerCase()}.`);
    setSelecting(false);
    setPicked(new Set());
  };
  const bulkAssign = async (assigneeId: string | null) => {
    const ids = [...picked];
    const r = await fetch("/api/me/assignations", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cveIds: ids, assigneeId }) }).catch(() => null);
    const j = r?.ok ? await r.json() : null;
    if (!j) return setBulkMsg("Échec de l’assignation.");
    setOwners(j.items ?? {});
    setBulkMsg(`${ids.length} vulnérabilité${ids.length > 1 ? "s" : ""} ${assigneeId ? `assignée${ids.length > 1 ? "s" : ""} à ${members.find((m) => m.userId === assigneeId)?.name ?? "ce membre"}` : "sans responsable"}.`);
    setSelecting(false);
    setPicked(new Set());
  };
  useEffect(() => {
    if (!bulkMsg) return;
    const t = window.setTimeout(() => setBulkMsg(null), 4000);
    return () => window.clearTimeout(t);
  }, [bulkMsg]);
  const meId = me?.user.id;
  useEffect(() => {
    if (!meId) return;
    fetch("/api/cti/watch", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j: { alerts?: { seen: boolean }[] } | null) => j?.alerts && setCtiUnread(j.alerts.filter((a) => !a.seen).length))
      .catch(() => {});
  }, [meId]);
  const personal = me?.settings.stack ?? "";
  /** Opérateur de la plateforme (VIGILANTIQ_ANALYSTS) : seul à voir les détails techniques (clés, flux en erreur). */
  const operator = Boolean(me?.features.analyst);
  const setPersonal = (v: string) => saveSettings({ stack: v });
  const statusOf = (id: string) => statuses[id] ?? "a_traiter";
  const [sortBy, setSortBy] = useState<"score" | "echeance">("score");
  const [showDone, setShowDone] = useState(false);
  // Échéances du catalogue CISA hors du flux du jour (failles ajoutées il y a plusieurs jours)
  const [kevDue, setKevDue] = useState<{ id: string; vendor: string; product: string; dueDate: string; ransomware: boolean }[]>([]);
  const [kevDueError, setKevDueError] = useState<string | null>(null);
  useEffect(() => {
    fetch("/api/echeances")
      .then(async (r) => {
        const j = await r.json();
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        setKevDue(j.items ?? []);
      })
      .catch((e: Error) => setKevDueError(`Échéances CISA partielles : ${e.message}`));
  }, []);
  const [editingStack, setEditingStack] = useState(false);
  const [now, setNow] = useState(() => Date.parse(feed.generatedAt));

  // ---------- flux RSS en direct ----------
  const [rss, setRss] = useState<RssSnapshot>(initialRss);
  const [lastSeen, setLastSeen] = useState<number>(() => Date.parse(initialRss.fetchedAt) || Date.now());
  const [checking, setChecking] = useState(false);

  const poll = useCallback(async () => {
    setChecking(true);
    try {
      const res = await fetch("/api/rss", { cache: "no-store" });
      if (res.ok) setRss(await res.json());
    } catch {
      /* réseau indisponible : on réessaiera */
    } finally {
      setChecking(false);
      setNow(Date.now());
    }
  }, []);

  useEffect(() => {
    setNow(Date.now());
    const tick = () => document.visibilityState === "visible" && poll();
    const id = setInterval(tick, POLL_MS);
    document.addEventListener("visibilitychange", tick);
    return () => {
      clearInterval(id);
      document.removeEventListener("visibilitychange", tick);
    };
  }, [poll]);

  const newItems = rss.items.filter((it) => it.published && Date.parse(it.published) > lastSeen).length;
  useEffect(() => {
    if (view === "live") setLastSeen(Date.now());
  }, [view, rss]);

  // ---------- données ----------
  const stack = useMemo(() => parseStack(personal), [personal]);
  const vulns = useMemo(() => feed.vulns.map((v) => ({ ...v, matches: matchStack(v, stack) })), [feed.vulns, stack]);
  const byId = useMemo(() => new Map(vulns.map((v) => [v.id, v])), [vulns]);
  const deadlines = useMemo(() => new Map<string, Deadline | null>(vulns.map((v) => [v.id, deadlineOf(v, now)])), [vulns, now]);
  const dueItems: DueItem[] = useMemo(() => {
    const out: DueItem[] = [];
    for (const v of vulns) {
      const d = deadlines.get(v.id);
      if (!d || d.daysLeft > 45 || d.daysLeft < -30) continue;
      out.push({ id: v.id, product: productName(v), deadline: d, priority: v.priority, exploited: Boolean(v.kev || v.ssvc?.exploitation === "active"), ransomware: Boolean(v.kev?.ransomware), status: statusOf(v.id), inFeed: true });
    }
    for (const k of kevDue) {
      if (byId.has(k.id)) continue;
      const d = deadlineOf({ priority: "urgente", published: k.dueDate, kev: { dueDate: k.dueDate } }, now);
      if (!d) continue;
      out.push({ id: k.id, product: [k.vendor, k.product].filter(Boolean).join(" ") || k.id, deadline: d, priority: null, exploited: true, ransomware: k.ransomware, status: statusOf(k.id), inFeed: false });
    }
    return out.sort((a, b) => byDeadline(a.deadline, b.deadline));
  }, [vulns, deadlines, kevDue, byId, now, statuses]); // eslint-disable-line react-hooks/exhaustive-deps
  const openDue = dueItems.filter((i) => i.status !== "traitee" && i.status !== "non_concernee");
  const dueSoon = openDue.filter((i) => i.deadline.daysLeft <= 7);
  const dueHot = openDue.filter((i) => i.deadline.daysLeft <= 2).length;

  // Échéance CISA dépassée depuis plus d'un mois : retirée des listes, mais toujours trouvable par la recherche.
  const isStale = (v: Vuln) => {
    const d = deadlines.get(v.id);
    return Boolean(d && d.source === "cisa" && d.daysLeft < -STALE_DAYS);
  };
  const visible = useMemo(() => vulns.filter((v) => !isStale(v)), [vulns, deadlines]); // eslint-disable-line react-hooks/exhaustive-deps
  const staleCount = vulns.length - visible.length;

  const counts = {
    today: visible.length,
    kev: visible.filter((v) => v.kev || v.ssvc?.exploitation === "active").length,
    poc: visible.filter(hasPoc).length,
    stack: visible.filter((v) => v.matches.length > 0).length,
  };
  const toTreat = visible.filter((v) => (v.priority === "urgente" || v.priority === "haute") && !isClosed(statusOf(v.id))).length;
  const inProgress = visible.filter((v) => statusOf(v.id) === "en_cours").length;
  const closedCount = visible.filter((v) => isClosed(statusOf(v.id))).length;
  const nvdCount = visible.filter((v) => v.origin === "nvd").length;

  const q = query.trim().toLowerCase();
  const matchesQuery = (v: Vuln) =>
    !q ||
    v.id.toLowerCase().includes(q) ||
    v.description.toLowerCase().includes(q) ||
    v.products.some((p) => p.includes(q)) ||
    v.vendors.some((p) => p.includes(q)) ||
    v.affected.some((a) => a.product.toLowerCase().includes(q)) ||
    (v.ai?.resume.toLowerCase().includes(q) ?? false);

  const segCounts = useMemo(() => {
    const c: Record<Priority, number> = { urgente: 0, haute: 0, moyenne: 0, basse: 0 };
    for (const v of q ? vulns : visible) {
      if (view === "kev" && !(v.kev || v.ssvc?.exploitation === "active")) continue;
      if (view === "poc" && !hasPoc(v)) continue;
      if (view === "stack" && v.matches.length === 0) continue;
      if (view === "suivi" && statusOf(v.id) !== "en_cours") continue;
      c[v.priority]++;
    }
    return c;
  }, [vulns, visible, view, q]); // eslint-disable-line react-hooks/exhaustive-deps

  const list = (q ? vulns : visible).filter((v) => {
    if (view === "kev" && !(v.kev || v.ssvc?.exploitation === "active")) return false;
    if (view === "poc" && !hasPoc(v)) return false;
    if (view === "stack" && v.matches.length === 0) return false;
    if (view === "suivi" && statusOf(v.id) !== "en_cours") return false;
    if (seg !== "all" && v.priority !== seg) return false;
    return matchesQuery(v);
  });
  if (sortBy === "echeance") list.sort((a, b) => byDeadline(deadlines.get(a.id) ?? null, deadlines.get(b.id) ?? null));

  const rssList = rss.items.filter((it) => {
    if (kindSeg === "alertes" && !(it.kind === "cert" || it.kind === "gouv")) return false;
    if (kindSeg !== "all" && kindSeg !== "alertes" && it.kind !== kindSeg) return false;
    if (!q) return true;
    return (it.title + " " + it.summary + " " + it.source + " " + it.cves.join(" ")).toLowerCase().includes(q);
  });

  // ---------- fiche détaillée : une page par vulnérabilité ----------
  const select = (id: string) => {
    // Le résumé en français du flux du jour accompagne la fiche (utile sans compte, où la fiche n'appelle pas l'IA).
    const ai = byId.get(id)?.ai;
    try {
      if (ai) sessionStorage.setItem(`vq-ai-${id}`, JSON.stringify(ai));
      sessionStorage.setItem("vq-back", window.location.pathname + window.location.search);
    } catch {
      /* stockage indisponible */
    }
    router.push(`/cve/${id}`);
  };
  const prefetch = (id: string) => router.prefetch(`/cve/${id}`);

  const wide = WIDE.includes(view);
  const platformAnalyst = Boolean(me?.features.analyst);
  const orgAnalyst = roleAtLeast(me?.org?.role, "analyst");
  const analyst = platformAnalyst || orgAnalyst;

  // Navigation resserrée : 6 espaces ; les vues proches deviennent des onglets en tête de page.
  type IconKey = "home" | "warning" | "globe" | "eye" | "shield" | "wrench";
  type Tab = { key: View; label: string; count?: number | string; badge?: number };
  type Space = { id: string; label: string; short?: string; icon: IconKey; tabs: Tab[]; badge?: number; count?: number | string };
  const SPACES: Space[] = [
    { id: "today", label: "Aujourd’hui", short: "Accueil", icon: "home", tabs: [{ key: "today", label: "Aujourd’hui" }], count: counts.today },
    {
      id: "vulns",
      label: "Vulnérabilités",
      short: "Failles",
      icon: "warning",
      badge: dueHot + newItems || undefined,
      count: counts.kev,
      tabs: [
        ...(guest ? [] : [{ key: "stack" as View, label: "Ma stack", count: counts.stack }]),
        { key: "kev", label: "Exploitées", count: counts.kev },
        { key: "echeances", label: "Échéances", count: dueSoon.length, badge: dueHot || undefined },
        { key: "poc", label: "PoC publics", count: counts.poc },
        { key: "suivi", label: "En cours", count: inProgress },
        { key: "live", label: "Flux en direct", count: rss.items.length, badge: newItems || undefined },
      ],
    },
    {
      id: "menaces",
      label: "Menaces",
      icon: "globe",
      tabs: [
        { key: "map", label: "ThreatMap" },
        { key: "rw", label: "Rançongiciels" },
        { key: "fuites", label: "Fuites de données" },
        { key: "ioc", label: "Indicateurs (IOC)" },
      ],
    },
    {
      id: "surveillance",
      label: "Ma surveillance",
      short: "Veille",
      icon: "eye",
      badge: ctiUnread || undefined,
      tabs: [
        { key: "veille", label: "Alertes", badge: ctiUnread || undefined },
        ...(guest ? [] : [{ key: "darkweb" as View, label: "Forums dark web" }]),
        ...(analyst && !guest ? [{ key: "analyse" as View, label: "Qualification" }] : []),
      ],
    },
    { id: "hunt", label: "Threat Hunting", short: "Hunting", icon: "shield", tabs: [{ key: "hunt", label: "Threat Hunting" }] },
    { id: "parc", label: "Parc & correctifs", short: "Parc", icon: "wrench", tabs: [{ key: "parc", label: "Parc & correctifs" }] },
  ];
  const space = SPACES.find((sp) => sp.tabs.some((t) => t.key === view)) ?? SPACES[0];
  /** Onglet d'entrée d'un espace : Ma stack si elle est renseignée, sinon le premier onglet. */
  const entryOf = (sp: Space): View => (sp.id === "vulns" ? (stack.length && !guest ? "stack" : "kev") : sp.tabs[0].key);
  const SURV: View[] = ["veille", "darkweb", "analyse"];
  const tabLabel = space.tabs.find((t) => t.key === view)?.label ?? "";
  const viewTitle = space.tabs.length > 1 ? space.label : space.label;
  /** Titre précis (exports PDF) */
  const exportTitle = space.tabs.length > 1 ? `${space.label} – ${tabLabel}` : space.label;

  const rssOk = rss.sources.filter((s) => s.ok).length;

  return (
    <div className="app">
      <header className="toolbar">
        <div className="brand">
          <span className="brand-mark">
            <LogoMark size={22} />
          </span>
          <BrandName />
        </div>
        <label className="search">
          <Icon name="search" size={15} />
          <span className="sr-only">Rechercher</span>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={view === "live" ? "Rechercher dans les alertes" : "Rechercher un produit, un éditeur, une CVE"}
          />
        </label>
        <div className="tb-right">
          {newItems > 0 && view !== "live" && (
            <button type="button" className="newpill" onClick={() => setView("live")}>
              {newItems} nouvelle{newItems > 1 ? "s" : ""} alerte{newItems > 1 ? "s" : ""}
            </button>
          )}
          <button type="button" className="cmdk-btn" onClick={() => setPalette(true)} aria-label="Recherche globale (⌘K)" title="Rechercher partout (⌘K)">
            <Icon name="search" size={15} />
            <span className="cmdk-btn-label">Tout rechercher</span>
            <kbd>⌘K</kbd>
          </button>
          <button type="button" className="icon-btn" onClick={poll} aria-label="Vérifier les flux maintenant" title={`Flux vérifiés ${relTime(rss.fetchedAt, now)}`} disabled={checking}>
            <Icon name="refresh" size={16} className={checking ? "spin" : ""} />
          </button>
          <UserMenu me={me} guest={guest} />
        </div>
      </header>

      <CommandPalette
        open={palette}
        onClose={() => setPalette(false)}
        signedIn={Boolean(me) && !guest}
        nav={SPACES.flatMap((sp) => sp.tabs.map((t) => ({ key: t.key, label: t.label, group: sp.label })))}
        vulns={feed.vulns.map((v) => ({ id: v.id, label: productName(v), priority: PRIORITY_LABEL[v.priority].toLowerCase() }))}
        onNav={(k) => {
          if (k.startsWith("ioc:")) {
            setIocQuery(k.slice(4));
            setView("ioc");
          } else setView(k as View);
          setSeg("all");
          window.scrollTo({ top: 0 });
        }}
        onCve={(id) => select(id)}
      />

      {meError && (
        <p className="toast" role="alert">
          {meError}
        </p>
      )}
      <div className="split is-map">
        <aside className={`sidebar v-${view}`}>
          <nav className="nav" aria-label="Vues">
            {SPACES.map((sp) => (
              <button
                key={sp.id}
                type="button"
                className={`nav-item${space.id === sp.id ? " is-on" : ""}`}
                aria-current={space.id === sp.id ? "page" : undefined}
                onClick={() => {
                  setView(space.id === sp.id ? view : entryOf(sp));
                  setSeg("all");
                }}
              >
                <span className={`nav-icon ni-sp-${sp.id}`}>
                  <Icon name={sp.icon} size={14} />
                </span>
                <span className="nav-label">
                  <span className="nl-long">{sp.label}</span>
                  <span className="nl-short" aria-hidden="true">
                    {sp.short ?? sp.label}
                  </span>
                </span>
                {sp.badge ? <span className="nav-badge">{sp.badge}</span> : <span className="nav-count">{sp.count ?? ""}</span>}
              </button>
            ))}
          </nav>

          {guest ? (
            <section className="side-sec guest-card" aria-label="Mode invité">
              <p className="guest-title">Vous consultez sans compte</p>
              <p className="hint">
                Consultation en lecture seule. Connectez-vous pour changer le statut des vulnérabilités, gérer Ma stack, recevoir le digest
                et utiliser le partage, les rapports PDF et les tickets.
              </p>
              <a className="btn-primary guest-btn" href="/connexion">
                Se connecter
              </a>
              <div className="guest-appear">
                <span className="menu-appear-label">Apparence</span>
                <AppearanceSegmented />
              </div>
            </section>
          ) : (
          <section className="side-sec sec-stack">
            <div className="side-head">
              <h2>Ma stack</h2>
              <button type="button" className="btn-plain" onClick={() => setEditingStack(!editingStack)}>
                {editingStack ? "Terminé" : "Modifier"}
              </button>
            </div>
            {editingStack ? (
              <>
                <label className="sr-only" htmlFor="stack-input">
                  Vos logiciels, éditeurs ou équipements, séparés par des virgules
                </label>
                <textarea
                  id="stack-input"
                  className="stack-input"
                  rows={3}
                  value={personal}
                  onChange={(e) => setPersonal(e.target.value)}
                  placeholder="fortinet, nginx, wordpress, cisco"
                />
                <p className="hint">{saving ? "Enregistrement…" : "Séparez par des virgules. Enregistré dans votre compte, sur tous vos appareils."}</p>
              </>
            ) : stack.length ? (
              <div className="chips">
                {stack.map((s) => (
                  <span key={s} className="chip-soft">
                    {s}
                  </span>
                ))}
              </div>
            ) : (
              <p className="hint">Ajoutez vos technologies pour voir d’abord ce qui vous concerne.</p>
            )}
          </section>
          )}

          <section className="side-sec">
            <h2>Sources</h2>
            <ul className="group sources">
              {feed.sources
                .filter((s) => s.name !== "Flux RSS")
                .map((s) => (
                  <li key={s.name}>
                    <span>{s.name}</span>
                    <span className="src-state">
                      <span className={`dot ${s.ok ? "dot-ok" : operator ? "dot-bad" : "dot-warn"}`} aria-hidden="true" />
                      {s.ok ? "À jour" : operator ? "Erreur" : "En attente"}
                    </span>
                  </li>
                ))}
              <li>
                <details className="src-rss">
                  <summary>
                    <span>Flux RSS</span>
                    <span className="src-state">
                      <span className={`dot ${rssOk === rss.sources.length ? "dot-ok" : "dot-warn"}`} aria-hidden="true" />
                      {rssOk}/{rss.sources.length}
                    </span>
                  </summary>
                  <ul>
                    {rss.sources.map((s) => (
                      <li key={s.name}>
                        <span>{s.name}</span>
                        <span className="src-state">
                          <span className={`dot ${s.ok ? "dot-ok" : "dot-bad"}`} aria-hidden="true" />
                          {s.ok ? s.detail : "Erreur"}
                        </span>
                      </li>
                    ))}
                  </ul>
                </details>
              </li>
            </ul>
            <p className="hint">
              CVE mises à jour à {timeFr(feed.generatedAt)} UTC. Flux vérifiés {relTime(rss.fetchedAt, now)}.
            </p>
          </section>
        </aside>

        <main className="content">
          <div className="titlebar titlebar-row">
            <div>
              <p className="eyebrow">{dateFr(feed.generatedAt)}</p>
              <h1>{viewTitle}</h1>
            </div>
            {!guest && view !== "live" && !wide && list.length > 0 && (
              <a
                className="btn-pdf"
                href={`/api/v1/report?ids=${list.slice(0, 50).map((v) => v.id).join(",")}&titre=${encodeURIComponent(
                  `${exportTitle}${seg !== "all" ? ` – priorité ${PRIORITY_LABEL[seg].toLowerCase()}` : ""}`,
                )}`}
                download
                title={list.length > 50 ? "Les 50 premières vulnérabilités de la liste" : "Toutes les vulnérabilités de la liste"}
              >
                <Icon name="file" size={15} />
                Exporter en PDF{list.length > 50 ? " (50 premières)" : ""}
              </a>
            )}
          </div>

          {space.tabs.length > 1 && (
            <div className="space-tabs" role="tablist" aria-label={space.label}>
              {space.tabs.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  role="tab"
                  aria-selected={view === t.key}
                  className={`space-tab${view === t.key ? " is-on" : ""}`}
                  onClick={() => {
                    setView(t.key);
                    setSeg("all");
                  }}
                >
                  {t.label}
                  {t.badge ? <span className="space-badge">{t.badge}</span> : t.count !== undefined && t.count !== "" ? <span className="space-count">{t.count}</span> : null}
                </button>
              ))}
            </div>
          )}

          {/* Détails techniques réservés aux opérateurs de la plateforme (page État) */}
          {operator && (feed.errors.length > 0 || !feed.aiEnabled) && view !== "live" && !wide && (
            <p className="callout callout-err" role="status">
              <span>
                {feed.errors.length > 0 ? `${feed.errors.length} source(s) en erreur` : "Résumés en français désactivés"} —{" "}
                <a href="/etat">voir l’état de la plateforme</a> (visible des opérateurs uniquement).
              </span>
            </p>
          )}

          {view === "map" ? (
            <ThreatMap operator={operator} />
          ) : view === "echeances" ? (
            <DeadlinesView items={dueItems} onOpen={select} kevError={operator ? kevDueError : null} showDone={showDone} setShowDone={setShowDone} />
          ) : view === "rw" ? (
            <RansomwareView now={now} />
          ) : view === "fuites" ? (
            <BreachesView now={now} />
          ) : view === "ioc" ? (
            <IocView now={now} initialQ={iocQuery} />
          ) : SURV.includes(view) ? (
            <>
              {view === "darkweb" && !guest ? (
                <DarkwebMonitorView now={now} />
              ) : view === "analyse" && !guest ? (
                analyst ? <LeakQualifyView now={now} platformAnalyst={platformAnalyst} orgAnalyst={orgAnalyst} orgAdmin={roleAtLeast(me?.org?.role, "admin")} /> : <p className="hint">Espace réservé aux analystes.</p>
              ) : (
                <WatchView now={now} guest={guest} onUnread={setCtiUnread} />
              )}
            </>
          ) : view === "hunt" ? (
            <HuntView now={now} guest={guest} />
          ) : view === "parc" ? (
            <PatchView now={now} guest={guest} />
          ) : view !== "live" ? (
            <>
              {view === "today" && me && !guest && (
                <Onboarding
                  onStack={() => {
                    setEditingStack(true);
                    document.querySelector(".sec-stack")?.scrollIntoView({ behavior: "smooth", block: "center" });
                    window.setTimeout(() => (document.querySelector(".sec-stack textarea, .sec-stack input") as HTMLElement | null)?.focus(), 400);
                  }}
                />
              )}
              {view === "today" && (
                <section className="hero card" aria-label="Résumé du jour">
                  <div className="hero-main">
                    <Ring
                      score={visible.length ? Math.round((toTreat / visible.length) * 100) : 0}
                      display={toTreat}
                      size={84}
                      stroke={10}
                      big
                      label={`${toTreat} à traiter sur ${visible.length}`}
                    />
                    <div>
                      <p className="hero-title">
                        {toTreat === 0 ? "Rien d’urgent à traiter" : `${toTreat} vulnérabilité${toTreat > 1 ? "s" : ""} à traiter`}
                      </p>
                      <p className="hero-sub">
                        Sur {nvdCount} CVE publiée{nvdCount > 1 ? "s" : ""} en {feed.windowHours} h, plus{" "}
                        {visible.length - nvdCount} signalée{visible.length - nvdCount > 1 ? "s" : ""} par la CISA ou les flux.
                      </p>
                    </div>
                  </div>
                  <div className="stats">
                    <div className="stat">
                      <span className="stat-v stat-red">{counts.kev}</span>
                      <span className="stat-k">Exploitées</span>
                    </div>
                    {!guest && (
                      <div className="stat">
                        <span className="stat-v">{counts.stack}</span>
                        <span className="stat-k">Dans ma stack</span>
                      </div>
                    )}
                    <div className="stat">
                      <span className="stat-v">{closedCount}</span>
                      <span className="stat-k">Traitées</span>
                    </div>
                  </div>
                </section>
              )}

              {(view === "today" || view === "kev") && dueSoon.length > 0 && (
                <section className={`due-strip card due-strip-${dueSoon[0].deadline.level}`} aria-label="Échéances de correction proches">
                  <div className="due-strip-head">
                    <span className="due-strip-icon">
                      <Icon name="clock" size={16} />
                    </span>
                    <div>
                      <p className="due-strip-title">
                        {dueSoon.filter((i) => i.deadline.daysLeft < 0).length > 0
                          ? `${dueSoon.filter((i) => i.deadline.daysLeft < 0).length} échéance${dueSoon.filter((i) => i.deadline.daysLeft < 0).length > 1 ? "s" : ""} dépassée${dueSoon.filter((i) => i.deadline.daysLeft < 0).length > 1 ? "s" : ""}, `
                          : ""}
                        {dueSoon.filter((i) => i.deadline.daysLeft >= 0).length} correction{dueSoon.filter((i) => i.deadline.daysLeft >= 0).length > 1 ? "s" : ""} à faire d’ici 7 jours
                      </p>
                      <p className="hero-sub">Échéances CISA des failles exploitées et délais recommandés selon la priorité.</p>
                    </div>
                    <button type="button" className="btn-plain" onClick={() => setView("echeances")}>
                      Tout voir
                    </button>
                  </div>
                  <ul className="due-mini">
                    {dueSoon.slice(0, 5).map((it) => (
                      <li key={it.id}>
                        <button type="button" onClick={() => select(it.id)}>
                          <DueChip d={it.deadline} compact />
                          <span className="due-mini-name">{it.product}</span>
                          <span className="row-id">{it.id}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {view === "poc" && (
                <>
                  <p className="lede">
                    Vulnérabilités pour lesquelles un code d’exploitation ou une preuve de concept circule publiquement
                    (GitHub, Exploit-DB). Touchez une vulnérabilité pour voir ses PoC.
                  </p>
                </>
              )}

              <div className="list-tools">
              <div className="segmented" role="group" aria-label="Priorité">
                {(["all", ...PRIORITY_ORDER] as Seg[]).map((s) => (
                  <button key={s} type="button" aria-pressed={seg === s} className={seg === s ? "is-on" : ""} onClick={() => setSeg(s)}>
                    {s === "all" ? "Toutes" : `${PRIORITY_LABEL[s]}s`}
                    {s !== "all" && <span className="seg-n">{segCounts[s]}</span>}
                  </button>
                ))}
              </div>
              <div className="segmented sort-seg" role="group" aria-label="Trier par">
                <button type="button" aria-pressed={sortBy === "score"} className={sortBy === "score" ? "is-on" : ""} onClick={() => setSortBy("score")}>
                  Par score
                </button>
                <button type="button" aria-pressed={sortBy === "echeance"} className={sortBy === "echeance" ? "is-on" : ""} onClick={() => setSortBy("echeance")}>
                  Par échéance
                </button>
              </div>
              {!guest && orgAnalyst && list.length > 0 && (
                <button type="button" className={`btn-select${selecting ? " is-on" : ""}`} onClick={() => (selecting ? (setSelecting(false), setPicked(new Set())) : startSelecting())}>
                  {selecting ? "Annuler" : "Sélectionner"}
                </button>
              )}
              </div>

              {list.length === 0 ? (
                <div className="empty card">
                  {(() => {
                    // Écran vide : dire pourquoi, et proposer l'action suivante
                    const openStack = () => {
                      setEditingStack(true);
                      document.querySelector(".sec-stack")?.scrollIntoView({ behavior: "smooth", block: "center" });
                    };
                    const e: { t: string; d: React.ReactNode; a?: React.ReactNode } =
                      guest && view === "suivi"
                        ? { t: "Suivi réservé aux comptes", d: "Les vulnérabilités que vous passez « En cours » apparaissent ici.", a: <a className="btn-primary btn-sm" href="/connexion">Se connecter</a> }
                        : view === "stack" && !stack.length
                          ? {
                              t: "Votre stack est vide",
                              d: "Indiquez vos logiciels et équipements (Fortinet, Nginx, Windows Server…) : les failles qui vous concernent passeront en tête.",
                              a: guest ? undefined : <button type="button" className="btn-primary btn-sm" onClick={openStack}>Ajouter mes technologies</button>,
                            }
                          : view === "stack" && !q && seg === "all"
                            ? { t: "Rien ne touche votre stack aujourd’hui", d: "Aucune vulnérabilité du jour ne concerne vos technologies. Vous serez prévenu dans l’e-mail du matin si cela change." }
                            : view === "suivi" && !q
                              ? { t: "Rien en cours", d: "Ouvrez une vulnérabilité et choisissez « En cours » : elle apparaîtra ici, partagée avec votre équipe." }
                              : q
                                ? {
                                    t: "Aucun résultat dans le tableau du jour",
                                    d: q.length >= 3 ? "Les résultats du catalogue complet s’affichent ci-dessous. Saisissez un identifiant CVE exact pour ouvrir n’importe quelle fiche." : "Saisissez au moins 3 caractères.",
                                  }
                                : { t: "Aucune vulnérabilité ici", d: "Changez de priorité pour en voir davantage.", a: seg !== "all" ? <button type="button" className="btn-secondary btn-sm" onClick={() => setSeg("all")}>Voir toutes les priorités</button> : undefined };
                    return (
                      <>
                        <p className="empty-title">{e.t}</p>
                        <p>{e.d}</p>
                        {e.a && <div className="empty-action">{e.a}</div>}
                      </>
                    );
                  })()}
                </div>
              ) : (
                <ul className="list card">
                  {list.map((v) => {
                    const versions = affectedSummary(v.affected, 1);
                    const st = statusOf(v.id);
                    const isDone = isClosed(st);
                    const owner = owners[v.id];
                    return (
                      <li key={v.id} className={selecting ? `is-selecting${picked.has(v.id) ? " is-picked" : ""}` : undefined}>
                        {selecting && (
                          <label className="row-check">
                            <input type="checkbox" checked={picked.has(v.id)} onChange={() => togglePick(v.id)} aria-label={`Sélectionner ${v.id}`} />
                          </label>
                        )}
                        <button
                          type="button"
                          className={`row ${PRIO_CLASS[v.priority]}${isDone ? " is-done" : ""}`}
                          onClick={() => (selecting ? togglePick(v.id) : select(v.id))}
                          onMouseEnter={() => prefetch(v.id)}
                        >
                          <Ring score={v.score} />
                          <span className="row-main">
                            <span className="row-top">
                              <span className="row-product">{productName(v)}</span>
                              <span className="row-id">{v.id}</span>
                            </span>
                            <span className="row-text">{v.ai?.resume || v.description}</span>
                            <span className="chips">
                              {(() => {
                                const d = deadlines.get(v.id);
                                return d && !isDone && d.daysLeft <= 14 ? <DueChip d={d} /> : null;
                              })()}
                              <span className="tag tag-prio">{PRIORITY_LABEL[v.priority]}</span>
                              {(v.kev || v.ssvc?.exploitation === "active") && <span className="tag tag-kev">Exploitée</span>}
                              {hasPoc(v) && <span className="tag tag-poc">PoC{v.exploits?.length ? ` ×${v.exploits.length}` : ""}</span>}
                              {st !== "a_traiter" && <span className={`tag tag-st-${st}`}>{STATUS_LABEL[st]}</span>}
                              {owner && <span className="tag tag-owner">{owner.userId === myId ? "Moi" : owner.name}</span>}
                              {v.matches.map((m) => (
                                <span key={m} className="tag tag-stack">{m}</span>
                              ))}
                              {versions && <span className="tag tag-ver">{versions}</span>}
                              {v.mentions.length > 0 && <span className="tag">{v.mentions[0].source}</span>}
                            </span>
                          </span>
                          <span className="row-meta">
                            <span>CVSS {cvssFr(v.cvss)}</span>
                            <span>EPSS {pct(v.epss)}</span>
                            <span>{relTime(v.published, now)}</span>
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
              {selecting && (
                <div className="bulk-bar" role="toolbar" aria-label="Actions groupées">
                  <button type="button" className="btn-link" onClick={() => setPicked(picked.size === list.length ? new Set() : new Set(list.map((v) => v.id)))}>
                    {picked.size === list.length ? "Tout désélectionner" : "Tout sélectionner"}
                  </button>
                  <span className="bulk-n">{picked.size} sélectionnée{picked.size > 1 ? "s" : ""}</span>
                  <button type="button" className="btn-secondary btn-sm" disabled={!picked.size} onClick={() => bulkStatus("en_cours")}>
                    En cours
                  </button>
                  <button type="button" className="btn-secondary btn-sm" disabled={!picked.size} onClick={() => bulkStatus("traitee")}>
                    Traitées
                  </button>
                  <button type="button" className="btn-secondary btn-sm" disabled={!picked.size} onClick={() => bulkStatus("non_concernee")}>
                    Non concernées
                  </button>
                  <select className="plan-select" aria-label="Assigner la sélection" disabled={!picked.size} value="" onChange={(e) => e.target.value && bulkAssign(e.target.value === "-" ? null : e.target.value)}>
                    <option value="">Assigner à…</option>
                    {members.map((m) => (
                      <option key={m.userId} value={m.userId}>
                        {m.userId === myId ? `${m.name} (moi)` : m.name}
                      </option>
                    ))}
                    <option value="-">Retirer le responsable</option>
                  </select>
                </div>
              )}
              {bulkMsg && (
                <p className="toast toast-ok" role="status">
                  {bulkMsg}
                </p>
              )}
              {q.length >= 3 && <CatalogSearch q={q} exclude={byId} onOpen={select} now={now} />}
              {!q && staleCount > 0 && (
                <p className="hint stale-hint">
                  {staleCount} vulnérabilité{staleCount > 1 ? "s" : ""} dont l’échéance CISA est dépassée depuis plus d’un mois{" "}
                  {staleCount > 1 ? "sont masquées" : "est masquée"}. Utilisez la recherche pour les retrouver, ainsi que tout le catalogue CISA.
                </p>
              )}
              {view === "poc" && <OtherPocCves exclude={byId} selected={null} onSelect={select} />}
            </>
          ) : (
            <>
              <p className="lede">
                Alertes de {rss.sources.length} sources (CERT, agences, éditeurs, Exploit-DB), vérifiées toutes les minutes.
                Touchez une CVE pour ouvrir sa fiche.
              </p>
              <div className="segmented" role="group" aria-label="Type de source">
                {(
                  [
                    ["all", "Tout"],
                    ["alertes", "CERT et agences"],
                    ["editeur", "Éditeurs"],
                    ["exploit", "Exploits"],
                    ["cve", "Nouvelles CVE"],
                  ] as [KindSeg, string][]
                ).map(([k, l]) => (
                  <button key={k} type="button" aria-pressed={kindSeg === k} className={kindSeg === k ? "is-on" : ""} onClick={() => setKindSeg(k)}>
                    {l}
                  </button>
                ))}
              </div>
              {rssList.length === 0 ? (
                <div className="empty card">
                  <p className="empty-title">Aucune alerte</p>
                  <p>Aucun flux n’a publié d’élément correspondant. La liste se met à jour toute seule.</p>
                </div>
              ) : (
                <ul className="list card">
                  {rssList.slice(0, 150).map((it: RssItem) => (
                    <li key={it.key} className="alert">
                      <div className="alert-top">
                        <span className={`src src-${it.kind}`}>{it.source}</span>
                        <span className="alert-kind">{KIND_LABEL[it.kind]}</span>
                        <span className="alert-time">{relTime(it.published, now)}</span>
                      </div>
                      <a className="alert-title" href={it.link} target="_blank" rel="noreferrer">
                        {it.title}
                      </a>
                      {it.summary && <p className="alert-sum">{it.summary}</p>}
                      {it.cves.length > 0 && (
                        <div className="chips">
                          {it.cves.slice(0, 8).map((c) => (
                            <button key={c} type="button" className={`cvechip${byId.has(c) ? " in-feed" : ""}`} onClick={() => select(c)}>
                              {c}
                            </button>
                          ))}
                          {it.cves.length > 8 && <span className="hint">et {it.cves.length - 8} autres</span>}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
          {!wide && <p className="foot-note">
            Le score combine gravité (CVSS), probabilité d’exploitation (EPSS), exploitation confirmée (CISA KEV, SSVC) et
            alertes des CERT. Flux JSON : <a href="/api/cves">/api/cves</a> et <a href="/api/rss">/api/rss</a>.
          </p>}
        </main>
      </div>
    </div>
  );
}
