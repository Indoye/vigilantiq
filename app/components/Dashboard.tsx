"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { cvssFr, dateFr, pct, productName, relTime, timeFr } from "@/lib/format";
import { PRIORITY_LABEL, PRIORITY_ORDER } from "@/lib/score";
import { matchStack, parseStack } from "@/lib/stack";
import type { CveDetail, ExploitRef, Feed, FeedKind, Priority, RssItem, RssSnapshot, Vuln } from "@/lib/types";
import { affectedSummary } from "@/lib/versions";
import CveDetailView from "./CveDetailView";
import { ExploitsSection, OtherPocCves } from "./Integrations";
import { Icon, PRIO_CLASS, Ring } from "./ui";
import UserMenu from "./UserMenu";
import { isClosed, STATUS_LABEL, useMe } from "./useMe";

type View = "today" | "kev" | "poc" | "stack" | "suivi" | "live";
type Seg = "all" | Priority;
type KindSeg = "all" | "alertes" | "editeur" | "exploit" | "cve";

const KIND_LABEL: Record<FeedKind, string> = { cert: "CERT", gouv: "Agence", editeur: "Éditeur", exploit: "Exploit", cve: "Nouvelle CVE" };
const POLL_MS = 60_000;

/** Code d'exploitation public connu : dépôt PoC, Exploit-DB, ou SSVC « poc ». */
function hasPoc(v: Vuln): boolean {
  return (v.exploits?.length ?? 0) > 0 || v.mentions.some((m) => m.kind === "exploit") || v.ssvc?.exploitation === "poc";
}

export default function Dashboard({ feed, initialRss }: { feed: Feed; initialRss: RssSnapshot }) {
  const [view, setView] = useState<View>("today");
  const [seg, setSeg] = useState<Seg>("all");
  const [kindSeg, setKindSeg] = useState<KindSeg>("all");
  const [query, setQuery] = useState("");
  const { me, error: meError, saving, setStatus, saveSettings } = useMe();
  const personal = me?.settings.stack ?? "";
  const setPersonal = (v: string) => saveSettings({ stack: v });
  const statusOf = (id: string) => me?.statuses[id] ?? "a_traiter";
  const [editingStack, setEditingStack] = useState(false);
  const [selected, setSelected] = useState<string | null>(feed.vulns[0]?.id ?? null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [otherPocs, setOtherPocs] = useState<ExploitRef[]>([]);
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

  const counts = {
    today: vulns.length,
    kev: vulns.filter((v) => v.kev || v.ssvc?.exploitation === "active").length,
    poc: vulns.filter(hasPoc).length,
    stack: vulns.filter((v) => v.matches.length > 0).length,
  };
  const toTreat = vulns.filter((v) => (v.priority === "urgente" || v.priority === "haute") && !isClosed(statusOf(v.id))).length;
  const inProgress = vulns.filter((v) => statusOf(v.id) === "en_cours").length;
  const closedCount = vulns.filter((v) => isClosed(statusOf(v.id))).length;
  const nvdCount = vulns.filter((v) => v.origin === "nvd").length;

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
    for (const v of vulns) {
      if (view === "kev" && !(v.kev || v.ssvc?.exploitation === "active")) continue;
      if (view === "poc" && !hasPoc(v)) continue;
      if (view === "stack" && v.matches.length === 0) continue;
      if (view === "suivi" && statusOf(v.id) !== "en_cours") continue;
      c[v.priority]++;
    }
    return c;
  }, [vulns, view]);

  const list = vulns.filter((v) => {
    if (view === "kev" && !(v.kev || v.ssvc?.exploitation === "active")) return false;
    if (view === "poc" && !hasPoc(v)) return false;
    if (view === "stack" && v.matches.length === 0) return false;
    if (view === "suivi" && statusOf(v.id) !== "en_cours") return false;
    if (seg !== "all" && v.priority !== seg) return false;
    return matchesQuery(v);
  });

  const rssList = rss.items.filter((it) => {
    if (kindSeg === "alertes" && !(it.kind === "cert" || it.kind === "gouv")) return false;
    if (kindSeg !== "all" && kindSeg !== "alertes" && it.kind !== kindSeg) return false;
    if (!q) return true;
    return (it.title + " " + it.summary + " " + it.source + " " + it.cves.join(" ")).toLowerCase().includes(q);
  });

  // ---------- fiche détaillée ----------
  const [details, setDetails] = useState<Record<string, CveDetail>>({});
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const reqRef = useRef(0);

  useEffect(() => {
    if (!selected || details[selected]) return;
    const n = ++reqRef.current;
    setLoadingId(selected);
    setDetailError(null);
    fetch(`/api/cve/${selected}`)
      .then(async (r) => {
        const j = await r.json();
        if (!r.ok) throw new Error(j.error ?? `Erreur ${r.status}`);
        if (n === reqRef.current) setDetails((d) => ({ ...d, [selected]: j }));
      })
      .catch((e: Error) => n === reqRef.current && setDetailError(`Fiche complète indisponible : ${e.message}`))
      .finally(() => n === reqRef.current && setLoadingId(null));
  }, [selected, details]);

  const select = (id: string) => {
    setSelected(id);
    setSheetOpen(true);
  };

  const selBase: Vuln | CveDetail | null = selected ? byId.get(selected) ?? details[selected] ?? null : null;
  const selFull = selected ? details[selected] ?? null : null;

  // Escape ferme la feuille sur mobile
  useEffect(() => {
    if (!sheetOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setSheetOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sheetOpen]);

  const viewTitle = { today: "Aujourd’hui", kev: "Exploitées", poc: "PoC publics", stack: "Ma stack", suivi: "En cours", live: "Flux en direct" }[view];
  const navItems: { key: View; label: string; icon: "calendar" | "warning" | "stack" | "radio" | "check" | "code"; count: number | string; badge?: number }[] = [
    { key: "today", label: "Aujourd’hui", icon: "calendar", count: counts.today },
    { key: "kev", label: "Exploitées", icon: "warning", count: counts.kev },
    { key: "poc", label: "PoC publics", icon: "code", count: counts.poc },
    { key: "stack", label: "Ma stack", icon: "stack", count: counts.stack },
    { key: "suivi", label: "En cours", icon: "check", count: inProgress },
    { key: "live", label: "Flux en direct", icon: "radio", count: rss.items.length, badge: newItems },
  ];

  const rssOk = rss.sources.filter((s) => s.ok).length;

  return (
    <div className="app">
      <header className="toolbar">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="shield" size={16} />
          </span>
          <span className="brand-name">VigilantIQ</span>
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
          <span className="live" title={`Flux vérifiés ${relTime(rss.fetchedAt, now)}`}>
            <span className={`live-dot${checking ? " is-checking" : ""}`} aria-hidden="true" />
            <span className="live-txt">En direct</span>
          </span>
          <button type="button" className="icon-btn" onClick={poll} aria-label="Vérifier les flux maintenant" disabled={checking}>
            <Icon name="refresh" size={16} className={checking ? "spin" : ""} />
          </button>
          <UserMenu me={me} />
        </div>
      </header>

      {meError && (
        <p className="toast" role="alert">
          {meError}
        </p>
      )}
      <div className="split">
        <aside className={`sidebar v-${view}`}>
          <nav className="nav" aria-label="Vues">
            {navItems.map((n) => (
              <button
                key={n.key}
                type="button"
                className={`nav-item${view === n.key ? " is-on" : ""}`}
                aria-current={view === n.key ? "page" : undefined}
                onClick={() => {
                  setView(n.key);
                  setSeg("all");
                  if (n.key === "poc" && !(selected && byId.get(selected) && hasPoc(byId.get(selected)!))) {
                    const first = vulns.find(hasPoc);
                    if (first) setSelected(first.id);
                  }
                }}
              >
                <span className={`nav-icon ni-${n.key}`}>
                  <Icon name={n.icon} size={14} />
                </span>
                <span className="nav-label">{n.label}</span>
                {n.badge ? <span className="nav-badge">{n.badge}</span> : <span className="nav-count">{n.count}</span>}
              </button>
            ))}
          </nav>

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

          <section className="side-sec">
            <h2>Sources</h2>
            <ul className="group sources">
              {feed.sources
                .filter((s) => s.name !== "Flux RSS")
                .map((s) => (
                  <li key={s.name}>
                    <span>{s.name}</span>
                    <span className="src-state">
                      <span className={`dot ${s.ok ? "dot-ok" : "dot-bad"}`} aria-hidden="true" />
                      {s.ok ? "À jour" : "Erreur"}
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
            {view !== "live" && list.length > 0 && (
              <a
                className="btn-pdf"
                href={`/api/v1/report?ids=${list.slice(0, 50).map((v) => v.id).join(",")}&titre=${encodeURIComponent(
                  `${viewTitle}${seg !== "all" ? ` – priorité ${PRIORITY_LABEL[seg].toLowerCase()}` : ""}`,
                )}`}
                download
                title={list.length > 50 ? "Les 50 premières vulnérabilités de la liste" : "Toutes les vulnérabilités de la liste"}
              >
                <Icon name="file" size={15} />
                Exporter en PDF{list.length > 50 ? " (50 premières)" : ""}
              </a>
            )}
          </div>

          {feed.errors.length > 0 && view !== "live" && (
            <p className="callout callout-err" role="status">
              Données partielles : {feed.errors.join(" ; ")}. Le prochain rafraîchissement réessaiera.
            </p>
          )}
          {!feed.aiEnabled && view !== "live" && (
            <p className="callout" role="status">
              Résumés en français désactivés : ajoutez ANTHROPIC_API_KEY dans les variables d’environnement du projet.
            </p>
          )}

          {view !== "live" ? (
            <>
              {view === "today" && (
                <section className="hero card" aria-label="Résumé du jour">
                  <div className="hero-main">
                    <Ring
                      score={vulns.length ? Math.round((toTreat / vulns.length) * 100) : 0}
                      display={toTreat}
                      size={84}
                      stroke={10}
                      big
                      label={`${toTreat} à traiter sur ${vulns.length}`}
                    />
                    <div>
                      <p className="hero-title">
                        {toTreat === 0 ? "Rien d’urgent à traiter" : `${toTreat} vulnérabilité${toTreat > 1 ? "s" : ""} à traiter`}
                      </p>
                      <p className="hero-sub">
                        Sur {nvdCount} CVE publiée{nvdCount > 1 ? "s" : ""} en {feed.windowHours} h, plus{" "}
                        {vulns.length - nvdCount} signalée{vulns.length - nvdCount > 1 ? "s" : ""} par la CISA ou les flux.
                      </p>
                    </div>
                  </div>
                  <div className="stats">
                    <div className="stat">
                      <span className="stat-v stat-red">{counts.kev}</span>
                      <span className="stat-k">Exploitées</span>
                    </div>
                    <div className="stat">
                      <span className="stat-v">{counts.stack}</span>
                      <span className="stat-k">Dans ma stack</span>
                    </div>
                    <div className="stat">
                      <span className="stat-v">{closedCount}</span>
                      <span className="stat-k">Traitées</span>
                    </div>
                  </div>
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

              <div className="segmented" role="group" aria-label="Priorité">
                {(["all", ...PRIORITY_ORDER] as Seg[]).map((s) => (
                  <button key={s} type="button" aria-pressed={seg === s} className={seg === s ? "is-on" : ""} onClick={() => setSeg(s)}>
                    {s === "all" ? "Toutes" : `${PRIORITY_LABEL[s]}s`}
                    {s !== "all" && <span className="seg-n">{segCounts[s]}</span>}
                  </button>
                ))}
              </div>

              {list.length === 0 ? (
                <div className="empty card">
                  <p className="empty-title">{view === "stack" && !stack.length ? "Votre stack est vide" : "Aucune vulnérabilité ici"}</p>
                  <p>
                    {view === "stack" && !stack.length
                      ? "Ajoutez vos technologies dans « Ma stack » pour filtrer les CVE qui vous concernent."
                      : "Changez de priorité ou effacez la recherche pour en voir davantage."}
                  </p>
                </div>
              ) : (
                <ul className="list card">
                  {list.map((v) => {
                    const versions = affectedSummary(v.affected, 1);
                    const st = statusOf(v.id);
                    const isDone = isClosed(st);
                    return (
                      <li key={v.id}>
                        <button
                          type="button"
                          className={`row ${PRIO_CLASS[v.priority]}${selected === v.id ? " is-sel" : ""}${isDone ? " is-done" : ""}`}
                          aria-pressed={selected === v.id}
                          onClick={() => select(v.id)}
                        >
                          <Ring score={v.score} />
                          <span className="row-main">
                            <span className="row-top">
                              <span className="row-product">{productName(v)}</span>
                              <span className="row-id">{v.id}</span>
                            </span>
                            <span className="row-text">{v.ai?.resume || v.description}</span>
                            <span className="chips">
                              <span className="tag tag-prio">{PRIORITY_LABEL[v.priority]}</span>
                              {(v.kev || v.ssvc?.exploitation === "active") && <span className="tag tag-kev">Exploitée</span>}
                              {hasPoc(v) && <span className="tag tag-poc">PoC{v.exploits?.length ? ` ×${v.exploits.length}` : ""}</span>}
                              {st !== "a_traiter" && <span className={`tag tag-st-${st}`}>{STATUS_LABEL[st]}</span>}
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
              {view === "poc" && <OtherPocCves exclude={byId} selected={selected} onSelect={select} onLoaded={setOtherPocs} />}
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
          <p className="foot-note">
            Le score combine gravité (CVSS), probabilité d’exploitation (EPSS), exploitation confirmée (CISA KEV, SSVC) et
            alertes des CERT. Flux JSON : <a href="/api/cves">/api/cves</a> et <a href="/api/rss">/api/rss</a>.
          </p>
        </main>

        <aside className={`inspector${sheetOpen ? " is-open" : ""}`} aria-label="Fiche de la vulnérabilité">
          {selected && selBase ? (
            <CveDetailView
              key={selected}
              base={selBase}
              full={selFull}
              loading={loadingId === selected}
              error={detailError}
              status={statusOf(selected)}
              onStatus={(s) => setStatus(selected, s)}
              onClose={() => setSheetOpen(false)}
              pocFirst={view === "poc"}
            />
          ) : selected && loadingId === selected ? (
            <div className="detail">
              <div className="sheet-bar">
                <span className="grabber" aria-hidden="true" />
                <button type="button" className="btn-plain" onClick={() => setSheetOpen(false)}>
                  Fermer
                </button>
              </div>
              <p className="d-sub">{selected}</p>
              <div className="skeleton" aria-busy="true" aria-label="Chargement de la fiche">
                <span />
                <span />
                <span />
              </div>
            </div>
          ) : (
            <div className="detail">
              <div className="sheet-bar">
                <span className="grabber" aria-hidden="true" />
                <button type="button" className="btn-plain" onClick={() => setSheetOpen(false)}>
                  Fermer
                </button>
              </div>
              {selected && otherPocs.some((e) => e.cveId === selected) ? (
                <>
                  <header className="d-head">
                    <div className="d-title">
                      <h2>{selected}</h2>
                      <p className="d-sub">Fiche détaillée momentanément indisponible ; les PoC déjà détectés restent consultables.</p>
                    </div>
                  </header>
                  <ExploitsSection list={otherPocs.filter((e) => e.cveId === selected)} id={selected} />
                  <a className="btn-secondary" style={{ flex: "none" }} href={`https://nvd.nist.gov/vuln/detail/${selected}`} target="_blank" rel="noreferrer">
                    Voir la fiche sur la NVD
                  </a>
                </>
              ) : detailError ? (
                <p className="callout callout-err">{detailError}</p>
              ) : (
                <p className="hint">Sélectionnez une vulnérabilité pour afficher sa fiche.</p>
              )}
            </div>
          )}
        </aside>
        {sheetOpen && <button type="button" className="scrim" aria-label="Fermer la fiche" onClick={() => setSheetOpen(false)} />}
      </div>
    </div>
  );
}
