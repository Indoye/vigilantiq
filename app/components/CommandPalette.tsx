"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./ui";

export interface PaletteVuln {
  id: string;
  label: string;
  priority: string;
}
export interface PaletteNav {
  key: string;
  label: string;
  group: string;
}
type Item = { id: string; kind: "nav" | "action" | "cve" | "catalog" | "ioc"; title: string; sub?: string; run: () => void };

const KIND_LABEL: Record<Item["kind"], string> = { nav: "Aller à", action: "Actions", cve: "Vulnérabilités du jour", catalog: "Catalogue des failles exploitées", ioc: "Indicateurs de compromission" };
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const norm = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();

/**
 * Recherche globale (⌘K / Ctrl+K, ou « / ») : écrans, actions, CVE du jour, catalogue complet et IOC.
 */
export default function CommandPalette({
  open,
  onClose,
  nav,
  vulns,
  onNav,
  onCve,
  signedIn,
}: {
  open: boolean;
  onClose: () => void;
  nav: PaletteNav[];
  vulns: PaletteVuln[];
  onNav: (key: string) => void;
  onCve: (id: string) => void;
  signedIn: boolean;
}) {
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [remote, setRemote] = useState<{ catalog: Item[]; ioc: Item[] }>({ catalog: [], ioc: [] });
  const input = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  // Rappels conservés dans une référence : la recherche distante ne se relance pas à chaque rendu du parent
  const cb = useRef({ onCve, onNav });
  cb.current = { onCve, onNav };

  useEffect(() => {
    if (open) {
      setQ("");
      setActive(0);
      setRemote({ catalog: [], ioc: [] });
      window.setTimeout(() => input.current?.focus(), 10);
    }
  }, [open]);

  // Recherche distante (catalogue CISA et IOC), avec un léger délai
  useEffect(() => {
    if (!open) return;
    const term = q.trim();
    if (term.length < 3) {
      setRemote({ catalog: [], ioc: [] });
      return;
    }
    const ctl = new AbortController();
    const t = window.setTimeout(async () => {
      const [cat, ioc] = await Promise.all([
        fetch(`/api/recherche?q=${encodeURIComponent(term)}`, { signal: ctl.signal })
          .then((r) => r.json())
          .catch(() => ({ items: [] })),
        fetch(`/api/cti/iocs?limit=5&q=${encodeURIComponent(term)}`, { signal: ctl.signal })
          .then((r) => (r.ok ? r.json() : { items: [] }))
          .catch(() => ({ items: [] })),
      ]);
      if (ctl.signal.aborted) return;
      setRemote({
        catalog: ((cat.items ?? []) as { id: string; vendor: string; product: string; name: string }[]).slice(0, 6).map((k) => ({
          id: `cat-${k.id}`,
          kind: "catalog",
          title: `${k.vendor} ${k.product}`.trim(),
          sub: `${k.id}${k.name ? ` · ${k.name}` : ""}`,
          run: () => cb.current.onCve(k.id),
        })),
        ioc: ((ioc.items ?? []) as { type: string; value: string; threat: string; malware: string }[]).slice(0, 5).map((i) => ({
          id: `ioc-${i.type}-${i.value}`,
          kind: "ioc",
          title: i.value,
          sub: `${i.threat}${i.malware ? ` · ${i.malware}` : ""}`,
          run: () => cb.current.onNav(`ioc:${i.value}`),
        })),
      });
    }, 220);
    return () => {
      ctl.abort();
      window.clearTimeout(t);
    };
  }, [q, open]);

  const items = useMemo<Item[]>(() => {
    const term = norm(q.trim());
    const out: Item[] = [];
    if (CVE_RE.test(q.trim())) out.push({ id: "open-cve", kind: "cve", title: `Ouvrir ${q.trim().toUpperCase()}`, sub: "Fiche complète de la vulnérabilité", run: () => cb.current.onCve(q.trim().toUpperCase()) });
    const navHits = nav.filter((n) => !term || norm(`${n.label} ${n.group}`).includes(term)).slice(0, term ? 6 : 8);
    out.push(...navHits.map((n) => ({ id: `nav-${n.key}`, kind: "nav" as const, title: n.label, sub: n.group !== n.label ? n.group : undefined, run: () => cb.current.onNav(n.key) })));
    const actions: { t: string; s: string; href: string; auth?: boolean }[] = [
      { t: "Mon compte et préférences", s: "Profil, e-mail du matin, sécurité", href: "/compte", auth: true },
      { t: "Inviter un collègue", s: "Organisation → membres", href: "/compte#organisation", auth: true },
      { t: "Configurer une intégration", s: "Jira, ServiceNow, XSOAR, SIEM, MISP", href: "/compte#organisation", auth: true },
      { t: "Créer un motif dark web", s: "Ma surveillance → Forums dark web", href: "/?vue=dark-web", auth: true },
      { t: "Ajouter un équipement", s: "Parc & correctifs → agent", href: "/?vue=parc", auth: true },
      { t: "Se connecter", s: "Accéder au suivi et aux alertes", href: "/connexion" },
    ];
    out.push(
      ...actions
        .filter((a) => (a.auth ? signedIn : !signedIn) && (!term || norm(`${a.t} ${a.s}`).includes(term)))
        .slice(0, term ? 4 : 3)
        .map((a) => ({ id: `act-${a.t}`, kind: "action" as const, title: a.t, sub: a.s, run: () => window.location.assign(a.href) })),
    );
    if (term.length >= 2) {
      out.push(
        ...vulns
          .filter((v) => norm(`${v.id} ${v.label}`).includes(term))
          .slice(0, 6)
          .map((v) => ({ id: `cve-${v.id}`, kind: "cve" as const, title: v.label, sub: `${v.id} · priorité ${v.priority}`, run: () => cb.current.onCve(v.id) })),
      );
    }
    const seen = new Set(out.filter((i) => i.kind === "cve").map((i) => i.sub?.split(" ")[0]));
    out.push(...remote.catalog.filter((c) => !seen.has(c.sub?.split(" ")[0])));
    out.push(...remote.ioc);
    return out;
  }, [q, nav, vulns, remote, signedIn]);

  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-i="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  const run = (i: Item | undefined) => {
    if (!i) return;
    onClose();
    i.run();
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(items.length - 1, a + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(items[active]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  let lastKind = "";
  return (
    <div className="cmdk-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="cmdk" role="dialog" aria-modal="true" aria-label="Recherche globale">
        <label className="cmdk-input">
          <Icon name="search" size={17} />
          <input
            ref={input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder="Rechercher une CVE, un produit, un IOC, un écran…"
            aria-controls="cmdk-list"
            aria-activedescendant={items[active] ? `cmdk-${active}` : undefined}
            role="combobox"
            aria-expanded="true"
            spellCheck={false}
          />
          <kbd>Échap</kbd>
        </label>
        <ul className="cmdk-list" id="cmdk-list" role="listbox" ref={listRef}>
          {items.length === 0 && <li className="cmdk-empty">{q.trim().length < 3 ? "Saisissez au moins 3 caractères pour chercher dans le catalogue et les IOC." : "Aucun résultat."}</li>}
          {items.map((i, n) => {
            const head = i.kind !== lastKind ? KIND_LABEL[i.kind] : null;
            lastKind = i.kind;
            return [
              head ? (
                <li key={`h-${i.kind}`} className="cmdk-head" role="presentation">
                  {head}
                </li>
              ) : null,
              <li
                key={i.id}
                id={`cmdk-${n}`}
                data-i={n}
                role="option"
                aria-selected={n === active}
                className={`cmdk-item${n === active ? " is-on" : ""}`}
                onMouseMove={() => setActive(n)}
                onClick={() => run(i)}
              >
                <span className="cmdk-title">{i.title}</span>
                {i.sub && <span className="cmdk-sub">{i.sub}</span>}
              </li>,
            ];
          })}
        </ul>
        <p className="cmdk-foot">
          <kbd>↑</kbd>
          <kbd>↓</kbd> naviguer · <kbd>Entrée</kbd> ouvrir · <kbd>⌘K</kbd> ou <kbd>Ctrl K</kbd> partout
        </p>
      </div>
    </div>
  );
}
