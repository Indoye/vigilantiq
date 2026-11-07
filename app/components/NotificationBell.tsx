"use client";

import { useEffect, useRef, useState } from "react";
import { relTime } from "@/lib/format";
import { Icon } from "./ui";

interface Notif {
  id: string;
  kind: "alerte" | "darkweb" | "assignation" | "commentaire" | "echeance";
  title: string;
  detail: string;
  href: string;
  severity: string;
  at: string;
  unread: boolean;
}

const KIND: Record<Notif["kind"], { icon: "eye" | "search" | "user" | "message" | "clock"; label: string }> = {
  alerte: { icon: "eye", label: "Surveillance" },
  darkweb: { icon: "search", label: "Dark web" },
  assignation: { icon: "user", label: "Assignation" },
  commentaire: { icon: "message", label: "Discussion" },
  echeance: { icon: "clock", label: "Échéance" },
};

/**
 * Cloche du bandeau : alertes de surveillance, dark web, CVE confiées, commentaires, et échéances proches
 * (fournies par la page, calculées sur le flux du jour). Rafraîchie toutes les 2 minutes.
 */
export default function NotificationBell({ deadlines }: { deadlines: { id: string; title: string; detail: string; overdue: boolean }[] }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<{ items: Notif[]; unread: number } | null>(null);
  const box = useRef<HTMLDivElement>(null);

  const load = () =>
    fetch("/api/notifications", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => j && setData(j))
      .catch(() => undefined);
  useEffect(() => {
    void load();
    const t = window.setInterval(load, 120_000);
    return () => window.clearInterval(t);
  }, []);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);

  const due: Notif[] = deadlines.slice(0, 5).map((d) => ({ id: `e${d.id}`, kind: "echeance", title: d.title, detail: d.detail, href: `/cve/${d.id}`, severity: d.overdue ? "critique" : "haute", at: "", unread: false }));
  const unread = (data?.unread ?? 0) + deadlines.filter((d) => d.overdue).length;

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && data?.unread) {
      void fetch("/api/notifications", { method: "POST" });
      // Le badge disparaît ; les éléments restent mis en évidence pendant cette ouverture
      setData({ ...data, unread: 0 });
    }
  };

  return (
    <div className="bell" ref={box}>
      <button type="button" className="icon-btn bell-btn" aria-label={`Notifications${unread ? ` (${unread} nouvelle${unread > 1 ? "s" : ""})` : ""}`} aria-expanded={open} onClick={toggle}>
        <Icon name="bell" size={16} />
        {unread > 0 && <span className="bell-badge">{unread > 99 ? "99+" : unread}</span>}
      </button>
      {open && (
        <div className="bell-panel" role="dialog" aria-label="Notifications">
          <p className="bell-head">Notifications</p>
          {due.length > 0 && (
            <>
              <p className="bell-sec">Échéances proches</p>
              <ul className="bell-list">
                {due.map((n) => (
                  <Item key={n.id} n={n} />
                ))}
              </ul>
            </>
          )}
          <p className="bell-sec">Activité des 30 derniers jours</p>
          {!data ? (
            <p className="hint bell-empty">Chargement…</p>
          ) : !data.items.length ? (
            <p className="hint bell-empty">Rien de nouveau. Vous serez prévenu ici des alertes, des mentions sur le dark web et des CVE qui vous sont confiées.</p>
          ) : (
            <ul className="bell-list">
              {data.items.map((n) => (
                <Item key={n.id} n={n} />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function Item({ n }: { n: Notif }) {
  const k = KIND[n.kind];
  return (
    <li>
      <a href={n.href} className={`bell-item${n.unread ? " is-unread" : ""}`}>
        <span className={`bell-ic bell-ic-${n.kind} sev-${n.severity}`}>
          <Icon name={k.icon} size={13} />
        </span>
        <span className="bell-txt">
          <span className="bell-title">{n.title}</span>
          <span className="bell-detail">
            {k.label}
            {n.detail ? ` · ${n.detail}` : ""}
            {n.at ? ` · ${relTime(n.at)}` : ""}
          </span>
        </span>
      </a>
    </li>
  );
}
