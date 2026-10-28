"use client";

import { useCallback, useEffect, useState } from "react";
import type { Priority } from "@/lib/types";

export const PRIO_CLASS: Record<Priority, string> = {
  urgente: "p-urgente",
  haute: "p-haute",
  moyenne: "p-moyenne",
  basse: "p-basse",
};

/** Anneau de score, façon anneaux d'activité. */
export function Ring({
  score,
  size = 44,
  stroke = 5,
  label,
  big = false,
  display,
}: {
  score: number;
  size?: number;
  stroke?: number;
  label?: string;
  big?: boolean;
  /** Valeur affichée au centre (par défaut, le score) */
  display?: number | string;
}) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(score));
    return () => cancelAnimationFrame(id);
  }, [score]);
  return (
    <span className={`ring${big ? " ring-big" : ""}`} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label ?? `Score ${score} sur 100`}>
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} fill="none" />
        <circle
          className="ring-value"
          cx={size / 2}
          cy={size / 2}
          r={r}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${((shown / 100) * c).toFixed(2)} ${c.toFixed(2)}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <span className="ring-num" aria-hidden="true">
        {display ?? score}
      </span>
    </span>
  );
}

type IconName =
  | "shield" | "search" | "refresh" | "calendar" | "warning" | "stack" | "radio" | "chevron" | "back"
  | "close" | "link" | "copy" | "check" | "external" | "code" | "wrench" | "send" | "star" | "file" | "share" | "mail" | "more" | "globe";

const PATHS: Record<IconName, string> = {
  shield: "M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z M12 8v5 M12 16.5v.01",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-3.5-3.5",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7 M20 4v7h-7",
  calendar: "M7 5h10a3 3 0 0 1 3 3v9a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3V8a3 3 0 0 1 3-3z M4 10h16 M9 3v4 M15 3v4",
  warning: "M12 3L2 20h20L12 3z M12 10v4 M12 17v.01",
  stack: "M12 3l9 5-9 5-9-5 9-5z M3 13l9 5 9-5",
  radio: "M5 12a7 7 0 0 1 14 0 M8.5 12a3.5 3.5 0 0 1 7 0 M12 12v.01 M2 12a10 10 0 0 1 20 0",
  chevron: "M9 6l6 6-6 6",
  back: "M15 5l-7 7 7 7",
  close: "M6 6l12 12 M18 6L6 18",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1 M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  copy: "M9 9h10v10H9z M5 15V5h10",
  check: "M5 12l5 5L20 7",
  external: "M14 4h6v6 M20 4l-9 9 M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5",
  code: "M8 8l-4 4 4 4 M16 8l4 4-4 4 M13.5 5l-3 14",
  wrench: "M14.7 6.3a4 4 0 0 0-5.4 5.2L4 16.8V20h3.2l5.3-5.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.4-.5-.5-2.4 2.5-2.7z",
  send: "M21 3L10 14 M21 3l-7 18-4-7-7-4 18-7z",
  file: "M7 3h7l5 5v13H7z M14 3v5h5 M10 13h6 M10 17h6",
  share: "M12 3v12 M8 7l4-4 4 4 M8 10H6a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1h-2",
  mail: "M4 6h16a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1z M3.5 7l8.5 6.5L20.5 7",
  more: "M6 12h.01 M12 12h.01 M18 12h.01",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9 M12 3C9.5 5.6 8.2 8.6 8.2 12s1.3 6.4 3.8 9",
  star: "M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9L12 3z",
};

export function Icon({ name, size = 16, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name].split(" M").map((d, i) => (
        <path key={i} d={i === 0 ? d : `M${d}`} />
      ))}
    </svg>
  );
}

function safeGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function safeSet(key: string, v: string) {
  try {
    localStorage.setItem(key, v);
  } catch {
    /* stockage indisponible : la valeur reste en mémoire */
  }
}

export function useStoredString(key: string, initial = ""): [string, (v: string) => void] {
  const [v, setV] = useState(initial);
  useEffect(() => {
    const s = safeGet(key);
    if (s != null) setV(s);
  }, [key]);
  const set = useCallback(
    (nv: string) => {
      setV(nv);
      safeSet(key, nv);
    },
    [key],
  );
  return [v, set];
}

export function useStoredSet(key: string): [Set<string>, (id: string) => void] {
  const [v, setV] = useState<Set<string>>(new Set());
  useEffect(() => {
    try {
      setV(new Set(JSON.parse(safeGet(key) ?? "[]")));
    } catch {
      /* valeur illisible : on repart de zéro */
    }
  }, [key]);
  const toggle = useCallback(
    (id: string) =>
      setV((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        safeSet(key, JSON.stringify([...next]));
        return next;
      }),
    [key],
  );
  return [v, toggle];
}
