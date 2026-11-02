/**
 * Échéances de correction : date limite CISA (catalogue KEV, obligatoire pour les agences fédérales américaines)
 * ou, à défaut, délai recommandé selon la priorité, compté depuis la publication de la CVE.
 */
import type { Priority } from "./types.ts";

export const DELAY_DAYS: Record<Priority, number> = { urgente: 2, haute: 7, moyenne: 30, basse: 90 };

export type DeadlineLevel = "retard" | "urgent" | "proche" | "bientot" | "plus-tard";

export interface Deadline {
  /** Jour limite (AAAA-MM-JJ) */
  date: string;
  source: "cisa" | "priorite";
  /** Jours restants (négatif si dépassée), comptés en jours calendaires UTC */
  daysLeft: number;
  level: DeadlineLevel;
}

const DAY = 86400_000;
const dayStart = (t: number) => Math.floor(t / DAY) * DAY;

export function levelOf(daysLeft: number): DeadlineLevel {
  if (daysLeft < 0) return "retard";
  if (daysLeft <= 2) return "urgent";
  if (daysLeft <= 7) return "proche";
  if (daysLeft <= 14) return "bientot";
  return "plus-tard";
}

export function makeDeadline(date: string, source: Deadline["source"], now = Date.now()): Deadline | null {
  const t = Date.parse(date.slice(0, 10));
  if (!Number.isFinite(t)) return null;
  const daysLeft = Math.round((dayStart(t) - dayStart(now)) / DAY);
  return { date: date.slice(0, 10), source, daysLeft, level: levelOf(daysLeft) };
}

export function deadlineOf(v: { priority: Priority; published: string; kev?: { dueDate?: string } | null }, now = Date.now()): Deadline | null {
  if (v.kev?.dueDate) return makeDeadline(v.kev.dueDate, "cisa", now);
  const pub = Date.parse(v.published);
  if (!Number.isFinite(pub)) return null;
  return makeDeadline(new Date(pub + DELAY_DAYS[v.priority] * DAY).toISOString(), "priorite", now);
}

/** « En retard de 3 j », « Aujourd’hui », « Demain », « Dans 5 j » */
export function countdown(d: Deadline): string {
  if (d.daysLeft < -1) return `En retard de ${-d.daysLeft} j`;
  if (d.daysLeft === -1) return "En retard d’1 j";
  if (d.daysLeft === 0) return "Aujourd’hui";
  if (d.daysLeft === 1) return "Demain";
  return `Dans ${d.daysLeft} j`;
}

/** Tri : les plus urgentes d'abord (retards compris), puis CISA avant priorité à date égale. */
export function byDeadline(a: Deadline | null, b: Deadline | null): number {
  if (!a) return b ? 1 : 0;
  if (!b) return -1;
  return a.daysLeft - b.daysLeft || (a.source === b.source ? 0 : a.source === "cisa" ? -1 : 1);
}
