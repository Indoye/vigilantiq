/** Petits agrégats pour les tableaux de bord de renseignement. */
export function countBy<T>(items: T[], key: (t: T) => string, top = 10): { key: string; count: number }[] {
  const m = new Map<string, number>();
  for (const it of items) {
    const k = key(it);
    if (k) m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].map(([k, count]) => ({ key: k, count })).sort((a, b) => b.count - a.count || a.key.localeCompare(b.key)).slice(0, top);
}
