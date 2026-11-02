import { NextResponse } from "next/server";
import { fetchKev } from "@/lib/sources";

export const dynamic = "force-dynamic";

const CVE_RE = /^cve-\d{4}-\d{4,7}$/i;
const norm = (s: string) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");

/**
 * Recherche hors du tableau du jour : tout le catalogue CISA KEV (dont les failles à l'échéance dépassée
 * depuis plus d'un mois, masquées des listes) ; un identifiant CVE exact ouvre toujours sa fiche. Données publiques.
 */
export async function GET(req: Request) {
  const q = norm((new URL(req.url).searchParams.get("q") ?? "").trim()).slice(0, 80);
  if (q.length < 3) return NextResponse.json({ items: [], total: 0, cve: null });
  const cve = CVE_RE.test(q) ? q.toUpperCase() : null;
  try {
    const kev = await fetchKev();
    const terms = q.split(/\s+/).filter(Boolean);
    const all = [...kev.values()].filter((k) => {
      const hay = norm(`${k.id} ${k.vendor} ${k.product} ${k.name ?? ""} ${k.description}`);
      return terms.every((t) => hay.includes(t));
    });
    all.sort((a, b) => (b.dateAdded ?? "").localeCompare(a.dateAdded ?? ""));
    const items = all.slice(0, 60).map((k) => ({ id: k.id, vendor: k.vendor, product: k.product, name: k.name ?? "", dateAdded: k.dateAdded ?? "", dueDate: k.dueDate ?? "", ransomware: Boolean(k.ransomware) }));
    return NextResponse.json({ items, total: all.length, cve }, { headers: { "Cache-Control": "public, max-age=900" } });
  } catch (e) {
    return NextResponse.json({ items: [], total: 0, cve, error: `Catalogue CISA indisponible : ${e instanceof Error ? e.message : e}` }, { status: 200 });
  }
}
