import { NextResponse } from "next/server";
import { fetchKev } from "@/lib/sources";

export const dynamic = "force-dynamic";

/**
 * Failles du catalogue CISA KEV dont l'échéance de correction tombe entre il y a 30 jours et dans 45 jours,
 * y compris celles ajoutées avant la fenêtre du flux du jour. Données publiques.
 */
export async function GET() {
  try {
    const kev = await fetchKev();
    const now = Date.now();
    const from = now - 30 * 86400_000;
    const to = now + 45 * 86400_000;
    const items = [...kev.entries()]
      .map(([id, k]) => ({ id, vendor: k.vendor ?? "", product: k.product ?? "", name: k.name, dateAdded: k.dateAdded, dueDate: k.dueDate, ransomware: k.ransomware }))
      .filter((k) => {
        const t = Date.parse(k.dueDate);
        return Number.isFinite(t) && t >= from && t <= to;
      })
      .sort((a, b) => a.dueDate.localeCompare(b.dueDate));
    return NextResponse.json({ generatedAt: new Date().toISOString(), items }, { headers: { "Cache-Control": "public, max-age=900" } });
  } catch (e) {
    return NextResponse.json({ error: `Catalogue CISA indisponible : ${e instanceof Error ? e.message : e}` }, { status: 502 });
  }
}
