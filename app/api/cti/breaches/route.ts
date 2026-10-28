import { NextResponse } from "next/server";
import { getBreaches } from "@/lib/cti/store";

export const dynamic = "force-dynamic";

/** Fuites de données récemment ajoutées au catalogue public de Have I Been Pwned. */
export async function GET(req: Request) {
  const days = Math.min(365, Math.max(7, Number(new URL(req.url).searchParams.get("jours")) || 90));
  try {
    const all = await getBreaches();
    const since = Date.now() - days * 86400_000;
    const items = all.filter((b) => b.addedDate && Date.parse(b.addedDate) >= since).slice(0, 200);
    return NextResponse.json(
      {
        generatedAt: new Date().toISOString(),
        days,
        total: all.length,
        accounts: items.reduce((s, b) => s + b.pwnCount, 0),
        items,
      },
      { headers: { "Cache-Control": "public, max-age=600" } },
    );
  } catch (e) {
    return NextResponse.json({ error: `Have I Been Pwned indisponible : ${e instanceof Error ? e.message : e}` }, { status: 502 });
  }
}
