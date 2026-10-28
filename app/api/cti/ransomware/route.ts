import { NextResponse } from "next/server";
import { getRansomVictims } from "@/lib/cti/store";
import { countBy } from "@/lib/cti/stats";

export const dynamic = "force-dynamic";

/** Victimes récemment revendiquées sur les sites de fuite des rançongiciels (ransomware.live), données publiques. */
export async function GET() {
  try {
    const items = await getRansomVictims();
    return NextResponse.json(
      {
        generatedAt: new Date().toISOString(),
        count: items.length,
        items,
        groups: countBy(items, (v) => v.group, 12),
        countries: countBy(items, (v) => v.country, 12),
        sectors: countBy(items, (v) => v.sector, 10),
      },
      { headers: { "Cache-Control": "public, max-age=300" } },
    );
  } catch (e) {
    return NextResponse.json({ error: `Source ransomware.live indisponible : ${e instanceof Error ? e.message : e}` }, { status: 502 });
  }
}
