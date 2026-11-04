import { NextResponse } from "next/server";
import { isAnalyst } from "@/lib/cti/leakstore";
import { corpusStats, searchConfigured } from "@/lib/darkweb/search";
import { apifyConfigured } from "@/lib/darkweb/store";
import { can } from "@/lib/tenant";
import { tenant } from "./common";

export const dynamic = "force-dynamic";

/** État du module : configuration, taille du corpus, droits de l'utilisateur. */
export async function GET() {
  const t = await tenant("viewer");
  if (t instanceof NextResponse) return t;
  const stats = searchConfigured() ? await corpusStats().catch((e) => ({ error: e instanceof Error ? e.message : String(e) })) : null;
  return NextResponse.json(
    { apify: apifyConfigured(), search: searchConfigured(), stats, canEdit: can(t.role, "analyst"), platformAnalyst: isAnalyst(t.email) },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}
