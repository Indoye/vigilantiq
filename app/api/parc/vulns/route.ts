import { NextResponse } from "next/server";
import { fail, noStore, readJson, userOr } from "@/lib/patch/http";
import { fleetVulns, setVulnStatus } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/** CVE du parc, regroupées par CVE et triées par score : ?status=ouverte (défaut) | ignoree | corrigee | toutes. */
export async function GET(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const s = new URL(req.url).searchParams.get("status") ?? "ouverte";
  const status = ["ouverte", "ignoree", "corrigee", "toutes"].includes(s) ? s : "ouverte";
  try {
    return NextResponse.json({ items: await fleetVulns(u.id, status) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** { cveId, deviceId?, action: "ignore", reason } ou { cveId, deviceId?, action: "reopen" }. */
export async function PATCH(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json(await setVulnStatus(u.id, u.email, await readJson(req)));
  } catch (e) {
    return fail(e);
  }
}
