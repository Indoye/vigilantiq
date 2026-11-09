import { NextResponse } from "next/server";
import { fail, noStore, userOr } from "@/lib/patch/http";
import { softwareCves } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/** CVE d'un logiciel du parc : ?nom=…&version=… (version facultative). */
export async function GET(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const sp = new URL(req.url).searchParams;
  const name = sp.get("nom") ?? "";
  if (!name) return NextResponse.json({ error: "Logiciel manquant." }, { status: 400 });
  try {
    return NextResponse.json({ items: await softwareCves(u.id, name, sp.get("version") ?? "") }, noStore);
  } catch (e) {
    return fail(e);
  }
}
