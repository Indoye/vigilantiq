import { NextResponse } from "next/server";
import { fail, noStore, userOr } from "@/lib/patch/http";
import { software } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/** Logiciels du parc par nom et version, avec leurs CVE ouvertes : ?q= pour chercher, ?vulnerables=1 pour filtrer. */
export async function GET(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const sp = new URL(req.url).searchParams;
  try {
    return NextResponse.json({ items: await software(u.id, sp.get("q") ?? "", sp.get("vulnerables") === "1") }, noStore);
  } catch (e) {
    return fail(e);
  }
}
