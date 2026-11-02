import { NextResponse } from "next/server";
import { fail, noStore, userOr } from "@/lib/patch/http";
import { software } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/** Logiciels du parc, agrégés par nom et version : ?q= pour chercher (y compris dans les paquets Linux). */
export async function GET(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json({ items: await software(u.id, new URL(req.url).searchParams.get("q") ?? "") }, noStore);
  } catch (e) {
    return fail(e);
  }
}
