import { NextResponse } from "next/server";
import { adhocSearch } from "@/lib/darkweb/store";
import { body, fail, tenant } from "../common";

export const dynamic = "force-dynamic";

/** { kind, value } — recherche dans le corpus masqué (analystes). */
export async function POST(req: Request) {
  const t = await tenant("analyst");
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    return NextResponse.json(await adhocSearch(String(b.kind ?? "keyword"), String(b.value ?? "")));
  } catch (e) {
    return fail(e);
  }
}
