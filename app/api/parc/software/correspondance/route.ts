import { NextResponse } from "next/server";
import { fail, userOr } from "@/lib/patch/http";
import { resolveSoftwareNow, setSoftwareMapping } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** Recherche immédiate du produit NVD d'un logiciel : { name, publisher }. */
export async function POST(req: Request) {
  const u = await userOr("analyst");
  if (u instanceof NextResponse) return u;
  const b = ((await req.json().catch(() => null)) ?? {}) as Record<string, unknown>;
  try {
    return NextResponse.json(await resolveSoftwareNow(u.id, String(b.name ?? ""), String(b.publisher ?? "")));
  } catch (e) {
    return fail(e);
  }
}

/** Correction : { name, vendor, product } — ou { name, ignore: true } — ou { name, reset: true }. */
export async function PUT(req: Request) {
  const u = await userOr("admin");
  if (u instanceof NextResponse) return u;
  const b = ((await req.json().catch(() => null)) ?? {}) as Record<string, unknown>;
  try {
    return NextResponse.json(await setSoftwareMapping(u.id, u.email, b));
  } catch (e) {
    return fail(e);
  }
}
