import { NextResponse } from "next/server";
import { investigate } from "@/lib/hunt/agent";
import { fail, noStore, userOr } from "../common";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/** Enquête de l'agent IA (ou rapport par règles si aucun fournisseur IA n'est configuré). */
export async function POST() {
  const u = await userOr("analyst");
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json(await investigate(u.id), noStore);
  } catch (e) {
    return fail(e);
  }
}
