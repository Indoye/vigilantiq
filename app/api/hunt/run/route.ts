import { NextResponse } from "next/server";
import { huntUser } from "@/lib/hunt/store";
import { fail, noStore, userOr } from "../common";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** Chasse rétroactive : tous les observables des 30 derniers jours contre les IOC du moment. */
export async function POST() {
  const u = await userOr("analyst");
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json(await huntUser(u.id), noStore);
  } catch (e) {
    return fail(e);
  }
}
