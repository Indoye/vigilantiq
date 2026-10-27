import { NextResponse } from "next/server";
import { getRssSnapshot } from "@/lib/rss";

// Rafraîchi au plus toutes les 2 minutes ; chaque flux est mis en cache 3 minutes.
export const revalidate = 120;

/** Alertes des CERT, agences, éditeurs et bases d'exploits, avec les CVE citées. */
export async function GET() {
  return NextResponse.json(await getRssSnapshot());
}
