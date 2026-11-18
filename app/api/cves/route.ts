import { NextResponse } from "next/server";
import { currentFeed } from "@/lib/feedstore";

export const dynamic = "force-dynamic";

/** Flux JSON du jour (dernier instantané de la collecte continue), pour brancher un SIEM, un outil de ticketing ou un script. */
export async function GET() {
  const feed = await currentFeed();
  return NextResponse.json(feed, { headers: { "Cache-Control": "public, s-maxage=60, stale-while-revalidate=60" } });
}
