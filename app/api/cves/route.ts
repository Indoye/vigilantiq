import { NextResponse } from "next/server";
import { getDailyFeed } from "@/lib/feed";

export const revalidate = 21600;

/** Flux JSON du jour, pour brancher un SIEM, un outil de ticketing ou un script. */
export async function GET() {
  const feed = await getDailyFeed();
  return NextResponse.json(feed);
}
