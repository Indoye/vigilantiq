import { NextResponse } from "next/server";
import { markNotificationsSeen, notificationsFor } from "@/lib/notifications";
import { requireTenant } from "@/lib/tenant";

export const dynamic = "force-dynamic";

export async function GET() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  return NextResponse.json(await notificationsFor(t), { headers: { "Cache-Control": "private, no-store" } });
}

/** Marque tout comme lu (ouverture du centre). */
export async function POST() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  await markNotificationsSeen(t.userId);
  return NextResponse.json({ ok: true });
}
