import { NextResponse } from "next/server";
import { getDb } from "@/db";
import { feedback } from "@/db/schema";
import { currentTenant } from "@/lib/tenant";

export const dynamic = "force-dynamic";

/** { mood: content | neutre | mecontent, message, page } — visible des opérateurs dans « État de la plateforme ». */
export async function POST(req: Request) {
  const t = await currentTenant();
  if (!t) return NextResponse.json({ error: "Connectez-vous pour donner votre avis." }, { status: 401 });
  const b = (await req.json().catch(() => ({}))) as { mood?: unknown; message?: unknown; page?: unknown };
  const mood = ["content", "neutre", "mecontent"].includes(String(b.mood)) ? String(b.mood) : null;
  if (!mood) return NextResponse.json({ error: "Choisissez une humeur." }, { status: 400 });
  const message = typeof b.message === "string" ? b.message.trim().slice(0, 2000) : "";
  const page = typeof b.page === "string" ? b.page.slice(0, 200) : "";
  await getDb()
    .insert(feedback)
    .values({ userId: t.userId, orgId: t.orgId, mood, message, page });
  return NextResponse.json({ ok: true }, { status: 201 });
}
