import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db";
import { scRepo } from "@/db/schema";
import { parseRepo } from "@/lib/sc-core";
import { scanStatus, startScan } from "@/lib/securitycontext";
import { noStore, scFail, scTenant } from "../../common";

export const dynamic = "force-dynamic";

/** Lance l'analyse d'un dépôt suivi absent de l'index SecurityContext : { repo }. */
export async function POST(req: Request) {
  const t = await scTenant("analyst");
  if (t instanceof NextResponse) return t;
  const repo = parseRepo(String(((await req.json().catch(() => ({}))) as { repo?: string }).repo ?? ""));
  if (!repo) return NextResponse.json({ error: "Dépôt invalide." }, { status: 400 });
  try {
    const db = getDb();
    const [row] = await db.select().from(scRepo).where(and(eq(scRepo.orgId, t.orgId), eq(scRepo.repo, repo)));
    if (!row) return NextResponse.json({ error: "Ajoutez d’abord ce dépôt à la liste suivie." }, { status: 404 });
    const job = await startScan(repo);
    await db.update(scRepo).set({ scanId: job.id }).where(eq(scRepo.id, row.id));
    return NextResponse.json(job, noStore);
  } catch (e) {
    return scFail(e);
  }
}

/** Avancement de l'analyse : ?repo=owner/name */
export async function GET(req: Request) {
  const t = await scTenant();
  if (t instanceof NextResponse) return t;
  const repo = parseRepo(new URL(req.url).searchParams.get("repo") ?? "");
  if (!repo) return NextResponse.json({ error: "Dépôt invalide." }, { status: 400 });
  try {
    const [row] = await getDb().select().from(scRepo).where(and(eq(scRepo.orgId, t.orgId), eq(scRepo.repo, repo)));
    if (!row?.scanId) return NextResponse.json({ status: "none" }, noStore);
    const s = await scanStatus(row.scanId, repo);
    if (s.status === "done" || s.status === "failed") await getDb().update(scRepo).set({ scanId: null }).where(eq(scRepo.id, row.id));
    return NextResponse.json(s, noStore);
  } catch (e) {
    return scFail(e);
  }
}
