import { and, eq } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/db";
import { scRepo } from "@/db/schema";
import { parseRepo } from "@/lib/sc-core";
import { ATTRIBUTION, repoContext, repoEscalations } from "@/lib/securitycontext";
import { noStore, scFail, scTenant } from "../common";

export const dynamic = "force-dynamic";
export const maxDuration = 60;
const MAX_REPOS = 25;

/** Dépôts suivis par l'organisation, avec leur contexte (score de risque, mises à jour à faire, escalades). */
export async function GET() {
  const t = await scTenant();
  if (t instanceof NextResponse) return t;
  try {
    const rows = await getDb().select().from(scRepo).where(eq(scRepo.orgId, t.orgId)).orderBy(scRepo.createdAt);
    const repos = [];
    for (const r of rows) {
      try {
        const ctx = await repoContext(r.repo);
        const esc = ctx.found ? await repoEscalations(r.repo).catch(() => []) : [];
        repos.push({ ...ctx, scanId: r.scanId, escalations: esc.slice(0, 20) });
      } catch (e) {
        repos.push({ repo: r.repo, found: false, error: e instanceof Error ? e.message : String(e), scanId: r.scanId, escalations: [] });
      }
    }
    return NextResponse.json({ repos, max: MAX_REPOS, source: ATTRIBUTION }, noStore);
  } catch (e) {
    return scFail(e);
  }
}

/** Suivre un dépôt public : { repo: "owner/name" ou URL GitHub }. */
export async function POST(req: Request) {
  const t = await scTenant("analyst");
  if (t instanceof NextResponse) return t;
  const body = (await req.json().catch(() => ({}))) as { repo?: string };
  const repo = parseRepo(String(body.repo ?? ""));
  if (!repo) return NextResponse.json({ error: "Indiquez un dépôt GitHub public : propriétaire/nom ou son adresse github.com." }, { status: 400 });
  try {
    const db = getDb();
    const n = await db.$count(scRepo, eq(scRepo.orgId, t.orgId));
    if (n >= MAX_REPOS) return NextResponse.json({ error: `${MAX_REPOS} dépôts suivis au plus.` }, { status: 400 });
    await db.insert(scRepo).values({ orgId: t.orgId, repo, addedBy: t.email }).onConflictDoNothing();
    return NextResponse.json({ ok: true, repo, context: await repoContext(repo) }, noStore);
  } catch (e) {
    return scFail(e);
  }
}

/** Ne plus suivre un dépôt : ?repo=owner/name */
export async function DELETE(req: Request) {
  const t = await scTenant("analyst");
  if (t instanceof NextResponse) return t;
  const repo = parseRepo(new URL(req.url).searchParams.get("repo") ?? "");
  if (!repo) return NextResponse.json({ error: "Dépôt invalide." }, { status: 400 });
  await getDb().delete(scRepo).where(and(eq(scRepo.orgId, t.orgId), eq(scRepo.repo, repo)));
  return NextResponse.json({ ok: true }, noStore);
}
