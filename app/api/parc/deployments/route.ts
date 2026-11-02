import { NextResponse } from "next/server";
import { fail, noStore, readJson, userOr } from "@/lib/patch/http";
import { createDeployment, deploymentAction, deploymentFromRequest, listDeployments } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json({ items: await listDeployments(u.id) }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** Corriger maintenant : { deviceIds, cves?, content, minPriority, kevOnly, reboot, window?, pilot? }. */
export async function POST(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    return NextResponse.json(await createDeployment(u.id, u.email, deploymentFromRequest(await readJson(req))));
  } catch (e) {
    return fail(e);
  }
}

/** { id, action: "approve" | "cancel" | "rollback" }. */
export async function PATCH(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const b = await readJson(req);
  const id = Number(b.id);
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    return NextResponse.json(await deploymentAction(u.id, u.email, id, String(b.action ?? "")));
  } catch (e) {
    return fail(e);
  }
}
