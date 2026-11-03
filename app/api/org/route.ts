import { NextResponse } from "next/server";
import { listApiKeys } from "@/lib/apiauth";
import { mailConfigured } from "@/lib/mail";
import { can, listInvites, listMembers, renameOrg, removeMember, requireTenant } from "@/lib/tenant";
import { body, fail, str } from "./common";

export const dynamic = "force-dynamic";

/** Organisation de l'utilisateur : membres, invitations en cours et clés d'API (administrateurs). */
export async function GET() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  const admin = can(t.role, "admin");
  const [members, invites, apiKeys] = await Promise.all([listMembers(t.orgId), admin ? listInvites(t.orgId) : [], admin ? listApiKeys(t.orgId) : []]);
  return NextResponse.json(
    { id: t.orgId, name: t.orgName, role: t.role, me: t.userId, members, invites, apiKeys, mail: mailConfigured() },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}

/** { name } — renomme l'organisation (administrateurs). */
export async function PATCH(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    await renameOrg(t, str((await body(req)).name));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

/** Quitter l'organisation : le compte repart dans une organisation personnelle vide. */
export async function DELETE() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  try {
    await removeMember(t, t.userId);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}
