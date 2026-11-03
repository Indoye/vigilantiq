import { NextResponse } from "next/server";
import { deleteOrgConnector, listOrgConnectors, saveOrgConnector } from "@/lib/orgconnectors";
import { can, requireTenant, TenantError } from "@/lib/tenant";

export const dynamic = "force-dynamic";

const fail = (e: unknown) =>
  e instanceof TenantError ? NextResponse.json({ error: e.message }, { status: e.status }) : (console.error(`[connecteurs] ${e}`), NextResponse.json({ error: "Erreur interne." }, { status: 500 }));

/** Connecteurs de l'organisation (jamais les valeurs des secrets). */
export async function GET() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  return NextResponse.json(
    { connectors: await listOrgConnectors(t.orgId), canManage: can(t.role, "admin"), pocMonitor: { githubToken: Boolean(process.env.GITHUB_TOKEN) } },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}

/** { type, values: { CLE: valeur }, enabled, autoSend } — un secret laissé vide est conservé. */
export async function PUT(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  const b = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  try {
    await saveOrgConnector(t, String(b?.type ?? ""), b ?? {});
    return NextResponse.json({ connectors: await listOrgConnectors(t.orgId) });
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    await deleteOrgConnector(t, new URL(req.url).searchParams.get("type") ?? "");
    return NextResponse.json({ connectors: await listOrgConnectors(t.orgId) });
  } catch (e) {
    return fail(e);
  }
}
