import { NextResponse } from "next/server";
import { onboarding, setOnboardingHidden } from "@/lib/onboarding";
import { requireTenant } from "@/lib/tenant";

export const dynamic = "force-dynamic";

export async function GET() {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  return NextResponse.json({ ...(await onboarding(t.orgId, t.userId)), role: t.role }, { headers: { "Cache-Control": "private, no-store" } });
}

/** { hidden: boolean } */
export async function PATCH(req: Request) {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  const b = (await req.json().catch(() => ({}))) as { hidden?: unknown };
  await setOnboardingHidden(t.userId, b.hidden === true);
  return NextResponse.json({ ok: true });
}
