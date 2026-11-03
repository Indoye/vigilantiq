import { NextResponse } from "next/server";
import { googleConfigured } from "@/lib/auth";
import { requireTenant } from "@/lib/tenant";
import { isAnalyst } from "@/lib/cti/leakstore";
import { mailConfigured } from "@/lib/mail";
import { getProviders, getSettings, getStatuses } from "@/lib/userdata";

export const dynamic = "force-dynamic";

/** Profil, organisation et rôle, préférences, et suivi des CVE de l'organisation. */
export async function GET() {
  const s = await requireTenant("viewer");
  if (s instanceof NextResponse) return s;
  const [settings, statuses, providers] = await Promise.all([getSettings(s.userId, s.orgId), getStatuses(s.orgId), getProviders(s.userId)]);
  return NextResponse.json({
    user: s.user,
    org: { id: s.orgId, name: s.orgName, role: s.role },
    settings,
    statuses,
    providers,
    features: { mail: mailConfigured(), google: googleConfigured(), analyst: isAnalyst(s.user.email) },
  });
}
