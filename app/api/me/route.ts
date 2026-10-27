import { NextResponse } from "next/server";
import { currentSession, googleConfigured } from "@/lib/auth";
import { mailConfigured } from "@/lib/mail";
import { getProviders, getSettings, getStatuses } from "@/lib/userdata";

export const dynamic = "force-dynamic";

/** Profil, préférences et suivi des CVE de l'utilisateur connecté. */
export async function GET() {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  const [settings, statuses, providers] = await Promise.all([
    getSettings(s.user.id),
    getStatuses(s.user.id),
    getProviders(s.user.id),
  ]);
  return NextResponse.json({
    user: { id: s.user.id, name: s.user.name, email: s.user.email, image: s.user.image ?? null, emailVerified: s.user.emailVerified },
    settings,
    statuses,
    providers,
    features: { mail: mailConfigured(), google: googleConfigured() },
  });
}
