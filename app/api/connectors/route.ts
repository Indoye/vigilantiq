import { NextResponse } from "next/server";
import { apiTokensConfigured, isAdmin } from "@/lib/apiauth";
import { currentSession } from "@/lib/auth";
import { autoMinPriority, listConnectors } from "@/lib/connectors";

export const dynamic = "force-dynamic";

/** État des connecteurs (jamais les valeurs des secrets) pour l'interface. */
export async function GET() {
  const s = await currentSession();
  if (!s) return NextResponse.json({ error: "Session expirée. Reconnectez-vous." }, { status: 401 });
  return NextResponse.json({
    connectors: listConnectors(),
    autoMinPriority: autoMinPriority(),
    apiTokens: apiTokensConfigured(),
    canTest: isAdmin(s.user.email),
    pocMonitor: { githubToken: Boolean(process.env.GITHUB_TOKEN) },
  });
}
