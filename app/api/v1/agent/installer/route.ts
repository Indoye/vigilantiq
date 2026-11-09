import { NextResponse } from "next/server";
import { agentServer } from "@/lib/patch/http";
import { agentScript, AGENT_FILE, AGENT_OSES, type AgentOs } from "@/lib/patch/scripts";
import { enrollmentOwner } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/**
 * Installeur de l'agent avec le jeton d'enrôlement intégré : GET ?os=windows|linux|macos&token=vqe_…
 * Sert aux commandes d'installation en une ligne et au déploiement en masse (GPO, Intune, Ansible).
 */
export async function GET(req: Request) {
  const u = new URL(req.url);
  const os = AGENT_OSES.find((o) => o === u.searchParams.get("os")) ?? null;
  const token = u.searchParams.get("token") ?? "";
  if (!os) return NextResponse.json({ error: "Paramètre os : windows, linux ou macos." }, { status: 400 });
  if (!(await enrollmentOwner(token))) return NextResponse.json({ error: "Jeton d’enrôlement invalide ou renouvelé." }, { status: 401 });
  const script = agentScript(os as AgentOs, agentServer(req), token);
  return new NextResponse(os === "windows" ? "﻿" + script : script, {
    headers: {
      "Content-Type": os === "windows" ? "text/plain; charset=utf-8" : os === "macos" ? "text/javascript; charset=utf-8" : "text/x-python; charset=utf-8",
      "Content-Disposition": `attachment; filename="${AGENT_FILE[os as AgentOs]}"`,
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
