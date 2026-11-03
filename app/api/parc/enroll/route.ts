import { NextResponse } from "next/server";
import { agentServer, fail, noStore, userOr } from "@/lib/patch/http";
import { installCommands } from "@/lib/patch/scripts";
import { getEnrollment, revokeEnrollment, rotateEnrollment } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

const kit = (req: Request, token: string, createdAt: string) => {
  const base = agentServer(req);
  const url = (os: string) => `${base}/api/v1/agent/installer?os=${os}&token=${encodeURIComponent(token)}`;
  return {
    token,
    createdAt,
    installers: { windows: url("windows"), linux: url("linux") },
    commands: { windows: installCommands("windows", url("windows")), linux: installCommands("linux", url("linux")) },
  };
};

/** Jeton d'enrôlement de l'utilisateur et commandes d'installation de l'agent. */
export async function GET(req: Request) {
  const u = await userOr("admin");
  if (u instanceof NextResponse) return u;
  try {
    const e = await getEnrollment(u.id);
    return NextResponse.json(e ? kit(req, e.token, e.createdAt) : { token: null }, noStore);
  } catch (e) {
    return fail(e);
  }
}

/** Crée ou renouvelle le jeton (l'ancien installeur cesse de fonctionner ; les équipements enrôlés ne sont pas touchés). */
export async function POST(req: Request) {
  const u = await userOr("admin");
  if (u instanceof NextResponse) return u;
  try {
    const token = await rotateEnrollment(u.id, u.email);
    return NextResponse.json(kit(req, token, new Date().toISOString()), noStore);
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE() {
  const u = await userOr("admin");
  if (u instanceof NextResponse) return u;
  try {
    await revokeEnrollment(u.id, u.email);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}
