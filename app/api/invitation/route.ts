import { NextResponse } from "next/server";
import { acceptInvite, requireTenant } from "@/lib/tenant";
import { body, fail, str } from "../org/common";

export const dynamic = "force-dynamic";

/** { token } — l'utilisateur connecté rejoint l'organisation qui l'a invité. */
export async function POST(req: Request) {
  const t = await requireTenant("viewer");
  if (t instanceof NextResponse) return t;
  try {
    return NextResponse.json(await acceptInvite(str((await body(req)).token), t.userId, t.email));
  } catch (e) {
    return fail(e);
  }
}
