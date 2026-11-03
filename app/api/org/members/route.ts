import { NextResponse } from "next/server";
import { removeMember, requireTenant, setMemberRole } from "@/lib/tenant";
import { body, fail, str } from "../common";

export const dynamic = "force-dynamic";

/** { userId, role } */
export async function PATCH(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    await setMemberRole(t, str(b.userId), str(b.role));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}

/** ?userId=… */
export async function DELETE(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    await removeMember(t, new URL(req.url).searchParams.get("userId") ?? "");
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}
