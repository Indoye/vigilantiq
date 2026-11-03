import { NextResponse } from "next/server";
import { accountEmail, mailConfigured, sendMail } from "@/lib/mail";
import { appUrl } from "@/lib/ticketstore";
import { createInvite, requireTenant, revokeInvite, ROLE_FR, type Role } from "@/lib/tenant";
import { body, fail, str } from "../common";

export const dynamic = "force-dynamic";

/** { email, role } — crée une invitation valable 7 jours ; le lien n'est montré qu'une fois. */
export async function POST(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    const b = await body(req);
    const email = str(b.email).trim().toLowerCase();
    const role = str(b.role) || "analyst";
    const { token, expiresAt } = await createInvite(t, email, role);
    const link = `${appUrl()}/invitation/${token}`;
    let mailed = false;
    if (mailConfigured()) {
      mailed = await sendMail({
        to: email,
        subject: `Invitation à rejoindre ${t.orgName} sur VigilantIQ`,
        html: accountEmail(
          `Rejoindre ${t.orgName}`,
          `${t.user.name || t.email} vous invite à rejoindre l’organisation ${t.orgName} sur VigilantIQ, avec le rôle ${ROLE_FR[role as Role] ?? role}. L’invitation est valable 7 jours.`,
          "Accepter l’invitation",
          link,
        ),
      }).catch(() => false);
    }
    return NextResponse.json({ link, mailed, expiresAt: expiresAt.toISOString() }, { status: 201 });
  } catch (e) {
    return fail(e);
  }
}

/** ?id=… */
export async function DELETE(req: Request) {
  const t = await requireTenant("admin");
  if (t instanceof NextResponse) return t;
  try {
    await revokeInvite(t, new URL(req.url).searchParams.get("id") ?? "");
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}
