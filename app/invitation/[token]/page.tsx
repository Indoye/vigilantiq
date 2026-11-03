import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { LogoMark } from "@/app/components/Logo";
import AcceptInvite from "@/app/components/AcceptInvite";
import { currentTenant, inviteInfo, listMembers, ROLE_FR, type Role } from "@/lib/tenant";

export const metadata: Metadata = { title: "Invitation – VigilantIQ", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function Invitation({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const t = await currentTenant();
  if (!t) redirect(`/connexion?suite=${encodeURIComponent(`/invitation/${token}`)}`);
  const inv = await inviteInfo(token);
  const alone = (await listMembers(t.orgId)).length <= 1;

  let body: React.ReactNode;
  if (!inv) {
    body = t.orgName ? (
      <p className="hint">Cette invitation n’est plus valable (expirée, révoquée ou déjà utilisée). Vous faites partie de l’organisation « {t.orgName} ».</p>
    ) : null;
  } else if (inv.orgId === t.orgId) {
    body = <p className="hint">Vous faites déjà partie de l’organisation « {inv.orgName} ».</p>;
  } else if (inv.email !== t.email.toLowerCase()) {
    body = <p className="form-msg form-err">Cette invitation est destinée à {inv.email}. Connectez-vous avec cette adresse pour l’accepter.</p>;
  } else {
    body = (
      <>
        <p>
          Vous êtes invité à rejoindre <strong>{inv.orgName}</strong> avec le rôle <strong>{ROLE_FR[inv.role as Role] ?? inv.role}</strong>.
        </p>
        <p className="hint">
          {alone
            ? `Votre organisation actuelle « ${t.orgName} », dont vous êtes le seul membre, sera supprimée avec ses données (stack, surveillance, parc, connecteurs).`
            : `Vous quitterez l’organisation « ${t.orgName} » et n’aurez plus accès à ses données.`}
        </p>
        <AcceptInvite token={token} />
      </>
    );
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-brand">
          <span className="brand-mark">
            <LogoMark size={44} />
          </span>
          <h1>Invitation</h1>
        </div>
        <div className="auth-panel">
          {body}
          <p className="hint" style={{ marginTop: 16 }}>
            <Link href="/">Retour au tableau de veille</Link>
          </p>
        </div>
      </div>
    </main>
  );
}
