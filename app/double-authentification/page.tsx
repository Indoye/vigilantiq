import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { LogoMark } from "@/app/components/Logo";
import MfaPanel from "@/app/components/MfaPanel";
import { rawSession } from "@/lib/auth";
import { getProviders } from "@/lib/userdata";

export const metadata: Metadata = { title: "Double authentification – VigilantIQ" };
export const dynamic = "force-dynamic";

/** Activation obligatoire de la double authentification (TOTP) avant tout accès à l'application. */
export default async function DoubleAuthentification({ searchParams }: { searchParams: Promise<{ suite?: string }> }) {
  const sp = await searchParams;
  const suite = sp.suite?.startsWith("/") && !sp.suite.startsWith("//") ? sp.suite : "/";
  const s = await rawSession();
  if (!s) redirect(`/connexion?suite=${encodeURIComponent(suite)}`);
  if (s.user.twoFactorEnabled) redirect(suite);
  const hasPassword = (await getProviders(s.user.id)).includes("credential");
  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-brand">
          <span className="brand-mark">
            <LogoMark size={44} />
          </span>
          <h1>Sécurisez votre compte</h1>
          <p>
            La double authentification est obligatoire sur VigilantIQ. Elle protège votre compte même si votre mot de passe est dérobé.
          </p>
        </div>
        <div className="auth-panel">
          <MfaPanel enabled={false} hasPassword={hasPassword} required next={suite} />
        </div>
      </div>
    </main>
  );
}
