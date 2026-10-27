import type { Metadata } from "next";
import { redirect } from "next/navigation";
import AuthForm from "@/app/components/AuthForm";
import { dbConfigured } from "@/db";
import { allowedDomains, currentSession, googleConfigured } from "@/lib/auth";
import { mailConfigured } from "@/lib/mail";

export const metadata: Metadata = { title: "Connexion – VigilantIQ" };
export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ suite?: string; mode?: string; erreur?: string }> };

export default async function Connexion({ searchParams }: Props) {
  const sp = await searchParams;
  if (!dbConfigured()) {
    return (
      <main className="auth">
        <div className="auth-card auth-panel">
          <h1 style={{ margin: 0, fontSize: 22 }}>Base de données non configurée</h1>
          <p style={{ margin: 0 }}>
            Ajoutez la variable DATABASE_URL (par exemple une base Neon depuis Vercel) puis redéployez pour activer les comptes.
          </p>
        </div>
      </main>
    );
  }
  if (await currentSession()) redirect(sp.suite?.startsWith("/") ? sp.suite : "/");
  return (
    <main className="auth">
      {sp.erreur === "google" && (
        <p className="toast" role="alert">
          La connexion avec Google n’a pas abouti. Réessayez ou utilisez votre e-mail.
        </p>
      )}
      <AuthForm
        google={googleConfigured()}
        mail={mailConfigured()}
        next={sp.suite ?? null}
        initialMode={sp.mode === "inscription" ? "inscription" : "connexion"}
        restrictedTo={allowedDomains()}
      />
    </main>
  );
}
