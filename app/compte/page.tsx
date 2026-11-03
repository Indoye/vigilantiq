import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import AccountView from "@/app/components/AccountView";
import { googleConfigured } from "@/lib/auth";
import { currentTenant } from "@/lib/tenant";
import { mailConfigured } from "@/lib/mail";
import { getProviders, getSettings } from "@/lib/userdata";

export const metadata: Metadata = { title: "Mon compte – VigilantIQ" };
export const dynamic = "force-dynamic";

export default async function Compte({ searchParams }: { searchParams: Promise<{ erreur?: string }> }) {
  const s = await currentTenant();
  if (!s) redirect("/connexion?suite=/compte");
  const sp = await searchParams;
  const [settings, providers] = await Promise.all([getSettings(s.userId, s.orgId), getProviders(s.userId)]);

  return (
    <div className="app">
      <header className="toolbar page-cve-bar">
        <Link href="/" className="back">
          <svg width="12" height="20" viewBox="0 0 12 20" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M10 2L2 10l8 8" />
          </svg>
          Tableau de veille
        </Link>
        <span className="toolbar-title">Mon compte</span>
        <span />
      </header>
      <AccountView
        initial={{
          user: { id: s.user.id, name: s.user.name, email: s.user.email, image: s.user.image ?? null, emailVerified: s.user.emailVerified, twoFactorEnabled: Boolean(s.user.twoFactorEnabled) },
          settings,
          statuses: {},
          org: { id: s.orgId, name: s.orgName, role: s.role },
          providers,
          features: { mail: mailConfigured(), google: googleConfigured() },
        }}
        linkError={sp.erreur === "liaison"}
      />
    </div>
  );
}
