import type { Metadata } from "next";
import { ResetForm } from "@/app/components/PasswordForms";

export const metadata: Metadata = { title: "Nouveau mot de passe – VigilantIQ" };
export const dynamic = "force-dynamic";

export default async function Page({ searchParams }: { searchParams: Promise<{ token?: string; error?: string }> }) {
  const sp = await searchParams;
  return (
    <main className="auth">
      <ResetForm token={sp.token ?? null} error={sp.error ?? null} />
    </main>
  );
}
