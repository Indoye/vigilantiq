import type { Metadata } from "next";
import { ForgotForm } from "@/app/components/PasswordForms";
import { mailConfigured } from "@/lib/mail";

export const metadata: Metadata = { title: "Mot de passe oublié – VigilantIQ" };
export const dynamic = "force-dynamic";

export default function Page() {
  return (
    <main className="auth">
      <ForgotForm mail={mailConfigured()} />
    </main>
  );
}
