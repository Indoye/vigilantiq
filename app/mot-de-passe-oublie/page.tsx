import type { Metadata } from "next";
import { ForgotForm } from "@/app/components/PasswordForms";

export const metadata: Metadata = { title: "Mot de passe oublié – VigilantIQ" };

export default function Page() {
  return (
    <main className="auth">
      <ForgotForm />
    </main>
  );
}
