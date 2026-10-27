import { getAuth } from "@/lib/auth";

export const dynamic = "force-dynamic";

// Inscription, connexion (e-mail ou Google), sessions, réinitialisation du mot de passe…
export const GET = (req: Request) => getAuth().handler(req);
export const POST = (req: Request) => getAuth().handler(req);
