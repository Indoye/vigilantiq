import { getSessionCookie } from "better-auth/cookies";
import { NextResponse, type NextRequest } from "next/server";

/**
 * Contrôle rapide : sans cookie de session, on renvoie vers la connexion (pages) ou on répond 401 (API).
 * Chaque route qui lit ou écrit des données d'utilisateur vérifie en plus la session en base.
 */
export function proxy(req: NextRequest) {
  if (getSessionCookie(req)) return NextResponse.next();
  const { pathname, search } = req.nextUrl;
  if (pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "Connectez-vous pour accéder à cette ressource." }, { status: 401 });
  }
  const url = new URL("/connexion", req.url);
  if (pathname !== "/") url.searchParams.set("suite", pathname + search);
  return NextResponse.redirect(url);
}

export const config = {
  // Tout est protégé, sauf les écrans de compte, les fiches partagées (jeton signé vérifié par la page), l'API d'authentification, les tâches planifiées (protégées par
  // CRON_SECRET), l'API v1 (jeton ou session, vérifiés par chaque route) et les fichiers statiques.
  matcher: ["/((?!connexion|partage|mot-de-passe-oublie|reinitialiser|api/auth|api/digest|api/cron|api/v1|_next/static|_next/image|favicon.ico|icon|apple-icon).*)"],
};
