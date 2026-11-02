import { getSessionCookie } from "better-auth/cookies";
import { NextResponse, type NextRequest } from "next/server";
import { getAuth } from "@/lib/auth";

/** Page d'activation obligatoire de la double authentification. */
export const MFA_SETUP = "/double-authentification";

/**
 * Pages et API ouvertes aux visiteurs sans compte : tableau de veille (Aujourd'hui, Exploitées, PoC publics,
 * En cours, Flux en direct, ThreatMap), fiches CVE publiques et leurs données. Tout le reste exige une session.
 */
const GUEST = [/^\/$/, /^\/cve\/[^/]+$/, /^\/api\/cves$/, /^\/api\/rss$/, /^\/api\/cve\/[^/]+$/, /^\/api\/threatmap$/, /^\/api\/cti\/(ransomware|breaches|iocs)$/, /^\/api\/echeances$/, /^\/api\/recherche$/];
export const guestAllowed = (pathname: string) => GUEST.some((re) => re.test(pathname));

/**
 * Contrôle rapide : sans cookie de session, on renvoie vers la connexion (pages) ou on répond 401 (API).
 * Chaque route qui lit ou écrit des données d'utilisateur vérifie en plus la session en base.
 */
export async function proxy(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  if (getSessionCookie(req)) {
    // Pages : un compte sans double authentification est envoyé vers son activation (obligatoire).
    // Les API, elles, refusent déjà ces sessions (currentSession renvoie null).
    if (pathname.startsWith("/api/") || pathname === MFA_SETUP) return NextResponse.next();
    const s = await getAuth().api.getSession({ headers: req.headers }).catch(() => null);
    if (s && !s.user.twoFactorEnabled) {
      const url = new URL(MFA_SETUP, req.url);
      if (pathname !== "/") url.searchParams.set("suite", pathname + search);
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }
  if (guestAllowed(pathname)) return NextResponse.next();
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
