import { APIError, betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { nextCookies } from "better-auth/next-js";
import { headers } from "next/headers";
import { createHash } from "node:crypto";
import { getDb } from "@/db";
import { account, session, user, userSettings, verification } from "@/db/schema";
import { accountEmail, mailConfigured, sendMail } from "./mail";

export function googleConfigured(): boolean {
  return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
}

/** Domaines autorisés à créer un compte (ex. « entreprise.sn, filiale.sn »). Vide = tout le monde. */
export function allowedDomains(): string[] {
  return (process.env.ALLOWED_EMAIL_DOMAINS ?? "")
    .split(",")
    .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean);
}

function baseURL(): string | undefined {
  if (process.env.BETTER_AUTH_URL) return process.env.BETTER_AUTH_URL;
  if (process.env.APP_URL) return process.env.APP_URL;
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  return undefined;
}

/** Adresses publiques du projet sur Vercel (le projet répond sous ces deux alias). */
const PROJECT_ALIASES = ["https://vigilantiq.vercel.app", "https://vigilantiq-xengin1.vercel.app"];

/** Origines autorisées à appeler l'authentification : alias du projet, déploiement courant, TRUSTED_ORIGINS. */
function trustedOrigins(): string[] {
  const host = (h?: string) => (h ? `https://${h}` : "");
  const extra = (process.env.TRUSTED_ORIGINS ?? "").split(",").map((s) => s.trim());
  return [
    ...PROJECT_ALIASES,
    host(process.env.VERCEL_PROJECT_PRODUCTION_URL),
    host(process.env.VERCEL_URL),
    host(process.env.VERCEL_BRANCH_URL),
    ...extra,
  ].filter((o, i, all) => o && all.indexOf(o) === i);
}

/**
 * Secret de signature des sessions. Recommandé : BETTER_AUTH_SECRET.
 * À défaut, un secret stable est dérivé de DATABASE_URL (elle-même secrète), pour que l'application
 * fonctionne dès que la base est branchée. Changer l'un ou l'autre déconnecte tout le monde.
 */
function authSecret(): string | undefined {
  if (process.env.BETTER_AUTH_SECRET) return process.env.BETTER_AUTH_SECRET;
  if (process.env.DATABASE_URL) {
    return createHash("sha256").update(`vigilantiq:session:${process.env.DATABASE_URL}`).digest("base64url");
  }
  return undefined;
}

function createAuth() {
  return betterAuth({
    appName: "VigilantIQ",
    baseURL: baseURL(),
    secret: authSecret(),
    trustedOrigins: trustedOrigins(),
    database: drizzleAdapter(getDb(), { provider: "pg", schema: { user, session, account, verification } }),
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 10,
      autoSignIn: true,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: async ({ user: u, url }) => {
        await sendMail({
          to: u.email,
          subject: "Réinitialiser votre mot de passe VigilantIQ",
          html: accountEmail(
            "Réinitialiser votre mot de passe",
            "Vous avez demandé un nouveau mot de passe pour VigilantIQ. Ce lien est valable une heure.",
            "Choisir un nouveau mot de passe",
            url,
          ),
        });
        if (!mailConfigured()) console.info(`Lien de réinitialisation pour ${u.email} : ${url}`);
      },
    },
    emailVerification: {
      // La vérification n'est pas exigée pour se connecter, mais elle l'est pour recevoir le digest.
      sendOnSignUp: mailConfigured(),
      autoSignInAfterVerification: true,
      sendVerificationEmail: async ({ user: u, url }) => {
        await sendMail({
          to: u.email,
          subject: "Confirmez votre adresse e-mail",
          html: accountEmail(
            "Confirmez votre adresse",
            "Confirmez votre adresse pour recevoir le digest quotidien des vulnérabilités.",
            "Confirmer mon adresse",
            url,
          ),
        });
      },
    },
    socialProviders: googleConfigured()
      ? {
          google: {
            clientId: process.env.GOOGLE_CLIENT_ID!,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
            prompt: "select_account",
          },
        }
      : {},
    account: { accountLinking: { enabled: true, trustedProviders: ["google"] } },
    user: { deleteUser: { enabled: true } },
    session: {
      expiresIn: 60 * 60 * 24 * 30,
      updateAge: 60 * 60 * 24,
      // Pas de cache de session dans le cookie : une session révoquée (déconnexion, nouveau mot de passe,
      // suppression du compte) cesse de fonctionner immédiatement, au prix d'une lecture en base par requête.
      cookieCache: { enabled: false },
    },
    rateLimit: { enabled: true, window: 60, max: 30 },
    databaseHooks: {
      user: {
        create: {
          before: async (u) => {
            const domains = allowedDomains();
            const domain = u.email.split("@")[1]?.toLowerCase() ?? "";
            if (domains.length && !domains.includes(domain)) {
              throw new APIError("FORBIDDEN", {
                message: `Les inscriptions sont réservées aux adresses ${domains.map((d) => "@" + d).join(", ")}.`,
              });
            }
            return { data: u };
          },
          after: async (u) => {
            // Chaque nouveau compte démarre avec la stack de l'équipe, s'il y en a une.
            await getDb()
              .insert(userSettings)
              .values({ userId: u.id, stack: process.env.STACK_KEYWORDS ?? "" })
              .onConflictDoNothing();
          },
        },
      },
    },
    plugins: [nextCookies()],
  });
}

type Auth = ReturnType<typeof createAuth>;
const g = globalThis as unknown as { __vigilantiqAuth?: Auth };

/** Instance créée à la première utilisation (la compilation n'a pas besoin de la base). */
export function getAuth(): Auth {
  if (!g.__vigilantiqAuth) g.__vigilantiqAuth = createAuth();
  return g.__vigilantiqAuth;
}

/** Session de la requête en cours, ou null. */
export async function currentSession() {
  return getAuth().api.getSession({ headers: await headers() });
}
